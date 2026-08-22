package analyzer

import (
	"fmt"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC010ImmutableSubClaim detects OIDC workflows that rely on name-based sub claims in
// cloud trust policies without the numeric repository/org IDs introduced by GitHub in July 2026.
//
// Attack: If a GitHub organization or repository is deleted, its name can be reregistered by a
// different entity. That new entity can then mint OIDC tokens that match the original name-based
// 'sub' claim (e.g., repo:old-org/old-repo:ref:refs/heads/main), gaining unauthorized access to
// cloud resources. The immutable ID format prevents this by embedding permanent numeric IDs.
type RuleOIDC010ImmutableSubClaim struct{}

func (r *RuleOIDC010ImmutableSubClaim) ID() string {
	return "OIDC-010"
}

func (r *RuleOIDC010ImmutableSubClaim) Name() string {
	return "OIDC Sub Claim Name-Squatting Vulnerability (Missing Immutable IDs)"
}

func (r *RuleOIDC010ImmutableSubClaim) DefaultSeverity() Severity {
	return SeverityInfo
}

// hasImmutableSubClaimFormat checks whether a role ARN or audience string contains references to
// the numeric-ID format (e.g., sub conditions using repo:org@12345/repo@6789 format). In practice,
// the auditor cannot read the cloud IAM trust policy directly, so it looks for signals in the
// workflow step configuration that indicate the consumer has opted into the secure format.
func hasImmutableSubClaimFormat(step parser.Step) bool {
	for k, v := range step.With {
		combined := strings.ToLower(k) + strings.ToLower(fmt.Sprintf("%v", v))
		if strings.Contains(combined, "immutable") || strings.Contains(combined, "repo-id") || strings.Contains(combined, "org-id") {
			return true
		}
	}
	return false
}

func (r *RuleOIDC010ImmutableSubClaim) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	// Only surface this advisory finding when the workflow is on a public/external trigger,
	// since internal-only workflows are less likely to be renamed/transferred/deleted in a way
	// that matters for the name-squatting attack.
	if !wf.HasUntrustedEventTrigger() {
		return findings
	}

	for jobName, job := range wf.Jobs {
		if !IsJobOIDCPrivileged(wf, jobName) {
			continue
		}

		for idx, step := range job.Steps {
			match, ok := MatchCloudAction(step)
			if !ok {
				continue
			}

			if match.Provider != ProviderAWS {
				continue
			}

			if !hasImmutableSubClaimFormat(step) {
				roleARN := match.TargetInfo
				targetDesc := roleARN
				if targetDesc == "" {
					targetDesc = "(role ARN not statically determinable — uses variable reference)"
				}

				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("AWS OIDC Trust Policy May Lack Immutable ID Protection for Job '%s'", jobName),
					Category:     "Identity and Authentication",
					CWE:          "CWE-345",
					Severity:     r.DefaultSeverity(),
					WorkflowPath: wf.Path,
					JobName:      jobName,
					StepIndex:    idx + 1,
					Description:  fmt.Sprintf("Job '%s' (step #%d) uses AWS OIDC federation via '%s' targeting role '%s'. As of July 15, 2026, GitHub introduced immutable numeric IDs in OIDC 'sub' claims for new repositories. If your IAM trust policy relies solely on name-based sub claim matching (e.g., StringEquals repo:org/repo:ref:...) without including the numeric-ID format, a repository or organization name reuse after deletion could allow a new owner to assume this cloud role.", jobName, idx+1, step.Uses, targetDesc),
					Remediation:  "Update your AWS IAM trust policy to accept both the legacy name-based sub claim AND the new immutable ID format: repo:your-org@ORGID/your-repo@REPOID:*. You can retrieve the numeric IDs from the GitHub API at /orgs/{org} and /repos/{owner}/{repo}. Verify the current sub claim format by decoding the OIDC JWT in a debug workflow step.",
				})
			}
		}
	}

	return findings
}

