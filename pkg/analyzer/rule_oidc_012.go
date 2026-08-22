package analyzer

import (
	"fmt"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC012WildcardTrustPolicy detects cloud authentication steps where the role ARN or
// audience hint suggests a wildcard trust policy — allowing any repository in an organization
// to assume the cloud role. This is the "overprivileged trust policy" category that allows
// any compromised repository to escalate to production roles.
type RuleOIDC012WildcardTrustPolicy struct{}

func (r *RuleOIDC012WildcardTrustPolicy) ID() string {
	return "OIDC-012"
}

func (r *RuleOIDC012WildcardTrustPolicy) Name() string {
	return "Potential Wildcard OIDC Trust Policy (Organization-Wide Cloud Access)"
}

func (r *RuleOIDC012WildcardTrustPolicy) DefaultSeverity() Severity {
	return SeverityHigh
}

// wildcardTrustSignals are patterns in 'with:' fields indicating a wildcard or overly broad trust scope.
var wildcardTrustSignals = []string{
	"/*",
	":*",
	"*:",
	"repo:*/",
	"repo:*:",
}

func hasWildcardTrustSignal(step parser.Step) (bool, string) {
	for k, v := range step.With {
		val := strings.ToLower(fmt.Sprintf("%v", v))
		for _, sig := range wildcardTrustSignals {
			if strings.Contains(val, sig) {
				return true, fmt.Sprintf("with.%s = %v", k, v)
			}
		}
	}
	for k, v := range step.Env {
		val := strings.ToLower(fmt.Sprintf("%v", v))
		for _, sig := range wildcardTrustSignals {
			if strings.Contains(val, sig) {
				return true, fmt.Sprintf("env.%s = %v", k, v)
			}
		}
	}
	return false, ""
}

func (r *RuleOIDC012WildcardTrustPolicy) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	for jobName, job := range wf.Jobs {
		if !IsJobOIDCPrivileged(wf, jobName) {
			continue
		}

		for idx, step := range job.Steps {
			_, ok := MatchCloudAction(step)
			if !ok {
				continue
			}

			if hasWild, signal := hasWildcardTrustSignal(step); hasWild {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("Possible Wildcard Trust Policy in Cloud Auth Step (Job '%s')", jobName),
					Category:     "Privilege Management",
					CWE:          "CWE-732",
					Severity:     r.DefaultSeverity(),
					WorkflowPath: wf.Path,
					JobName:      jobName,
					StepIndex:    idx + 1,
					Description:  fmt.Sprintf("Job '%s' step #%d uses a cloud authentication action with a value that suggests a wildcard trust scope (%s). Wildcard sub-claim patterns (e.g., repo:org/* or repo:org/repo:*) in cloud IAM trust policies allow any branch, tag, or workflow in the matched scope to assume the role, violating least-privilege. A compromised branch or tag can exploit this to assume production deployment roles.", jobName, idx+1, signal),
					Remediation:  "Replace wildcard trust policy conditions with exact, least-privilege sub claims scoped to specific branches and environments. Use repo:org/repo:ref:refs/heads/main:environment:production instead of repo:org/*.",
				})
			}
		}
	}
	return findings
}
