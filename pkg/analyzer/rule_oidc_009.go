package analyzer

import (
	"fmt"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// knownHighValueActions maps GitHub Actions marketplace identifiers that are high-value supply chain
// targets — actions that have been historically compromised or are widely trusted in OIDC pipelines.
// Unpinned references to these actions in any workflow (not just OIDC-privileged) are flagged as HIGH
// severity because a tag-takeover attack (like CVE-2025-30066) grants code execution in all consumer
// pipelines regardless of OIDC privilege.
var knownHighValueActions = []string{
	"tj-actions/changed-files",
	"tj-actions/",
	"reviewdog/action-",
	"actions/cache",
	"actions/checkout",
	"actions/upload-artifact",
	"actions/download-artifact",
	"actions/setup-node",
	"actions/setup-python",
	"actions/setup-go",
	"actions/setup-java",
	"docker/build-push-action",
	"docker/login-action",
	"docker/metadata-action",
	"docker/setup-buildx-action",
	"github/codeql-action",
	"aws-actions/configure-aws-credentials",
	"google-github-actions/auth",
	"azure/login",
	"hashicorp/vault-action",
}

func isHighValueAction(uses string) bool {
	lower := strings.ToLower(uses)
	for _, prefix := range knownHighValueActions {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

// RuleOIDC009TagHijackRisk detects high-value GitHub Actions referenced by mutable tags anywhere in the
// workflow — not limited to OIDC-privileged contexts. A compromised mutable tag (CVE-2025-30066 pattern)
// allows attackers to dump runner memory, secrets, and OIDC tokens across all consumer pipelines.
type RuleOIDC009TagHijackRisk struct{}

func (r *RuleOIDC009TagHijackRisk) ID() string {
	return "OIDC-009"
}

func (r *RuleOIDC009TagHijackRisk) Name() string {
	return "High-Value Action Mutable Tag Hijack Risk (CVE-2025-30066 Class)"
}

func (r *RuleOIDC009TagHijackRisk) DefaultSeverity() Severity {
	return SeverityHigh
}

func (r *RuleOIDC009TagHijackRisk) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	seen := make(map[string]bool)

	for jobName, job := range wf.Jobs {
		for idx, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			if isSafeActionRef(step.Uses) {
				continue
			}
			if !isHighValueAction(step.Uses) {
				continue
			}
			key := step.Uses
			if seen[key] {
				continue
			}
			seen[key] = true

			oidcNote := ""
			if IsJobOIDCPrivileged(wf, jobName) {
				oidcNote = " This job holds OIDC token minting rights, making the impact escalate to full cloud credential exfiltration."
			}

			findings = append(findings, Finding{
				RuleID:       r.ID(),
				Title:        fmt.Sprintf("High-Value Action '%s' Pinned by Mutable Tag", step.Uses),
				Category:     "Supply Chain Integrity",
				CWE:          "CWE-494",
				Severity:     r.DefaultSeverity(),
				WorkflowPath: wf.Path,
				JobName:      jobName,
				StepIndex:    idx + 1,
				Description:  fmt.Sprintf("Action '%s' (job '%s', step #%d) is a high-value supply chain target referenced by a mutable version tag. Attackers who compromise the upstream repository (e.g., via a stolen PAT) can retroactively point the tag to malicious code that dumps all runner environment variables and secrets into workflow logs — the exact attack vector of CVE-2025-30066 (tj-actions/changed-files, March 2025).%s", step.Uses, jobName, idx+1, oidcNote),
				Remediation:  "Pin the action to its full 40-character immutable commit SHA (e.g., uses: tj-actions/changed-files@abc1234...def). Review the GitHub Advisory Database for known compromises of this action.",
			})
		}
	}

	return findings
}
