package analyzer

import (
	"fmt"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC008SecretsInherit detects third-party reusable workflows invoked with 'secrets: inherit' in OIDC contexts.
type RuleOIDC008SecretsInherit struct{}

func (r *RuleOIDC008SecretsInherit) ID() string {
	return "OIDC-008"
}

func (r *RuleOIDC008SecretsInherit) Name() string {
	return "Unsafe 'secrets: inherit' in Third-Party Reusable Workflow"
}

func (r *RuleOIDC008SecretsInherit) DefaultSeverity() Severity {
	return SeverityHigh
}

func (r *RuleOIDC008SecretsInherit) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	for jobName, job := range wf.Jobs {
		if !IsJobOIDCPrivileged(wf, jobName) {
			continue
		}

		// Check if job calls an external/third-party reusable workflow with secrets: inherit
		if job.Uses != "" && job.InheritsSecretsAll() {
			trimmed := strings.TrimSpace(job.Uses)
			// Ignore local reusable workflows (./.github/workflows/...)
			if !strings.HasPrefix(trimmed, "./") && !strings.HasPrefix(trimmed, ".\\") {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("External Reusable Workflow with 'secrets: inherit' in Job '%s'", jobName),
					Severity:     r.DefaultSeverity(),
					WorkflowPath: wf.Path,
					JobName:      jobName,
					Description:  fmt.Sprintf("Job '%s' holds 'id-token: write' permissions and calls external reusable workflow '%s' with 'secrets: inherit'. This exposes all repository secrets to an external caller context.", jobName, job.Uses),
					Remediation:  "Avoid 'secrets: inherit' with third-party reusable workflows. Pass only the specific required secrets explicitly.",
				})
			}
		}
	}

	return findings
}
