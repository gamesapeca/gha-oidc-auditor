package analyzer

import (
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC001Global flags global id-token: write permissions declared at the workflow root.
type RuleOIDC001Global struct{}

func (r *RuleOIDC001Global) ID() string {
	return "OIDC-001"
}

func (r *RuleOIDC001Global) Name() string {
	return "Global id-token: write Exposure"
}

func (r *RuleOIDC001Global) DefaultSeverity() Severity {
	return SeverityHigh
}

func (r *RuleOIDC001Global) Check(wf *parser.Workflow) []Finding {
	var findings []Finding

	if wf == nil {
		return findings
	}

	if wf.Permissions["id-token"] == "write" || wf.PermissionsAll == "write-all" {
		findings = append(findings, Finding{
			RuleID:       r.ID(),
			Title:        "Global id-token: write Permission Detected",
			Severity:     r.DefaultSeverity(),
			WorkflowPath: wf.Path,
			JobName:      "*",
			Description:  "The workflow grants 'id-token: write' (or 'write-all') at the root level, exposing cloud OIDC minting capabilities to all jobs without least-privilege segmentation.",
			Remediation:  "Remove root-level 'id-token: write' and declare permissions explicitly within the specific deployment job.",
		})
	}

	return findings
}
