package analyzer

import (
	"fmt"

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
		severity := SeverityMedium
		contextNote := "Workflow triggers on trusted/internal events."
		if wf.HasUntrustedEventTrigger() {
			severity = SeverityHigh
			contextNote = "Workflow triggers on untrusted or external events, significantly increasing exposure."
		}

		jobCount := len(wf.Jobs)
		desc := "The workflow grants 'id-token: write' (or 'write-all') at the root level, exposing cloud OIDC minting capabilities to all jobs without least-privilege segmentation."
		if jobCount > 1 {
			desc += fmt.Sprintf(" %s All %d jobs in this workflow inherit OIDC token minting privileges.", contextNote, jobCount)
		} else {
			desc += fmt.Sprintf(" %s", contextNote)
		}

		findings = append(findings, Finding{
			RuleID:       r.ID(),
			Title:        "Global id-token: write Permission Detected",
			Severity:     severity,
			WorkflowPath: wf.Path,
			JobName:      "*",
			Description:  desc,
			Remediation:  "Remove root-level 'id-token: write' and declare permissions explicitly within the specific deployment job.",
		})
	}

	return findings
}
