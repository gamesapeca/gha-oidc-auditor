package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// secretPrintPatterns matches shell constructs that print secrets or tokens to stdout/logs.
// This includes echo, printf, cat, and common exfiltration patterns seen in compromised supply chain actions.
var secretPrintPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\becho\s+["\$']?\$?(?:ACTIONS_ID_TOKEN_REQUEST_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b`),
	regexp.MustCompile(`(?i)\becho\s+["']?\$\{\{\s*secrets\.\w+\s*\}\}`),
	regexp.MustCompile(`(?i)\bprintf\s+["%]s["\s]*\$\{\{\s*secrets\.\w+\s*\}\}`),
	regexp.MustCompile(`(?i)::(?:set-output|add-mask)::`),
	// Patterns matching env-dump exfiltration techniques used by tj-actions CVE-2025-30066
	regexp.MustCompile(`(?i)\benv\b.*\|\s*(?:base64|xxd|hexdump|od)`),
	regexp.MustCompile(`(?i)printenv\b`),
	regexp.MustCompile(`(?i)env\s+-0\b`),
}

// isDeprecatedSetOutputSyntax detects the old ::set-output:: syntax that was deprecated in 2022
// but is still dangerous when combined with untrusted inputs — used in supply chain attacks to
// pipe secrets into subsequent steps.
func isDeprecatedSetOutputSyntax(run string) bool {
	return strings.Contains(run, "::set-output name=") || strings.Contains(run, "::save-state name=")
}

// RuleOIDC011SecretLogExfiltration detects patterns that could exfiltrate secrets or OIDC tokens
// into workflow logs. This includes:
// 1. Direct `echo $SECRET` or `echo ${{ secrets.X }}` in run steps
// 2. Deprecated ::set-output:: syntax that can leak values to subsequent steps
// 3. Environment variable dump commands (printenv, env -0) — hallmark of supply chain attacks like CVE-2025-30066
type RuleOIDC011SecretLogExfiltration struct{}

func (r *RuleOIDC011SecretLogExfiltration) ID() string {
	return "OIDC-011"
}

func (r *RuleOIDC011SecretLogExfiltration) Name() string {
	return "Potential Secret or Token Exfiltration to Workflow Logs"
}

func (r *RuleOIDC011SecretLogExfiltration) DefaultSeverity() Severity {
	return SeverityCritical
}

func (r *RuleOIDC011SecretLogExfiltration) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	for jobName, job := range wf.Jobs {
		for idx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, pattern := range secretPrintPatterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, Finding{
						RuleID:       r.ID(),
						Title:        fmt.Sprintf("Possible Secret/Token Log Exfiltration in Job '%s' Step #%d", jobName, idx+1),
						Category:     "Credential Management",
						CWE:          "CWE-532",
						Severity:     r.DefaultSeverity(),
						WorkflowPath: wf.Path,
						JobName:      jobName,
						StepIndex:    idx + 1,
						Description:  fmt.Sprintf("Step #%d in job '%s' contains a shell construct that may print secrets, OIDC tokens, or all environment variables to workflow logs. This pattern is a hallmark of supply chain attacks (e.g., CVE-2025-30066 / tj-actions/changed-files). If injected by a compromised third-party action, it allows attackers to read sensitive credentials from public or accessible workflow logs.", idx+1, jobName),
						Remediation:  "Remove echo/printf/printenv calls that reference secrets or token variables. Use ::add-mask:: if values must appear in logs. Audit all third-party actions in the workflow for supply chain compromise. Pin actions to immutable commit SHAs.",
					})
					break
				}
			}

			// Separately flag deprecated ::set-output:: syntax
			if isDeprecatedSetOutputSyntax(step.Run) {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("Deprecated '::set-output::' Syntax in Job '%s' Step #%d", jobName, idx+1),
					Category:     "Credential Management",
					CWE:          "CWE-532",
					Severity:     SeverityMedium,
					WorkflowPath: wf.Path,
					JobName:      jobName,
					StepIndex:    idx + 1,
					Description:  fmt.Sprintf("Step #%d in job '%s' uses the deprecated ::set-output name=... workflow command, which was deprecated by GitHub in 2022. This syntax can inadvertently expose secret values in step outputs accessible to downstream jobs, and is a vector used in supply chain attacks to exfiltrate credentials.", idx+1, jobName),
					Remediation:  "Replace ::set-output name=VALUE:: with the GITHUB_OUTPUT environment file syntax: echo \"VALUE=result\" >> $GITHUB_OUTPUT",
				})
			}
		}
	}

	return findings
}
