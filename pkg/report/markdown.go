package report

import (
	"fmt"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
)

// ExportMarkdown renders the audit report and synthesized trust policies into a structured Markdown document.
func ExportMarkdown(report *analyzer.AuditReport, generatedPolicies map[string]string) string {
	var sb strings.Builder

	sb.WriteString("# Security Audit Report: GitHub Actions OIDC\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** `%s`  \n", report.TargetRepo))
	sb.WriteString(fmt.Sprintf("**Audit Timestamp:** %s  \n", report.ScanTime.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("**Workflows Scanned:** %d  \n", report.WorkflowsNum))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d  \n\n", len(report.Findings)))

	sb.WriteString("## 1. Executive Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("| :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| **CRITICAL** | %d |\n", report.Summary[analyzer.SeverityCritical]))
	sb.WriteString(fmt.Sprintf("| **HIGH** | %d |\n", report.Summary[analyzer.SeverityHigh]))
	sb.WriteString(fmt.Sprintf("| **MEDIUM** | %d |\n", report.Summary[analyzer.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("| **LOW** | %d |\n", report.Summary[analyzer.SeverityLow]))
	sb.WriteString(fmt.Sprintf("| **INFO** | %d |\n\n", report.Summary[analyzer.SeverityInfo]))

	sb.WriteString("## 2. Detailed Findings\n\n")
	if len(report.Findings) == 0 {
		sb.WriteString("> No OIDC supply chain risks or permission misconfigurations identified.\n\n")
	} else {
		for i, f := range report.Findings {
			sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, f.RuleID, f.Title))
			sb.WriteString(fmt.Sprintf("- **Severity:** `%s`\n", f.Severity))
			sb.WriteString(fmt.Sprintf("- **Workflow:** `%s`\n", f.WorkflowPath))
			sb.WriteString(fmt.Sprintf("- **Job:** `%s`\n", f.JobName))
			if f.StepIndex > 0 {
				sb.WriteString(fmt.Sprintf("- **Step Index:** `%d`\n", f.StepIndex))
			}
			sb.WriteString(fmt.Sprintf("- **Technical Description:** %s\n\n", f.Description))
			sb.WriteString(fmt.Sprintf("- **Remediation:** %s\n\n", f.Remediation))
			sb.WriteString("---\n\n")
		}
	}

	if len(generatedPolicies) > 0 {
		sb.WriteString("## 3. Synthesized Least-Privilege Cloud Trust Policies\n\n")
		for name, policy := range generatedPolicies {
			sb.WriteString(fmt.Sprintf("### %s\n\n", name))
			sb.WriteString("```json\n")
			sb.WriteString(policy)
			sb.WriteString("\n```\n\n")
		}
	}

	return sb.String()
}
