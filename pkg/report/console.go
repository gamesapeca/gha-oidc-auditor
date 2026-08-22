package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
)

// RenderConsole renders a stylized, colored terminal report summarizing audit findings.
func RenderConsole(w io.Writer, report *analyzer.AuditReport) {
	if w == nil {
		w = os.Stdout
	}

	cyan := color.New(color.FgCyan, color.Bold).FprintfFunc()
	green := color.New(color.FgGreen, color.Bold).SprintfFunc()
	red := color.New(color.FgRed, color.Bold).SprintfFunc()
	yellow := color.New(color.FgYellow, color.Bold).SprintfFunc()

	fmt.Fprintln(w)
	cyan(w, "----------------------------------------------------------------------------------\n")
	cyan(w, "  GHA-OIDC-AUDITOR: Security Static Analyzer & Least-Privilege Trust Policy Engine\n")
	cyan(w, "----------------------------------------------------------------------------------\n\n")

	fmt.Fprintf(w, "  Target:            %s\n", report.TargetRepo)
	fmt.Fprintf(w, "  Workflows Scanned: %d\n", report.WorkflowsNum)
	fmt.Fprintf(w, "  Total Findings:    %d\n", len(report.Findings))
	fmt.Fprintf(w, "  Scan Timestamp:    %s\n\n", report.ScanTime.Format("2006-01-02 15:04:05 UTC"))

	// Summary Table
	fmt.Fprintln(w, "--- Summary of Findings ---")
	twSum := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(twSum, "Severity\tCount")
	fmt.Fprintln(twSum, "--------\t-----")
	fmt.Fprintf(twSum, "%s\t%d\n", red("CRITICAL"), report.Summary[analyzer.SeverityCritical])
	fmt.Fprintf(twSum, "%s\t%d\n", yellow("HIGH"), report.Summary[analyzer.SeverityHigh])
	fmt.Fprintf(twSum, "%s\t%d\n", color.YellowString("MEDIUM"), report.Summary[analyzer.SeverityMedium])
	fmt.Fprintf(twSum, "%s\t%d\n", "LOW", report.Summary[analyzer.SeverityLow])
	fmt.Fprintf(twSum, "%s\t%d\n", "INFO", report.Summary[analyzer.SeverityInfo])
	twSum.Flush()
	fmt.Fprintln(w)

	if len(report.Findings) == 0 && len(report.ExploitChains) == 0 {
		fmt.Fprintf(w, "  %s No OIDC or Supply Chain risks identified in scanned workflows.\n\n", green("[OK]"))
		return
	}

	// Detailed Security Findings
	if len(report.Findings) > 0 {
		fmt.Fprintln(w, "--- Detailed Security Findings ---")
		for i, f := range report.Findings {
			var sevBadge string
			switch f.Severity {
			case analyzer.SeverityCritical:
				sevBadge = red("[CRITICAL]")
			case analyzer.SeverityHigh:
				sevBadge = yellow("[HIGH]")
			case analyzer.SeverityMedium:
				sevBadge = color.YellowString("[MEDIUM]")
			default:
				sevBadge = fmt.Sprintf("[%s]", f.Severity)
			}

			location := fmt.Sprintf("%s (Job: %s)", f.WorkflowPath, f.JobName)
			if f.StepIndex > 0 {
				location = fmt.Sprintf("%s - Step #%d", location, f.StepIndex)
			}

			fmt.Fprintf(w, "%d. %s %s - %s\n", i+1, sevBadge, color.CyanString(f.RuleID), f.Title)
			fmt.Fprintf(w, "   Location:    %s\n", location)
			fmt.Fprintf(w, "   Description: %s\n", f.Description)
			fmt.Fprintf(w, "   Remediation: %s\n", green(f.Remediation))
			fmt.Fprintln(w, strings.Repeat("-", 80))
		}
		fmt.Fprintln(w)
	}


	// Zero-Prerequisite Bug Bounty Exploit Chains
	if len(report.ExploitChains) > 0 {
		fmt.Fprintln(w, red(strings.Repeat("-", 80)))
		fmt.Fprintln(w, red("  [!] EXPLOITABLE BUG BOUNTY ATTACK CHAINS IDENTIFIED "))
		fmt.Fprintln(w, red(strings.Repeat("-", 80)))
		for i, ec := range report.ExploitChains {
			fmt.Fprintf(w, "\n%d. %s %s [%s / %s] - %s\n", i+1, red("[EXPLOITABLE]"), color.CyanString(ec.ID), color.YellowString(ec.Category), ec.CWE, ec.Title)
			fmt.Fprintf(w, "   Target Workflow: %s (Job: %s)\n", ec.WorkflowPath, ec.JobName)
			fmt.Fprintf(w, "   Ingress Trigger: %s (Vector: %s)\n", color.YellowString(ec.TriggerEvent), ec.IngressVector)
			if ec.TargetCloud != "" && ec.TargetCloud != analyzer.ProviderNone {
				fmt.Fprintf(w, "   Cloud Target:    %s (%s)\n", ec.TargetCloud, ec.TargetRoleARN)
			}
			fmt.Fprintf(w, "   PoC Payload:     %s\n", color.GreenString(ec.PoCPayload))
			fmt.Fprintln(w, strings.Repeat("-", 80))
		}
		fmt.Fprintln(w)
	}

}

