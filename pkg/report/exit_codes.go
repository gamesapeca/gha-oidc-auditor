package report

import (
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
)

const (
	ExitOK            = 0 // No findings or findings below configured threshold
	ExitFindingsFound = 1 // Findings matching failure threshold detected (HIGH / MEDIUM / LOW)
	ExitCriticalFound = 2 // One or more CRITICAL findings detected
	ExitParseError    = 3 // Workflow parsing or syntax failure
	ExitAPIError      = 4 // GitHub API communication or authentication error
	ExitInvalidArgs   = 5 // Invalid command-line arguments provided
)

// DetermineExitCode evaluates report findings against the configured --fail-on threshold.
func DetermineExitCode(report *analyzer.AuditReport, failOn string) int {
	if report == nil || len(report.Findings) == 0 {
		return ExitOK
	}

	normalized := strings.ToLower(failOn)

	switch normalized {
	case "none":
		return ExitOK

	case "critical":
		if report.Summary[analyzer.SeverityCritical] > 0 {
			return ExitCriticalFound
		}
		return ExitOK

	case "high":
		if report.Summary[analyzer.SeverityCritical] > 0 {
			return ExitCriticalFound
		}
		if report.Summary[analyzer.SeverityHigh] > 0 {
			return ExitFindingsFound
		}
		return ExitOK

	case "medium":
		if report.Summary[analyzer.SeverityCritical] > 0 {
			return ExitCriticalFound
		}
		if report.Summary[analyzer.SeverityHigh] > 0 || report.Summary[analyzer.SeverityMedium] > 0 {
			return ExitFindingsFound
		}
		return ExitOK

	case "all":
		if report.Summary[analyzer.SeverityCritical] > 0 {
			return ExitCriticalFound
		}
		return ExitFindingsFound

	default:
		if report.Summary[analyzer.SeverityCritical] > 0 {
			return ExitCriticalFound
		}
		return ExitOK
	}
}
