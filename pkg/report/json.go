package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
)

// MachineReport encapsulates the entire audit state for machine consumption, web dashboards, and database ingestion.
type MachineReport struct {
	Version             string                 `json:"version"`
	Target              string                 `json:"target"`
	Timestamp           string                 `json:"timestamp"`
	DurationMs          int64                  `json:"duration_ms,omitempty"`
	AuditReport         *analyzer.AuditReport  `json:"audit_report"`
	SynthesizedPolicies map[string]string      `json:"synthesized_policies,omitempty"`
	SynthesizedHCL      map[string]string      `json:"synthesized_hcl,omitempty"`
}

// ExportJSON serializes the AuditReport into a formatted JSON string.
func ExportJSON(report *analyzer.AuditReport) (string, error) {
	bytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to export JSON report: %w", err)
	}
	return string(bytes), nil
}

// ExportFullJSON serializes an enriched MachineReport containing findings, metrics, cloud policies, and Terraform modules.
func ExportFullJSON(report *analyzer.AuditReport, policies map[string]string, hcl map[string]string, target string, durationMs int64) (string, error) {
	if report == nil {
		report = analyzer.NewAuditReport(target)
	}

	doc := MachineReport{
		Version:             "0.2.0",
		Target:              target,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		DurationMs:          durationMs,
		AuditReport:         report,
		SynthesizedPolicies: policies,
		SynthesizedHCL:      hcl,
	}

	bytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to export full machine JSON report: %w", err)
	}
	return string(bytes), nil
}
