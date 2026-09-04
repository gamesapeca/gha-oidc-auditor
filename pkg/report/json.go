package report

import (
	"encoding/json"
	"fmt"
	"strings"
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
		Version:             "1.1.0",
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

// JSONLineRecord represents an event record emitted in JSON Lines (NDJSON) format.
type JSONLineRecord struct {
	Target     string      `json:"target"`
	Timestamp  string      `json:"timestamp"`
	RecordType string      `json:"record_type"` // "finding", "exploit_chain", or "summary"
	Data       interface{} `json:"data"`
}

// ExportJSONLines serializes audit findings, exploit chains, and summary into newline-delimited JSON (NDJSON/JSONL).
func ExportJSONLines(report *analyzer.AuditReport, target string) (string, error) {
	if report == nil {
		report = analyzer.NewAuditReport(target)
	}

	report.RLock()
	defer report.RUnlock()

	ts := time.Now().UTC().Format(time.RFC3339)
	var lines []string

	// 1. Emit summary record
	summaryRec := JSONLineRecord{
		Target:     target,
		Timestamp:  ts,
		RecordType: "summary",
		Data:       report.Summary,
	}
	sBytes, err := json.Marshal(summaryRec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal summary line: %w", err)
	}
	lines = append(lines, string(sBytes))

	// 2. Emit findings records
	for _, f := range report.Findings {
		rec := JSONLineRecord{
			Target:     target,
			Timestamp:  ts,
			RecordType: "finding",
			Data:       f,
		}
		bytes, err := json.Marshal(rec)
		if err != nil {
			return "", fmt.Errorf("failed to marshal finding line: %w", err)
		}
		lines = append(lines, string(bytes))
	}

	// 3. Emit exploit chain records
	for _, chain := range report.ExploitChains {
		rec := JSONLineRecord{
			Target:     target,
			Timestamp:  ts,
			RecordType: "exploit_chain",
			Data:       chain,
		}
		bytes, err := json.Marshal(rec)
		if err != nil {
			return "", fmt.Errorf("failed to marshal exploit chain line: %w", err)
		}
		lines = append(lines, string(bytes))
	}

	return strings.Join(lines, "\n") + "\n", nil
}
