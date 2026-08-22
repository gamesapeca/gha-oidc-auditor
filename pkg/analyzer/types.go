package analyzer

import (
	"time"
)

// Severity represents the criticality level of an audit finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// CloudProvider represents supported target cloud providers for OIDC federation.
type CloudProvider string

const (
	ProviderAWS   CloudProvider = "AWS"
	ProviderGCP   CloudProvider = "GCP"
	ProviderAzure CloudProvider = "Azure"
	ProviderVault CloudProvider = "Vault"
	ProviderNone  CloudProvider = "Unknown"
)

// Finding describes a specific detected security issue or misconfiguration.
type Finding struct {
	RuleID       string        `json:"rule_id"`
	Title        string        `json:"title"`
	Severity     Severity      `json:"severity"`
	WorkflowPath string        `json:"workflow_path"`
	JobName      string        `json:"job_name"`
	StepIndex    int           `json:"step_index,omitempty"`
	Provider     CloudProvider `json:"cloud_provider,omitempty"`
	Description  string        `json:"description"`
	Remediation  string        `json:"remediation"`
	LineNumber   int           `json:"line_number,omitempty"`
}

// AuditReport aggregates scan results, findings, and summary statistics.
type AuditReport struct {
	TargetRepo   string           `json:"target_repo"`
	ScanTime     time.Time        `json:"scan_time"`
	WorkflowsNum int              `json:"workflows_scanned"`
	Findings     []Finding        `json:"findings"`
	Summary      map[Severity]int `json:"summary"`
}

// NewAuditReport initializes an empty audit report for a given target.
func NewAuditReport(target string) *AuditReport {
	return &AuditReport{
		TargetRepo: target,
		ScanTime:   time.Now().UTC(),
		Findings:   make([]Finding, 0),
		Summary: map[Severity]int{
			SeverityCritical: 0,
			SeverityHigh:     0,
			SeverityMedium:   0,
			SeverityLow:      0,
			SeverityInfo:     0,
		},
	}
}

// AddFinding appends a finding to the report and updates summary metrics.
func (r *AuditReport) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
	r.Summary[f.Severity]++
}
