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
	ProviderAWS        CloudProvider = "AWS"
	ProviderGCP        CloudProvider = "GCP"
	ProviderAzure      CloudProvider = "Azure"
	ProviderVault      CloudProvider = "Vault"
	ProviderSigstore   CloudProvider = "Sigstore/Attestations"
	ProviderTailscale  CloudProvider = "Tailscale"
	ProviderKubernetes CloudProvider = "Kubernetes"
	ProviderNone       CloudProvider = "Unknown"
)


// ExploitChain describes an end-to-end zero-prerequisite attack path suitable for Bug Bounty reporting.
type ExploitChain struct {
	ID             string        `json:"id"`
	Title          string        `json:"title"`
	Category       string        `json:"category"` // e.g. "Remote Code Execution", "Privilege Escalation", "Information Disclosure"
	CWE            string        `json:"cwe"`      // e.g. "CWE-269", "CWE-522", "CWE-78", "CWE-284"
	Severity       Severity      `json:"severity"` // Always CRITICAL
	WorkflowPath   string        `json:"workflow_path"`
	JobName        string        `json:"job_name"`
	TriggerEvent   string        `json:"trigger_event"`
	IngressVector  string        `json:"ingress_vector"`
	ExecutionStep  int           `json:"execution_step"`
	TargetCloud    CloudProvider `json:"target_cloud"`
	TargetRoleARN  string        `json:"target_role_arn,omitempty"`
	AudienceClaim  string        `json:"audience_claim"`
	PoCPayload     string        `json:"poc_payload"`
	ReportTemplate string        `json:"report_template"`
}


// Finding describes a specific detected security issue or misconfiguration.
type Finding struct {
	RuleID       string        `json:"rule_id"`
	Title        string        `json:"title"`
	Category     string        `json:"category"`
	CWE          string        `json:"cwe"`
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
	TargetRepo    string           `json:"target_repo"`
	ScanTime      time.Time        `json:"scan_time"`
	WorkflowsNum  int              `json:"workflows_scanned"`
	Findings      []Finding        `json:"findings"`
	ExploitChains []ExploitChain   `json:"exploit_chains,omitempty"`
	Summary       map[Severity]int `json:"summary"`
}

// NewAuditReport initializes an empty audit report for a given target.
func NewAuditReport(target string) *AuditReport {
	return &AuditReport{
		TargetRepo:    target,
		ScanTime:      time.Now().UTC(),
		Findings:      make([]Finding, 0),
		ExploitChains: make([]ExploitChain, 0),
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

// AddExploitChain appends an exploitable attack chain to the report.
func (r *AuditReport) AddExploitChain(ec ExploitChain) {
	r.ExploitChains = append(r.ExploitChains, ec)
}

