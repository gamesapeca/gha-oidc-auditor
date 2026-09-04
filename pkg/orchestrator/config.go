package orchestrator

import (
	"runtime"
)

// Config encapsulates all execution parameters for an audit pipeline run.
type Config struct {
	// Target specifications
	Path string `json:"path,omitempty"`
	Repo string `json:"repo,omitempty"`
	Org  string `json:"org,omitempty"`

	// Authentication & Networking
	Token       string `json:"token,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`

	// Output & Formatting
	Format        string `json:"format,omitempty"` // console, json, jsonl, ndjson, sarif, markdown, hcl
	FailOn        string `json:"fail_on,omitempty"`
	OutputFile    string `json:"output_file,omitempty"`
	PoCOutputFile string `json:"poc_output_file,omitempty"`
	HCLOutputDir  string `json:"hcl_output_dir,omitempty"`

	// Features & Synthesis
	GeneratePolicies bool `json:"generate_policies,omitempty"`
	GenerateHCL      bool `json:"generate_hcl,omitempty"`
	BountyMode       bool `json:"bounty_mode,omitempty"`
	GeneratePoC      bool `json:"generate_poc,omitempty"`

	// Cloud Policy Verification (CIEM offline verification mode)
	VerifyPolicy  string `json:"verify_policy,omitempty"`
	CloudProvider string `json:"cloud_provider,omitempty"`
}

// DefaultConfig initializes standard production defaults for pipeline execution.
func DefaultConfig() Config {
	return Config{
		Format:        "console",
		FailOn:        "critical",
		Concurrency:   runtime.NumCPU(),
		CloudProvider: "aws",
	}
}

// RunResult aggregates all artifacts produced by the audit pipeline execution.
type RunResult struct {
	Target              string            `json:"target"`
	ExitCode            int               `json:"exit_code"`
	DurationMs          int64             `json:"duration_ms"`
	AuditReport         interface{}       `json:"audit_report,omitempty"` // *analyzer.AuditReport
	FormattedOutput     string            `json:"formatted_output,omitempty"`
	SynthesizedPolicies map[string]string `json:"synthesized_policies,omitempty"`
	SynthesizedHCL      map[string]string `json:"synthesized_hcl,omitempty"`
	PoCContent          string            `json:"poc_content,omitempty"`
}
