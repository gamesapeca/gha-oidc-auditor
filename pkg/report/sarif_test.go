package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/report"
)

func TestExportSARIF_SchemaAndMapping(t *testing.T) {
	rep := analyzer.NewAuditReport("gamesapeca/target-repo")
	rep.AddFinding(analyzer.Finding{
		RuleID:       "OIDC-001",
		Title:        "Untrusted Context Injection in Run",
		Category:     "Injection",
		CWE:          "CWE-78",
		Severity:     analyzer.SeverityCritical,
		WorkflowPath: ".github/workflows/deploy.yml",
		JobName:      "deploy",
		LineNumber:   42,
		Description:  "Untrusted github.event.issue.title injected into shell step",
		Remediation:  "Pass context via env: block instead of inline interpolation",
	})
	rep.AddFinding(analyzer.Finding{
		RuleID:       "OIDC-002",
		Title:        "Unpinned Action",
		Category:     "SupplyChain",
		CWE:          "CWE-829",
		Severity:     analyzer.SeverityMedium,
		WorkflowPath: ".github/workflows/ci.yml",
		JobName:      "lint",
		LineNumber:   15,
		Description:  "Action uses mutable tag v4",
		Remediation:  "Pin action to full 40-character commit SHA",
	})
	rep.AddExploitChain(analyzer.ExploitChain{
		ID:            "CHAIN-001",
		Title:         "PRT OIDC Cloud Takeover",
		Category:      "Privilege Escalation",
		CWE:           "CWE-269",
		Severity:      analyzer.SeverityCritical,
		WorkflowPath:  ".github/workflows/deploy.yml",
		JobName:       "deploy",
		TriggerEvent:  "pull_request_target",
		IngressVector: "untrusted checkout",
		TargetCloud:   analyzer.ProviderAWS,
	})

	sarifStr, err := report.ExportSARIF(rep)
	if err != nil {
		t.Fatalf("ExportSARIF failed: %v", err)
	}

	var parsed report.SARIFReport
	if err := json.Unmarshal([]byte(sarifStr), &parsed); err != nil {
		t.Fatalf("Failed to parse emitted SARIF as JSON: %v", err)
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %s", parsed.Version)
	}
	if !strings.Contains(parsed.Schema, "sarif-schema-2.1.0.json") {
		t.Errorf("Unexpected schema URL: %s", parsed.Schema)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(parsed.Runs))
	}

	run := parsed.Runs[0]
	if run.Tool.Driver.Name != "gha-oidc-auditor" {
		t.Errorf("Unexpected driver name: %s", run.Tool.Driver.Name)
	}

	// 2 findings + 1 chain = 3 results
	if len(run.Results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(run.Results))
	}

	// Check result 0 (OIDC-001 -> error level)
	r0 := run.Results[0]
	if r0.RuleID != "OIDC-001" || r0.Level != "error" {
		t.Errorf("Unexpected result 0: rule=%s, level=%s", r0.RuleID, r0.Level)
	}
	if len(r0.Locations) != 1 || r0.Locations[0].PhysicalLocation.ArtifactLocation.URI != ".github/workflows/deploy.yml" {
		t.Errorf("Unexpected location for result 0: %+v", r0.Locations)
	}
	if r0.Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("Expected startLine 42, got %d", r0.Locations[0].PhysicalLocation.Region.StartLine)
	}

	// Check result 1 (OIDC-002 -> warning level)
	r1 := run.Results[1]
	if r1.RuleID != "OIDC-002" || r1.Level != "warning" {
		t.Errorf("Unexpected result 1: rule=%s, level=%s", r1.RuleID, r1.Level)
	}

	// Check result 2 (CHAIN-001 -> error level)
	r2 := run.Results[2]
	if r2.RuleID != "CHAIN-001" || r2.Level != "error" {
		t.Errorf("Unexpected result 2: rule=%s, level=%s", r2.RuleID, r2.Level)
	}
}

func TestExportFullJSON_OutputStructure(t *testing.T) {
	rep := analyzer.NewAuditReport("owner/repo")
	policies := map[string]string{
		"deploy_aws.json": `{"Version": "2012-10-17"}`,
	}
	hcl := map[string]string{
		"aws_oidc.tf": `resource "aws_iam_role" "deploy" {}`,
	}

	out, err := report.ExportFullJSON(rep, policies, hcl, "owner/repo", 150)
	if err != nil {
		t.Fatalf("ExportFullJSON failed: %v", err)
	}

	var machine report.MachineReport
	if err := json.Unmarshal([]byte(out), &machine); err != nil {
		t.Fatalf("Failed to parse FullJSON output: %v", err)
	}

	if machine.Target != "owner/repo" {
		t.Errorf("Expected target 'owner/repo', got '%s'", machine.Target)
	}
	if machine.DurationMs != 150 {
		t.Errorf("Expected duration 150ms, got %d", machine.DurationMs)
	}
	if len(machine.SynthesizedPolicies) != 1 || machine.SynthesizedPolicies["deploy_aws.json"] == "" {
		t.Errorf("Expected synthesized policy in JSON output")
	}
	if len(machine.SynthesizedHCL) != 1 || machine.SynthesizedHCL["aws_oidc.tf"] == "" {
		t.Errorf("Expected synthesized HCL in JSON output")
	}
}
