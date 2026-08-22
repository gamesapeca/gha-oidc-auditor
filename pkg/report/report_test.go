package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/report"
)

func TestDetermineExitCode(t *testing.T) {
	rep := analyzer.NewAuditReport("test/repo")
	rep.AddFinding(analyzer.Finding{
		RuleID:   "OIDC-002",
		Severity: analyzer.SeverityCritical,
	})
	rep.AddFinding(analyzer.Finding{
		RuleID:   "OIDC-003",
		Severity: analyzer.SeverityHigh,
	})

	if code := report.DetermineExitCode(rep, "critical"); code != report.ExitCriticalFound {
		t.Errorf("expected ExitCriticalFound (2), got: %d", code)
	}

	if code := report.DetermineExitCode(rep, "none"); code != report.ExitOK {
		t.Errorf("expected ExitOK (0) for fail-on none, got: %d", code)
	}

	if code := report.DetermineExitCode(rep, "all"); code != report.ExitFindingsFound {
		t.Errorf("expected ExitFindingsFound (1) for fail-on all, got: %d", code)
	}
}

func TestExportJSON(t *testing.T) {
	rep := analyzer.NewAuditReport("gamesapeca/gha-oidc-auditor")
	rep.AddFinding(analyzer.Finding{
		RuleID:       "OIDC-001",
		Severity:     analyzer.SeverityHigh,
		WorkflowPath: ".github/workflows/deploy.yml",
		JobName:      "deploy",
		Title:        "Global OIDC write",
	})

	jsonStr, err := report.ExportJSON(rep)
	if err != nil {
		t.Fatalf("failed to export JSON: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("generated JSON is invalid: %v", err)
	}

	if parsed["target_repo"] != "gamesapeca/gha-oidc-auditor" {
		t.Errorf("incorrect target_repo field in JSON: %v", parsed["target_repo"])
	}
}

func TestExportMarkdown(t *testing.T) {
	rep := analyzer.NewAuditReport("gamesapeca/gha-oidc-auditor")
	rep.AddFinding(analyzer.Finding{
		RuleID:       "OIDC-004",
		Severity:     analyzer.SeverityCritical,
		WorkflowPath: ".github/workflows/ci.yml",
		JobName:      "test",
		Title:        "Context injection",
		Description:  "Untrusted issue title interpolated",
		Remediation:  "Use env variable",
	})

	policies := map[string]string{
		"AWS_TrustPolicy.json": "{\n  \"Version\": \"2012-10-17\"\n}",
	}

	md := report.ExportMarkdown(rep, policies)
	if !strings.Contains(md, "Security Audit Report") {
		t.Errorf("markdown title not found")
	}
	if !strings.Contains(md, "AWS_TrustPolicy.json") {
		t.Errorf("synthesized policy missing from markdown")
	}
}

func TestRenderConsole(t *testing.T) {
	rep := analyzer.NewAuditReport("gamesapeca/gha-oidc-auditor")
	rep.AddFinding(analyzer.Finding{
		RuleID:       "OIDC-002",
		Severity:     analyzer.SeverityCritical,
		WorkflowPath: ".github/workflows/prt.yml",
		JobName:      "pwn",
		Title:        "Ungated PRT OIDC",
		Description:  "PRT trigger allows external fork minting",
		Remediation:  "Add environment gate",
	})

	var buf bytes.Buffer
	report.RenderConsole(&buf, rep)

	output := buf.String()
	if !strings.Contains(output, "GHA-OIDC-AUDITOR") {
		t.Errorf("console banner not rendered")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Errorf("CRITICAL severity badge not rendered")
	}
}
