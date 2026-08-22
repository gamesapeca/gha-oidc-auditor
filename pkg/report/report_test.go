package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/report"
)

func TestDetermineExitCode_Matrix(t *testing.T) {
	tests := []struct {
		name         string
		setupReport  func() *analyzer.AuditReport
		failOn       string
		expectedCode int
	}{
		{
			name: "Nil report returns ExitOK",
			setupReport: func() *analyzer.AuditReport {
				return nil
			},
			failOn:       "critical",
			expectedCode: report.ExitOK,
		},
		{
			name: "Empty findings returns ExitOK",
			setupReport: func() *analyzer.AuditReport {
				return analyzer.NewAuditReport("test/repo")
			},
			failOn:       "all",
			expectedCode: report.ExitOK,
		},
		{
			name: "Fail-on none returns ExitOK even with Critical findings",
			setupReport: func() *analyzer.AuditReport {
				rep := analyzer.NewAuditReport("test/repo")
				rep.AddFinding(analyzer.Finding{Severity: analyzer.SeverityCritical})
				return rep
			},
			failOn:       "none",
			expectedCode: report.ExitOK,
		},
		{
			name: "Fail-on critical with Critical finding returns ExitCriticalFound",
			setupReport: func() *analyzer.AuditReport {
				rep := analyzer.NewAuditReport("test/repo")
				rep.AddFinding(analyzer.Finding{Severity: analyzer.SeverityCritical})
				return rep
			},
			failOn:       "critical",
			expectedCode: report.ExitCriticalFound,
		},
		{
			name: "Fail-on critical with only High finding returns ExitOK",
			setupReport: func() *analyzer.AuditReport {
				rep := analyzer.NewAuditReport("test/repo")
				rep.AddFinding(analyzer.Finding{Severity: analyzer.SeverityHigh})
				return rep
			},
			failOn:       "critical",
			expectedCode: report.ExitOK,
		},
		{
			name: "Fail-on high with Critical finding returns ExitCriticalFound",
			setupReport: func() *analyzer.AuditReport {
				rep := analyzer.NewAuditReport("test/repo")
				rep.AddFinding(analyzer.Finding{Severity: analyzer.SeverityCritical})
				return rep
			},
			failOn:       "high",
			expectedCode: report.ExitCriticalFound,
		},
		{
			name: "Fail-on high with High finding returns ExitFindingsFound",
			setupReport: func() *analyzer.AuditReport {
				rep := analyzer.NewAuditReport("test/repo")
				rep.AddFinding(analyzer.Finding{Severity: analyzer.SeverityHigh})
				return rep
			},
			failOn:       "high",
			expectedCode: report.ExitFindingsFound,
		},
		{
			name: "Fail-on high with Medium finding returns ExitOK",
			setupReport: func() *analyzer.AuditReport {
				rep := analyzer.NewAuditReport("test/repo")
				rep.AddFinding(analyzer.Finding{Severity: analyzer.SeverityMedium})
				return rep
			},
			failOn:       "high",
			expectedCode: report.ExitOK,
		},
		{
			name: "Fail-on medium with Medium finding returns ExitFindingsFound",
			setupReport: func() *analyzer.AuditReport {
				rep := analyzer.NewAuditReport("test/repo")
				rep.AddFinding(analyzer.Finding{Severity: analyzer.SeverityMedium})
				return rep
			},
			failOn:       "medium",
			expectedCode: report.ExitFindingsFound,
		},
		{
			name: "Fail-on all with Low/Info finding returns ExitFindingsFound",
			setupReport: func() *analyzer.AuditReport {
				rep := analyzer.NewAuditReport("test/repo")
				rep.AddFinding(analyzer.Finding{Severity: analyzer.SeverityLow})
				return rep
			},
			failOn:       "all",
			expectedCode: report.ExitFindingsFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := tt.setupReport()
			code := report.DetermineExitCode(rep, tt.failOn)
			if code != tt.expectedCode {
				t.Errorf("DetermineExitCode() = %d, want %d", code, tt.expectedCode)
			}
		})
	}
}

func TestExportJSON_SchemaValidation(t *testing.T) {
	rep := analyzer.NewAuditReport("gamesapeca/gha-oidc-auditor")
	rep.AddFinding(analyzer.Finding{
		RuleID:       "OIDC-001",
		Severity:     analyzer.SeverityHigh,
		WorkflowPath: ".github/workflows/deploy.yml",
		JobName:      "deploy",
		StepIndex:    2,
		Provider:     analyzer.ProviderAWS,
		Title:        "Global OIDC write",
		Description:  "Workflow grants id-token: write globally",
		Remediation:  "Restrict to job",
	})

	jsonStr, err := report.ExportJSON(rep)
	if err != nil {
		t.Fatalf("failed to export JSON: %v", err)
	}

	var parsed struct {
		TargetRepo   string                      `json:"target_repo"`
		Findings     []analyzer.Finding          `json:"findings"`
		Summary      map[analyzer.Severity]int   `json:"summary"`
		WorkflowsNum int                         `json:"workflows_scanned"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("failed to deserialized exported JSON: %v", err)
	}

	if parsed.TargetRepo != "gamesapeca/gha-oidc-auditor" {
		t.Errorf("TargetRepo = %s, want gamesapeca/gha-oidc-auditor", parsed.TargetRepo)
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].RuleID != "OIDC-001" {
		t.Errorf("RuleID = %s, want OIDC-001", parsed.Findings[0].RuleID)
	}
	if parsed.Summary[analyzer.SeverityHigh] != 1 {
		t.Errorf("Summary High = %d, want 1", parsed.Summary[analyzer.SeverityHigh])
	}
}

func TestExportMarkdown_Formatting(t *testing.T) {
	t.Run("Report with Findings and Policies", func(t *testing.T) {
		rep := analyzer.NewAuditReport("gamesapeca/gha-oidc-auditor")
		rep.WorkflowsNum = 3
		rep.AddFinding(analyzer.Finding{
			RuleID:       "OIDC-004",
			Severity:     analyzer.SeverityCritical,
			WorkflowPath: ".github/workflows/ci.yml",
			JobName:      "test",
			StepIndex:    1,
			Title:        "Context injection",
			Description:  "Untrusted issue title interpolated",
			Remediation:  "Use env variable",
		})

		policies := map[string]string{
			"Deploy_AWS_TrustPolicy.json": "{\n  \"Version\": \"2012-10-17\"\n}",
		}

		md := report.ExportMarkdown(rep, policies)

		if !strings.Contains(md, "# Security Audit Report: GitHub Actions OIDC") {
			t.Errorf("Markdown title missing")
		}
		if !strings.Contains(md, "CRITICAL") {
			t.Errorf("CRITICAL count missing from table")
		}
		if !strings.Contains(md, "Deploy_AWS_TrustPolicy.json") {
			t.Errorf("Policy key missing from markdown")
		}
		if !strings.Contains(md, "```json") {
			t.Errorf("JSON code block missing")
		}
	})

	t.Run("Report with Zero Findings", func(t *testing.T) {
		rep := analyzer.NewAuditReport("safe/repo")
		md := report.ExportMarkdown(rep, nil)

		if !strings.Contains(md, "No OIDC supply chain risks") {
			t.Errorf("Clean report message missing from markdown")
		}
	})
}

func TestRenderConsole_Outputs(t *testing.T) {
	t.Run("Console with Findings", func(t *testing.T) {
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
		if !strings.Contains(output, "OIDC-002") {
			t.Errorf("Rule ID not rendered")
		}
	})

	t.Run("Console with Zero Findings", func(t *testing.T) {
		rep := analyzer.NewAuditReport("safe/repo")
		var buf bytes.Buffer
		report.RenderConsole(&buf, rep)

		output := buf.String()
		if !strings.Contains(output, "[OK]") {
			t.Errorf("[OK] message not rendered for zero findings")
		}
	})

	t.Run("Console with Exploit Chains", func(t *testing.T) {
		rep := analyzer.NewAuditReport("vulnerable/repo")
		rep.AddExploitChain(analyzer.ExploitChain{
			ID:            "CHAIN-001",
			Title:         "Zero-Prerequisite Pwn-Request RCE",
			Severity:      analyzer.SeverityCritical,
			WorkflowPath:  ".github/workflows/pwn.yml",
			JobName:       "pwn_job",
			TriggerEvent:  "pull_request_target",
			IngressVector: "actions/checkout",
			TargetCloud:   analyzer.ProviderAWS,
			PoCPayload:    "aws sts assume-role-with-web-identity ...",
		})

		var buf bytes.Buffer
		report.RenderConsole(&buf, rep)

		output := buf.String()
		if !strings.Contains(output, "EXPLOITABLE BUG BOUNTY ATTACK CHAINS") {
			t.Errorf("bug bounty banner missing in console output")
		}
		if !strings.Contains(output, "CHAIN-001") {
			t.Errorf("CHAIN-001 missing in console output")
		}
	})
}

func TestGenerateBugBountyReport_Formatting(t *testing.T) {
	rep := analyzer.NewAuditReport("gamesapeca/gha-oidc-auditor")
	rep.AddExploitChain(analyzer.ExploitChain{
		ID:             "CHAIN-001",
		Title:          "Pwn-Request RCE",
		Severity:       analyzer.SeverityCritical,
		WorkflowPath:   ".github/workflows/prt.yml",
		JobName:        "pwn",
		ReportTemplate: "### Steps to Reproduce\n1. Submit PR\n2. Gain RCE",
	})

	md := report.GenerateBugBountyReport(rep)
	if !strings.Contains(md, "# Bug Bounty Vulnerability Submission Report") {
		t.Errorf("title missing from Bug Bounty report")
	}
	if !strings.Contains(md, "Pwn-Request RCE") {
		t.Errorf("chain title missing from report")
	}
	if !strings.Contains(md, "Gain RCE") {
		t.Errorf("reproduction steps missing from report")
	}
}

