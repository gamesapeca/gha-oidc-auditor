package orchestrator_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/orchestrator"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/report"
)

func TestPipeline_LocalScanVulnerable(t *testing.T) {
	cfg := orchestrator.DefaultConfig()
	cfg.Path = filepath.Join("..", "..", "testdata", "vulnerable")
	cfg.Concurrency = 4

	pipeline := orchestrator.NewPipeline(cfg)
	res, err := pipeline.Run(context.Background())
	if err != nil {
		t.Fatalf("Pipeline run failed: %v", err)
	}

	if res.ExitCode == report.ExitOK {
		t.Errorf("Expected non-zero exit code for vulnerable fixtures, got %d", res.ExitCode)
	}
	if !strings.Contains(strings.ToLower(res.FormattedOutput), "gha-oidc-auditor") {
		t.Errorf("Expected console output to contain tool header, got: %s", res.FormattedOutput)
	}
}

func TestPipeline_MultiFormatExport(t *testing.T) {
	formats := []string{"console", "json", "jsonl", "ndjson", "sarif", "markdown", "hcl"}

	for _, fmtName := range formats {
		t.Run("Format_"+fmtName, func(t *testing.T) {
			cfg := orchestrator.DefaultConfig()
			cfg.Path = filepath.Join("..", "..", "testdata", "vulnerable")
			cfg.Format = fmtName
			cfg.GeneratePolicies = true
			cfg.GenerateHCL = true

			pipeline := orchestrator.NewPipeline(cfg)
			res, err := pipeline.Run(context.Background())
			if err != nil {
				t.Fatalf("Pipeline failed for format %s: %v", fmtName, err)
			}

			if len(res.FormattedOutput) == 0 {
				t.Errorf("Empty output for format %s", fmtName)
			}

			switch fmtName {
			case "json":
				var js map[string]interface{}
				if err := json.Unmarshal([]byte(res.FormattedOutput), &js); err != nil {
					t.Fatalf("Failed to parse JSON output: %v", err)
				}
				if _, ok := js["audit_report"]; !ok {
					t.Errorf("Expected 'audit_report' key in JSON output")
				}
			case "jsonl", "ndjson":
				lines := strings.Split(strings.TrimSpace(res.FormattedOutput), "\n")
				if len(lines) == 0 {
					t.Fatalf("Expected non-empty NDJSON lines for format %s", fmtName)
				}
				for idx, l := range lines {
					var raw map[string]interface{}
					if err := json.Unmarshal([]byte(l), &raw); err != nil {
						t.Fatalf("Line %d failed to parse as JSON: %v. Content: %s", idx, err, l)
					}
				}
			case "sarif":
				var sarifDoc report.SARIFReport
				if err := json.Unmarshal([]byte(res.FormattedOutput), &sarifDoc); err != nil {
					t.Fatalf("Failed to parse SARIF output: %v", err)
				}
				if sarifDoc.Version != "2.1.0" {
					t.Errorf("Expected SARIF version 2.1.0, got %s", sarifDoc.Version)
				}
			case "markdown":
				if !strings.Contains(res.FormattedOutput, "Security Audit Report") {
					t.Errorf("Expected markdown title in output")
				}
			case "hcl":
				if !strings.Contains(res.FormattedOutput, "resource") {
					t.Errorf("Expected HCL resource block in output")
				}
			}
		})
	}
}

func TestPipeline_BountyModeAndPoC(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "poc_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	pocFile := filepath.Join(tempDir, "poc.md")

	cfg := orchestrator.DefaultConfig()
	cfg.Path = filepath.Join("..", "..", "testdata", "vulnerable")
	cfg.BountyMode = true
	cfg.GeneratePoC = true
	cfg.PoCOutputFile = pocFile

	pipeline := orchestrator.NewPipeline(cfg)
	res, err := pipeline.Run(context.Background())
	if err != nil {
		t.Fatalf("Pipeline run failed in bounty mode: %v", err)
	}

	if res.PoCContent == "" {
		t.Errorf("Expected non-empty PoC content")
	}

	if _, err := os.Stat(pocFile); os.IsNotExist(err) {
		t.Errorf("Expected PoC file to be written at %s", pocFile)
	}
}

func TestPipeline_VerifyPolicyMode(t *testing.T) {
	policyPath := filepath.Join("..", "..", "testdata", "policies", "aws_least_privilege_policy.json")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		t.Skip("Policy fixture not found, skipping")
	}

	cfg := orchestrator.DefaultConfig()
	cfg.VerifyPolicy = policyPath
	cfg.CloudProvider = "aws"

	pipeline := orchestrator.NewPipeline(cfg)
	res, err := pipeline.Run(context.Background())
	if err != nil {
		t.Fatalf("Policy verification failed: %v", err)
	}

	if !strings.Contains(res.FormattedOutput, "Cloud Trust Policy Audit") {
		t.Errorf("Expected verification header in output, got: %s", res.FormattedOutput)
	}
}
