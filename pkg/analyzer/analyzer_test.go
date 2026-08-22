package analyzer_test

import (
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

func TestEngine_VulnerableFixtures(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		expectRuleID string
	}{
		{
			name:         "PRT with Ungated OIDC",
			filePath:     "../../testdata/vulnerable/prt_oidc_minting.yml",
			expectRuleID: "OIDC-002",
		},
		{
			name:         "Global OIDC Leak",
			filePath:     "../../testdata/vulnerable/global_oidc_leak.yml",
			expectRuleID: "OIDC-001",
		},
		{
			name:         "Mutable Action in OIDC Job",
			filePath:     "../../testdata/vulnerable/mutable_action_oidc.yml",
			expectRuleID: "OIDC-003",
		},
		{
			name:         "Context Injection in OIDC Job",
			filePath:     "../../testdata/vulnerable/context_injection_run.yml",
			expectRuleID: "OIDC-004",
		},
		{
			name:         "Workflow Run OIDC Unsafe",
			filePath:     "../../testdata/vulnerable/workflow_run_oidc.yml",
			expectRuleID: "OIDC-006",
		},
	}

	engine := analyzer.NewDefaultEngine()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf, err := parser.ParseWorkflowFile(tt.filePath)
			if err != nil {
				t.Fatalf("failed to read workflow fixture %s: %v", tt.filePath, err)
			}

			findings := engine.AnalyzeWorkflow(wf)
			if len(findings) == 0 {
				t.Fatalf("expected finding for rule %s, got none", tt.expectRuleID)
			}

			found := false
			for _, f := range findings {
				if f.RuleID == tt.expectRuleID {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected rule %s was not found in findings: %+v", tt.expectRuleID, findings)
			}
		})
	}
}

func TestEngine_SafeFixtures(t *testing.T) {
	safeFiles := []string{
		"../../testdata/safe/sha_pinned_oidc.yml",
		"../../testdata/safe/environment_gate.yml",
		"../../testdata/safe/env_var_context.yml",
	}

	engine := analyzer.NewDefaultEngine()

	for _, file := range safeFiles {
		t.Run(file, func(t *testing.T) {
			wf, err := parser.ParseWorkflowFile(file)
			if err != nil {
				t.Fatalf("failed to read safe fixture %s: %v", file, err)
			}

			findings := engine.AnalyzeWorkflow(wf)
			if len(findings) > 0 {
				t.Errorf("false positive detected in safe fixture %s: %+v", file, findings)
			}
		})
	}
}

func TestPrecedence_Resolution(t *testing.T) {
	yamlContent := `
name: Precedence Test
permissions:
  id-token: write
jobs:
  override_none:
    permissions: {}
    steps:
      - run: echo 1
  override_read:
    permissions:
      id-token: read
    steps:
      - run: echo 2
  inherit_global:
    steps:
      - run: echo 3
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "prec.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if analyzer.ResolveJobIDTokenPermission(wf, "override_none") != "none" {
		t.Errorf("override_none should be 'none', got: %s", analyzer.ResolveJobIDTokenPermission(wf, "override_none"))
	}
	if analyzer.ResolveJobIDTokenPermission(wf, "override_read") != "read" {
		t.Errorf("override_read should be 'read', got: %s", analyzer.ResolveJobIDTokenPermission(wf, "override_read"))
	}
	if analyzer.ResolveJobIDTokenPermission(wf, "inherit_global") != "write" {
		t.Errorf("inherit_global should inherit 'write', got: %s", analyzer.ResolveJobIDTokenPermission(wf, "inherit_global"))
	}
}
