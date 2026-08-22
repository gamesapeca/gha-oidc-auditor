package parser_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

func TestCompositeAction_ParsingAndResolution(t *testing.T) {
	tempDir := t.TempDir()
	actionDir := filepath.Join(tempDir, ".github", "actions", "deploy-helper")
	if err := os.MkdirAll(actionDir, 0755); err != nil {
		t.Fatalf("failed to create temp action dir: %v", err)
	}

	actionContent := `
name: "Deploy Helper Action"
description: "Executes deployment steps"
runs:
  using: "composite"
  steps:
    - name: Echo Step
      shell: bash
      run: echo "Deploying target ${{ inputs.env }}"
    - name: Sub Action
      uses: actions/checkout@v4
`
	actionFile := filepath.Join(actionDir, "action.yml")
	if err := os.WriteFile(actionFile, []byte(actionContent), 0644); err != nil {
		t.Fatalf("failed to write action.yml: %v", err)
	}

	// 1. Direct file parsing
	comp, err := parser.ParseCompositeActionFile(actionFile)
	if err != nil {
		t.Fatalf("ParseCompositeActionFile failed: %v", err)
	}
	if comp.Name != "Deploy Helper Action" {
		t.Errorf("expected name 'Deploy Helper Action', got %s", comp.Name)
	}
	if comp.Runs.Using != "composite" {
		t.Errorf("expected runs.using 'composite', got %s", comp.Runs.Using)
	}
	if len(comp.Runs.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(comp.Runs.Steps))
	}

	// 2. Local action reference resolution
	resolved, err := parser.ResolveLocalCompositeAction(tempDir, "./.github/actions/deploy-helper")
	if err != nil {
		t.Fatalf("ResolveLocalCompositeAction failed: %v", err)
	}
	if resolved.Name != "Deploy Helper Action" {
		t.Errorf("expected resolved name 'Deploy Helper Action', got %s", resolved.Name)
	}
}
