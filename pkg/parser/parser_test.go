package parser_test

import (
	"strings"
	"testing"
	"time"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

func TestParseWorkflow_Triggers(t *testing.T) {
	t.Run("Scalar Trigger", func(t *testing.T) {
		yamlContent := `
name: Scalar CI
on: push
jobs:
  build:
    steps:
      - run: echo "building"
`
		wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "scalar.yml")
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(wf.On.Events) != 1 || wf.On.Events[0] != "push" {
			t.Fatalf("expected event ['push'], got: %v", wf.On.Events)
		}
	})

	t.Run("Sequence Trigger", func(t *testing.T) {
		yamlContent := `
name: Sequence CI
on: [push, pull_request_target, workflow_dispatch]
jobs:
  test:
    steps:
      - run: go test ./...
`
		wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "seq.yml")
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(wf.On.Events) != 3 {
			t.Fatalf("expected 3 events, got: %d", len(wf.On.Events))
		}
		expected := []string{"push", "pull_request_target", "workflow_dispatch"}
		for i, exp := range expected {
			if wf.On.Events[i] != exp {
				t.Errorf("event at index %d: expected %s, got %s", i, exp, wf.On.Events[i])
			}
		}
	})

	t.Run("Complex Mapping Trigger with Schedule and WorkflowRun", func(t *testing.T) {
		yamlContent := `
name: Complex Mapping CI
on:
  push:
    branches: [main, "release/**"]
  schedule:
    - cron: '0 0 * * *'
  workflow_run:
    workflows: ["Build"]
    types: [completed]
    branches: [main]
jobs:
  deploy:
    steps:
      - run: echo deploy
`
		wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "complex_map.yml")
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(wf.On.Events) != 3 {
			t.Fatalf("expected 3 events in mapping, got: %d", len(wf.On.Events))
		}
		if wf.On.Conditions == nil || len(wf.On.Conditions) != 3 {
			t.Fatalf("trigger conditions map missing or incomplete: %+v", wf.On.Conditions)
		}
	})
}

func TestParseWorkflow_PermissionsVariants(t *testing.T) {
	yamlContent := `
name: Permissions Matrix
permissions: write-all
jobs:
  inherit_global:
    steps:
      - run: echo 1
  override_read_all:
    permissions: read-all
    steps:
      - run: echo 2
  override_empty_map:
    permissions: {}
    steps:
      - run: echo 3
  override_granular:
    permissions:
      id-token: write
      contents: read
      pull-requests: write
    steps:
      - run: echo 4
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "perms.yml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if wf.PermissionsAll != "write-all" {
		t.Errorf("expected workflow root permissions 'write-all', got: '%s'", wf.PermissionsAll)
	}

	jobReadAll := wf.Jobs["override_read_all"]
	if jobReadAll.PermissionsAll != "read-all" {
		t.Errorf("expected job read-all, got: '%s'", jobReadAll.PermissionsAll)
	}

	jobEmpty := wf.Jobs["override_empty_map"]
	if jobEmpty.Permissions == nil || len(jobEmpty.Permissions) != 0 {
		t.Errorf("expected empty permissions map for override_empty_map, got: %+v", jobEmpty.Permissions)
	}

	jobGranular := wf.Jobs["override_granular"]
	if jobGranular.Permissions["id-token"] != "write" || jobGranular.Permissions["contents"] != "read" || jobGranular.Permissions["pull-requests"] != "write" {
		t.Errorf("granular permissions mismatch: %+v", jobGranular.Permissions)
	}
}

func TestStep_HeterogeneousInputsAndNilSafety(t *testing.T) {
	step := &parser.Step{
		Name: "Test Step",
		With: map[string]interface{}{
			"str_key":   "normal_string",
			"int_key":   42,
			"neg_int":   -999,
			"float_key": 3.1415,
			"bool_true": true,
			"bool_fls":  false,
			"nil_val":   nil,
			"slice_val": []string{"item1", "item2"},
			"map_val":   map[string]string{"k": "v"},
		},
		Env: map[string]interface{}{
			"ENV_PORT":    8080,
			"ENV_ENABLED": true,
			"ENV_NIL":     nil,
		},
	}

	if step.GetWithString("str_key") != "normal_string" {
		t.Errorf("str_key mismatch")
	}
	if step.GetWithString("int_key") != "42" {
		t.Errorf("int_key mismatch: %s", step.GetWithString("int_key"))
	}
	if step.GetWithString("neg_int") != "-999" {
		t.Errorf("neg_int mismatch: %s", step.GetWithString("neg_int"))
	}
	if step.GetWithString("bool_true") != "true" {
		t.Errorf("bool_true mismatch: %s", step.GetWithString("bool_true"))
	}
	if step.GetWithString("bool_fls") != "false" {
		t.Errorf("bool_fls mismatch: %s", step.GetWithString("bool_fls"))
	}
	if step.GetWithString("nil_val") != "" {
		t.Errorf("nil_val should return empty string")
	}
	if step.GetWithString("non_existent") != "" {
		t.Errorf("non_existent should return empty string")
	}

	if step.GetEnvString("ENV_PORT") != "8080" {
		t.Errorf("ENV_PORT mismatch: %s", step.GetEnvString("ENV_PORT"))
	}
	if step.GetEnvString("ENV_ENABLED") != "true" {
		t.Errorf("ENV_ENABLED mismatch: %s", step.GetEnvString("ENV_ENABLED"))
	}
	if step.GetEnvString("ENV_NIL") != "" {
		t.Errorf("ENV_NIL should return empty string")
	}

	// Nil receiver safety tests
	var nilStep *parser.Step
	if nilStep.GetWithString("any") != "" {
		t.Errorf("nil Step.GetWithString must return empty string without panicking")
	}
	if nilStep.GetEnvString("any") != "" {
		t.Errorf("nil Step.GetEnvString must return empty string without panicking")
	}

	var nilJob *parser.Job
	if nilJob.GetEnvironmentName() != "" {
		t.Errorf("nil Job.GetEnvironmentName must return empty string without panicking")
	}
}

func TestJob_EnvironmentExtraction(t *testing.T) {
	yamlContent := `
name: Environments
jobs:
  scalar_env:
    environment: production
    steps: [{ run: echo 1 }]
  mapping_env:
    environment:
      name: staging
      url: https://staging.internal
    steps: [{ run: echo 2 }]
  nil_env:
    steps: [{ run: echo 3 }]
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "envs.yml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	scalarJob := wf.Jobs["scalar_env"]
	if scalarJob.GetEnvironmentName() != "production" {
		t.Errorf("expected 'production', got: '%s'", scalarJob.GetEnvironmentName())
	}

	mappingJob := wf.Jobs["mapping_env"]
	if mappingJob.GetEnvironmentName() != "staging" {
		t.Errorf("expected 'staging', got: '%s'", mappingJob.GetEnvironmentName())
	}

	nilJob := wf.Jobs["nil_env"]
	if nilJob.GetEnvironmentName() != "" {
		t.Errorf("expected empty environment name for nil_env, got: '%s'", nilJob.GetEnvironmentName())
	}
}

func TestExpressionEval_CaseInsensitivityAndVariants(t *testing.T) {
	tests := []struct {
		name       string
		runBlock   string
		wantFound  bool
		wantTarget string
	}{
		{
			name:       "Standard lower case",
			runBlock:   `echo "${{ github.event.issue.title }}"`,
			wantFound:  true,
			wantTarget: "github.event.issue.title",
		},
		{
			name:       "Upper case evasion attempt",
			runBlock:   `echo "${{ GITHUB.EVENT.ISSUE.TITLE }}"`,
			wantFound:  true,
			wantTarget: "github.event.issue.title",
		},
		{
			name:       "Mixed case evasion attempt",
			runBlock:   `echo "${{ GitHub.Event.Pull_Request.Head.Ref }}"`,
			wantFound:  true,
			wantTarget: "github.event.pull_request.head.ref",
		},
		{
			name:       "Nested function call expression",
			runBlock:   `python script.py --title "${{ format('{0}', github.event.discussion.title) }}"`,
			wantFound:  true,
			wantTarget: "github.event.discussion.title",
		},
		{
			name:       "Workflow input expression",
			runBlock:   `deploy.sh "${{ github.event.inputs.target_env }}"`,
			wantFound:  true,
			wantTarget: "github.event.inputs.",
		},
		{
			name:       "Safe secret reference",
			runBlock:   `echo "${{ secrets.PROD_API_KEY }}"`,
			wantFound:  false,
			wantTarget: "",
		},
		{
			name:       "Safe github sha reference",
			runBlock:   `git checkout "${{ github.sha }}"`,
			wantFound:  false,
			wantTarget: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, target := parser.ContainsUntrustedContext(tt.runBlock)
			if found != tt.wantFound {
				t.Errorf("ContainsUntrustedContext() found = %v, want %v", found, tt.wantFound)
			}
			if target != tt.wantTarget {
				t.Errorf("ContainsUntrustedContext() target = %v, want %v", target, tt.wantTarget)
			}
		})
	}
}

func TestExpressionEval_ReDoSStressTest(t *testing.T) {
	// Build an adversarial payload with repeating unclosed pattern fragments
	var builder strings.Builder
	for i := 0; i < 5000; i++ {
		builder.WriteString("${{ ${{ github.unclosed.fragment ")
	}
	builder.WriteString("${{ github.event.issue.title }}")

	payload := builder.String()

	start := time.Now()
	found, target := parser.ContainsUntrustedContext(payload)
	elapsed := time.Since(start)

	if !found || target != "github.event.issue.title" {
		t.Errorf("expected to find target in adversarial payload, got found=%v, target=%s", found, target)
	}

	// Linear RE2 engine executes within 1 second even with race instrumentation overhead
	if elapsed > 1*time.Second {
		t.Errorf("ReDoS latency detected: evaluation took %v", elapsed)
	}
}

func TestExtractExpressions_Multiple(t *testing.T) {
	script := `
echo "${{ github.sha }}"
python -c 'print("${{ github.actor }}")'
echo "${{ secrets.TOKEN }}"
`
	exprs := parser.ExtractExpressions(script)
	if len(exprs) != 3 {
		t.Fatalf("expected 3 extracted expressions, got %d: %+v", len(exprs), exprs)
	}

	expected := []string{"github.sha", "github.actor", "secrets.TOKEN"}
	for i, exp := range expected {
		if exprs[i] != exp {
			t.Errorf("extracted expression at index %d: expected %s, got %s", i, exp, exprs[i])
		}
	}
}
