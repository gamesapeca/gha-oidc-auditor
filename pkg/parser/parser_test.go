package parser

import (
	"testing"
)

func TestParseWorkflow_ScalarTrigger(t *testing.T) {
	yamlContent := `
name: Scalar CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "building"
`
	wf, err := ParseWorkflowBytes([]byte(yamlContent), "scalar.yml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(wf.On.Events) != 1 || wf.On.Events[0] != "push" {
		t.Fatalf("expected event ['push'], got: %v", wf.On.Events)
	}
	if _, ok := wf.Jobs["build"]; !ok {
		t.Fatalf("job 'build' not found in AST")
	}
}

func TestParseWorkflow_SequenceTrigger(t *testing.T) {
	yamlContent := `
name: Sequence CI
on: [push, pull_request_target]
jobs:
  test:
    steps:
      - run: go test ./...
`
	wf, err := ParseWorkflowBytes([]byte(yamlContent), "seq.yml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(wf.On.Events) != 2 {
		t.Fatalf("expected 2 events, got: %d", len(wf.On.Events))
	}
	if wf.On.Events[0] != "push" || wf.On.Events[1] != "pull_request_target" {
		t.Fatalf("incorrect events parsed: %v", wf.On.Events)
	}
}

func TestParseWorkflow_MappingTrigger(t *testing.T) {
	yamlContent := `
name: Mapping CI
on:
  push:
    branches: [main, release/*]
  pull_request:
    types: [opened, synchronize]
jobs:
  deploy:
    steps:
      - uses: actions/checkout@v4
`
	wf, err := ParseWorkflowBytes([]byte(yamlContent), "map.yml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(wf.On.Events) != 2 {
		t.Fatalf("expected 2 events in mapping, got: %d", len(wf.On.Events))
	}
	if wf.On.Conditions == nil || len(wf.On.Conditions) != 2 {
		t.Fatalf("trigger sub-conditions not captured properly")
	}
}

func TestParseWorkflow_Permissions(t *testing.T) {
	yamlStringPerms := `
name: Write All CI
permissions: write-all
jobs:
  job1:
    steps:
      - run: echo 1
  job2:
    permissions:
      id-token: write
      contents: read
    steps:
      - run: echo 2
  job3:
    permissions: read-all
    steps:
      - run: echo 3
`
	wf, err := ParseWorkflowBytes([]byte(yamlStringPerms), "perms.yml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if wf.PermissionsAll != "write-all" {
		t.Errorf("expected PermissionsAll 'write-all', got: '%s'", wf.PermissionsAll)
	}

	job2 := wf.Jobs["job2"]
	if job2.Permissions["id-token"] != "write" || job2.Permissions["contents"] != "read" {
		t.Errorf("job2 permissions incorrect: %v", job2.Permissions)
	}

	job3 := wf.Jobs["job3"]
	if job3.PermissionsAll != "read-all" {
		t.Errorf("job3 PermissionsAll incorrect: '%s'", job3.PermissionsAll)
	}
}

func TestParseWorkflow_HeterogeneousStepWith(t *testing.T) {
	yamlContent := `
name: Complex Step With
jobs:
  deploy:
    steps:
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/DeployRole
          aws-region: us-east-1
          duration-seconds: 3600
          role-skip-session-tagging: true
          multiline-param: |
            line 1
            line 2
`
	wf, err := ParseWorkflowBytes([]byte(yamlContent), "step_with.yml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	job := wf.Jobs["deploy"]
	if len(job.Steps) != 1 {
		t.Fatalf("expected 1 step, got: %d", len(job.Steps))
	}

	step := job.Steps[0]
	if step.GetWithString("role-to-assume") != "arn:aws:iam::123456789012:role/DeployRole" {
		t.Errorf("failed to extract role-to-assume: %s", step.GetWithString("role-to-assume"))
	}
	if step.GetWithString("duration-seconds") != "3600" {
		t.Errorf("failed to extract duration-seconds integer as string: %s", step.GetWithString("duration-seconds"))
	}
	if step.GetWithString("role-skip-session-tagging") != "true" {
		t.Errorf("failed to extract boolean as string: %s", step.GetWithString("role-skip-session-tagging"))
	}
}

func TestParseWorkflow_EnvironmentExtraction(t *testing.T) {
	yamlContent := `
name: Environment Test
jobs:
  simple_env:
    environment: production
    steps:
      - run: echo prod
  object_env:
    environment:
      name: staging
      url: https://staging.example.com
    steps:
      - run: echo stage
`
	wf, err := ParseWorkflowBytes([]byte(yamlContent), "env.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	simpleJob := wf.Jobs["simple_env"]
	if simpleJob.GetEnvironmentName() != "production" {
		t.Errorf("expected environment 'production', got: '%s'", simpleJob.GetEnvironmentName())
	}

	objJob := wf.Jobs["object_env"]
	if objJob.GetEnvironmentName() != "staging" {
		t.Errorf("expected environment 'staging', got: '%s'", objJob.GetEnvironmentName())
	}
}

func TestExpressionEval_ContainsUntrustedContext(t *testing.T) {
	tests := []struct {
		name       string
		runBlock   string
		wantFound  bool
		wantTarget string
	}{
		{
			name:       "Single line issue title",
			runBlock:   `echo "Issue: ${{ github.event.issue.title }}"`,
			wantFound:  true,
			wantTarget: "github.event.issue.title",
		},
		{
			name: "Multiline injection in python script",
			runBlock: `python -c '
import sys
title = "${{ github.event.pull_request.title }}"
print(title)
'`,
			wantFound:  true,
			wantTarget: "github.event.pull_request.title",
		},
		{
			name:       "Head ref injection",
			runBlock:   `git checkout ${{ github.head_ref }}`,
			wantFound:  true,
			wantTarget: "github.head_ref",
		},
		{
			name:       "Safe expression with secret",
			runBlock:   `echo "Deploying with ${{ secrets.AWS_ROLE_ARN }}"`,
			wantFound:  false,
			wantTarget: "",
		},
		{
			name:       "Empty run block",
			runBlock:   "",
			wantFound:  false,
			wantTarget: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, target := ContainsUntrustedContext(tt.runBlock)
			if found != tt.wantFound {
				t.Errorf("ContainsUntrustedContext() found = %v, want %v", found, tt.wantFound)
			}
			if target != tt.wantTarget {
				t.Errorf("ContainsUntrustedContext() target = %v, want %v", target, tt.wantTarget)
			}
		})
	}
}
