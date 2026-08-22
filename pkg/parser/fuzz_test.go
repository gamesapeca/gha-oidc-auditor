package parser_test

import (
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// FuzzParseWorkflow tests the YAML AST parser against arbitrary malformed/adversarial byte streams
func FuzzParseWorkflow(f *testing.F) {
	// Seed corpus with valid and invalid workflow fragments
	seeds := [][]byte{
		[]byte("name: CI\non: push\njobs:\n  build:\n    steps:\n      - run: echo 1"),
		[]byte("on: [push, pull_request]\npermissions: write-all\njobs: {}"),
		[]byte("on: { workflow_run: { branches: [main] } }\njobs:\n  deploy:\n    permissions:\n      id-token: write"),
		[]byte(""),
		[]byte("::: invalid yaml :::"),
		[]byte("null"),
		[]byte("[]"),
		[]byte("on: 12345"),
		[]byte("jobs:\n  invalid:\n    steps:\n      - with:\n          key: [nested, { a: 1 }]"),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant: ParseWorkflowBytes must NEVER panic on any input
		wf, err := parser.ParseWorkflowBytes(data, "fuzz.yml")
		if err != nil {
			return
		}
		if wf == nil {
			t.Fatalf("returned nil workflow without error")
		}

		// Invariant: Accessing fields on parsed AST must never panic
		_ = wf.Name
		_ = wf.PermissionsAll
		_ = len(wf.On.Events)

		for jobName, job := range wf.Jobs {
			_ = jobName
			_ = job.GetEnvironmentName()
			for _, step := range job.Steps {
				_ = step.GetWithString("key")
				_ = step.GetEnvString("ENV_KEY")
				if step.Run != "" {
					_, _ = parser.ContainsUntrustedContext(step.Run)
					_ = parser.ExtractExpressions(step.Run)
				}
			}
		}
	})
}

// FuzzContainsUntrustedContext tests expression extractor against arbitrary strings
func FuzzContainsUntrustedContext(f *testing.F) {
	seeds := []string{
		`echo "${{ github.event.issue.title }}"`,
		`run: ${{ GITHUB.EVENT.PULL_REQUEST.HEAD.REF }}`,
		`${{ format('{0}', github.event.comment.body) }}`,
		`${{ secrets.AWS_KEY }}`,
		`${{ ${{ ${{ unclosed`,
		"",
		strings.Repeat("${{", 1000),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Invariant: ContainsUntrustedContext and ExtractExpressions must NEVER panic
		_, _ = parser.ContainsUntrustedContext(input)
		_ = parser.ExtractExpressions(input)
	})
}
