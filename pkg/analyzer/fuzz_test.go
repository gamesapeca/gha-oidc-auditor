package analyzer_test

import (
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/remediation"
)

// FuzzAnalyzerEngine tests the analyzer engine and policy synthesizers against arbitrary inputs
func FuzzAnalyzerEngine(f *testing.F) {
	seeds := [][]byte{
		[]byte("name: Test\non: pull_request_target\njobs:\n  j:\n    permissions:\n      id-token: write\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo ${{ github.event.issue.title }}"),
		[]byte("name: AWS\non: push\npermissions: write-all\njobs:\n  deploy:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::123:role/R"),
		[]byte("name: Multi\non: [workflow_run]\njobs:\n  multi:\n    permissions:\n      id-token: write\n    steps:\n      - uses: aws-actions/configure-aws-credentials@b4ffde65f46336ab88eb53be808477a3936bae11\n      - uses: google-github-actions/auth@b4ffde65f46336ab88eb53be808477a3936bae11"),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	engine := analyzer.NewDefaultEngine()

	f.Fuzz(func(t *testing.T, data []byte) {
		wf, err := parser.ParseWorkflowBytes(data, "fuzz_target.yml")
		if err != nil {
			return
		}

		// Invariant: AnalyzeWorkflow must never panic on any valid or pseudo-valid AST
		findings := engine.AnalyzeWorkflow(wf)
		_ = findings

		// Invariant: Cloud Trust Policy synthesis must never panic
		for _, job := range wf.Jobs {
			_, _ = remediation.GenerateAWSTrustPolicy("123456789012", "owner", "repo", wf, &job)
			_, _ = remediation.GenerateGCPWorkloadIdentityAssertion("123456789012", "pool", "prov", "owner", "repo", wf, &job)
			_, _ = remediation.GenerateAzureFederatedCredential("owner", "repo", wf, &job)
		}
	})
}
