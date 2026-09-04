package analyzer_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

func TestEngine_ConcurrentAnalysisDeterminism(t *testing.T) {
	engine := analyzer.NewDefaultEngine()

	// Build a synthetic batch of diverse workflows
	var wfs []*parser.Workflow
	for i := 0; i < 20; i++ {
		var content string
		if i%2 == 0 {
			content = fmt.Sprintf(`
name: VulnWorkflow_%d
on: pull_request_target
jobs:
  build:
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          echo "Title: ${{ github.event.issue.title }}"
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/DeployRole
`, i)
		} else {
			content = fmt.Sprintf(`
name: SafeWorkflow_%d
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: echo "Deterministic test %d"
`, i, i)
		}

		wf, err := parser.ParseWorkflowBytes([]byte(content), fmt.Sprintf(".github/workflows/wf_%d.yml", i))
		if err != nil {
			t.Fatalf("Failed to parse fixture %d: %v", i, err)
		}
		wfs = append(wfs, wf)
	}

	// Sequential run (1 worker)
	reportSeq := engine.AnalyzeWorkflowsConcurrently(context.Background(), "test-target", wfs, 1)

	// Parallel run (8 workers)
	reportPar := engine.AnalyzeWorkflowsConcurrently(context.Background(), "test-target", wfs, 8)

	// Verify counts match
	if len(reportSeq.Findings) != len(reportPar.Findings) {
		t.Fatalf("Finding count mismatch: seq=%d, par=%d", len(reportSeq.Findings), len(reportPar.Findings))
	}
	if len(reportSeq.ExploitChains) != len(reportPar.ExploitChains) {
		t.Fatalf("ExploitChain count mismatch: seq=%d, par=%d", len(reportSeq.ExploitChains), len(reportPar.ExploitChains))
	}

	// Verify exact finding order determinism
	for i := range reportSeq.Findings {
		fSeq := reportSeq.Findings[i]
		fPar := reportPar.Findings[i]

		if fSeq.RuleID != fPar.RuleID || fSeq.WorkflowPath != fPar.WorkflowPath || fSeq.JobName != fPar.JobName {
			t.Errorf("Finding [%d] differs between runs: seq=(%s, %s), par=(%s, %s)",
				i, fSeq.RuleID, fSeq.WorkflowPath, fPar.RuleID, fPar.WorkflowPath)
		}
	}
}

func TestEngine_ConcurrentAnalysisContextCancellation(t *testing.T) {
	engine := analyzer.NewDefaultEngine()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	var wfs []*parser.Workflow
	for i := 0; i < 10; i++ {
		wf, _ := parser.ParseWorkflowBytes([]byte("name: T\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"), "wf.yml")
		wfs = append(wfs, wf)
	}

	done := make(chan *analyzer.AuditReport, 1)
	go func() {
		done <- engine.AnalyzeWorkflowsConcurrently(ctx, "canceled-target", wfs, 4)
	}()

	select {
	case report := <-done:
		if report == nil {
			t.Fatal("Expected non-nil report even when canceled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AnalyzeWorkflowsConcurrently did not terminate on canceled context")
	}
}
