package analyzer

import (
	"context"
	"runtime"
	"sync"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// Engine coordinates the execution of security audit rules against parsed workflows.
type Engine struct {
	registry *Registry
}

// NewEngine initializes an analysis engine with a custom rule registry.
func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

// NewDefaultEngine initializes an analysis engine with the standard rule set.
func NewDefaultEngine() *Engine {
	return &Engine{registry: NewDefaultRegistry()}
}

// AnalyzeWorkflow audits a single workflow and returns all detected findings.
func (e *Engine) AnalyzeWorkflow(wf *parser.Workflow) []Finding {
	if wf == nil {
		return nil
	}
	return e.registry.RunAll(wf)
}

type workflowResult struct {
	findings []Finding
	chains   []ExploitChain
}

// AnalyzeWorkflowsConcurrently processes a collection of workflows in parallel using a bounded worker pool.
// Results are joined in original index order to guarantee deterministic and reproducible output.
func (e *Engine) AnalyzeWorkflowsConcurrently(ctx context.Context, targetName string, wfs []*parser.Workflow, concurrency int) *AuditReport {
	report := NewAuditReport(targetName)
	report.WorkflowsNum = len(wfs)

	if len(wfs) == 0 {
		return report
	}

	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	if concurrency > len(wfs) {
		concurrency = len(wfs)
	}

	results := make([]workflowResult, len(wfs))
	jobs := make(chan int, len(wfs))

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case idx, ok := <-jobs:
					if !ok {
						return
					}
					wf := wfs[idx]
					if wf != nil {
						findings := e.AnalyzeWorkflow(wf)
						chains := DetectExploitChains(wf)
						results[idx] = workflowResult{
							findings: findings,
							chains:   chains,
						}
					}
				}
			}
		}()
	}

	for i := 0; i < len(wfs); i++ {
		jobs <- i
	}
	close(jobs)

	wg.Wait()

	for _, res := range results {
		for _, f := range res.findings {
			report.AddFinding(f)
		}
		for _, c := range res.chains {
			report.AddExploitChain(c)
		}
	}

	return report
}

// AnalyzeWorkflows processes a collection of workflows and compiles a unified AuditReport.
func (e *Engine) AnalyzeWorkflows(targetName string, wfs []*parser.Workflow) *AuditReport {
	return e.AnalyzeWorkflowsConcurrently(context.Background(), targetName, wfs, runtime.NumCPU())
}
