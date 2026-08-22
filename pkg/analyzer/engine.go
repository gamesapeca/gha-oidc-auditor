package analyzer

import (
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

// AnalyzeWorkflows processes a collection of workflows and compiles a unified AuditReport.
func (e *Engine) AnalyzeWorkflows(targetName string, wfs []*parser.Workflow) *AuditReport {
	report := NewAuditReport(targetName)
	report.WorkflowsNum = len(wfs)

	for _, wf := range wfs {
		findings := e.AnalyzeWorkflow(wf)
		for _, f := range findings {
			report.AddFinding(f)
		}
	}

	return report
}
