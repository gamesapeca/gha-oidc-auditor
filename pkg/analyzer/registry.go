package analyzer

import (
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// Rule defines the interface that all audit check implementations must satisfy.
type Rule interface {
	ID() string
	Name() string
	DefaultSeverity() Severity
	Check(wf *parser.Workflow) []Finding
}

// Registry manages the set of active audit rules.
type Registry struct {
	rules []Rule
}

// NewRegistry creates a new rule registry with the given rules.
func NewRegistry(rules ...Rule) *Registry {
	return &Registry{rules: rules}
}

// Register adds a rule to the active registry.
func (r *Registry) Register(rule Rule) {
	r.rules = append(r.rules, rule)
}

// RunAll executes all registered audit rules against a parsed workflow AST.
func (r *Registry) RunAll(wf *parser.Workflow) []Finding {
	var findings []Finding
	for _, rule := range r.rules {
		findings = append(findings, rule.Check(wf)...)
	}
	return findings
}

// NewDefaultRegistry instantiates a registry preconfigured with all default official rules.
func NewDefaultRegistry() *Registry {
	return NewRegistry(
		&RuleOIDC001Global{},
		&RuleOIDC002TriggerPRT{},
		&RuleOIDC003ActionPinning{},
		&RuleOIDC004ContextInjection{},
		&RuleOIDC005MultiCloudScope{},
		&RuleOIDC006TriggerWorkflowRun{},
		&RuleOIDC007SelfHosted{},
	)
}
