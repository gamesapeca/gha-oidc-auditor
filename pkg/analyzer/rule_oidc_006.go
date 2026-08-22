package analyzer

import (
	"fmt"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC006TriggerWorkflowRun detects workflow_run triggers without branch filters in OIDC workflows.
type RuleOIDC006TriggerWorkflowRun struct{}

func (r *RuleOIDC006TriggerWorkflowRun) ID() string {
	return "OIDC-006"
}

func (r *RuleOIDC006TriggerWorkflowRun) Name() string {
	return "Unsafe workflow_run Trigger with OIDC Token Minting"
}

func (r *RuleOIDC006TriggerWorkflowRun) DefaultSeverity() Severity {
	return SeverityCritical
}

func (r *RuleOIDC006TriggerWorkflowRun) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	hasWorkflowRun := false
	for _, event := range wf.On.Events {
		if event == "workflow_run" {
			hasWorkflowRun = true
			break
		}
	}

	if !hasWorkflowRun {
		return findings
	}

	hasBranchRestriction := false
	if wf.On.Conditions != nil {
		if wrCond, ok := wf.On.Conditions["workflow_run"].(map[string]interface{}); ok {
			// Check list format: branches: [main]
			if branches, ok := wrCond["branches"].([]interface{}); ok && len(branches) > 0 {
				hasBranchRestriction = true
			}
			// Check scalar format: branches: "main"
			if branchStr, ok := wrCond["branches"].(string); ok && strings.TrimSpace(branchStr) != "" {
				hasBranchRestriction = true
			}
			// Check list format: branches-ignore: [feat/*]
			if branchesIgnore, ok := wrCond["branches-ignore"].([]interface{}); ok && len(branchesIgnore) > 0 {
				hasBranchRestriction = true
			}
			// Check scalar format: branches-ignore: "feat/*"
			if branchIgnoreStr, ok := wrCond["branches-ignore"].(string); ok && strings.TrimSpace(branchIgnoreStr) != "" {
				hasBranchRestriction = true
			}
		}
	}

	if hasBranchRestriction {
		return findings
	}

	for jobName := range wf.Jobs {
		if IsJobOIDCPrivileged(wf, jobName) {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				Title:        fmt.Sprintf("workflow_run without Branch Filter in OIDC Workflow (Job '%s')", jobName),
				Category:     "Artifact Integrity",
				CWE:          "CWE-494",
				Severity:     r.DefaultSeverity(),
				WorkflowPath: wf.Path,
				JobName:      jobName,
				Description:  fmt.Sprintf("Workflow triggers on 'workflow_run' without branch filtering while job '%s' holds 'id-token: write' permissions. Untrusted branch runs can trigger privileged execution.", jobName),
				Remediation:  "Add 'branches: [main]' under 'workflow_run' and assert 'github.event.workflow_run.head_branch == main' prior to performing cloud actions.",
			})
		}

	}

	return findings
}
