package analyzer

import (
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC004ContextInjection detects untrusted context interpolation inside 'run:' steps within OIDC-privileged jobs.
type RuleOIDC004ContextInjection struct{}

func (r *RuleOIDC004ContextInjection) ID() string {
	return "OIDC-004"
}

func (r *RuleOIDC004ContextInjection) Name() string {
	return "Untrusted Context Interpolation in OIDC Privileged Step"
}

func (r *RuleOIDC004ContextInjection) DefaultSeverity() Severity {
	return SeverityCritical
}

func (r *RuleOIDC004ContextInjection) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	for jobName, job := range wf.Jobs {
		if !IsJobOIDCPrivileged(wf, jobName) {
			continue
		}

		for idx, step := range job.Steps {
			if step.Run != "" {
				if hasVulnerableContext, contextVar := parser.ContainsUntrustedContext(step.Run); hasVulnerableContext {
					findings = append(findings, Finding{
						RuleID:       r.ID(),
						Title:        fmt.Sprintf("Context Injection via '%s' in OIDC Job '%s'", contextVar, jobName),
						Severity:     r.DefaultSeverity(),
						WorkflowPath: wf.Path,
						JobName:      jobName,
						StepIndex:    idx + 1,
						Description:  fmt.Sprintf("Step #%d interpolates untrusted context variable '%s' directly into a shell command in an OIDC-privileged job. Attackers can achieve RCE and exfiltrate runner OIDC credentials.", idx+1, contextVar),
						Remediation:  "Do not interpolate ${{ }} directly into shell script bodies. Pass context values safely via environment variables in 'env:'.",
					})
				}
			}
		}
	}

	return findings
}
