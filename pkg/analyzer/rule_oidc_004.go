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
					isExternal := parser.IsExternalAttackerPayload(contextVar)
					var severity Severity
					var title string
					var desc string

					if isExternal {
						severity = SeverityCritical
						title = fmt.Sprintf("CRITICAL: Context Injection via '%s' in OIDC Job '%s'", contextVar, jobName)
						desc = fmt.Sprintf("Step #%d interpolates externally-controllable context variable '%s' directly into a shell command in an OIDC-privileged job. Attackers can achieve Remote Code Execution and exfiltrate runner OIDC credentials.", idx+1, contextVar)
					} else {
						severity = SeverityMedium
						title = fmt.Sprintf("Input Parameter Interpolation via '%s' in OIDC Job '%s'", contextVar, jobName)
						desc = fmt.Sprintf("Step #%d interpolates input parameter '%s' directly into a shell command in an OIDC-privileged job. Direct interpolation into shell script bodies is an antipattern vulnerable to command injection if callers pass unsanitized arguments.", idx+1, contextVar)
					}

					findings = append(findings, Finding{
						RuleID:       r.ID(),
						Title:        title,
						Severity:     severity,
						WorkflowPath: wf.Path,
						JobName:      jobName,
						StepIndex:    idx + 1,
						Description:  desc,
						Remediation:  "Do not interpolate ${{ }} directly into shell script bodies. Pass context and input values safely via environment variables in 'env:'.",
					})
				}
			}
		}
	}

	return findings
}
