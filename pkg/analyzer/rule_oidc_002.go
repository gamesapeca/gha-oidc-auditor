package analyzer

import (
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC002TriggerPRT detects pull_request_target triggers paired with OIDC token minting without environment gates.
type RuleOIDC002TriggerPRT struct{}

func (r *RuleOIDC002TriggerPRT) ID() string {
	return "OIDC-002"
}

func (r *RuleOIDC002TriggerPRT) Name() string {
	return "Unsafe pull_request_target Trigger with OIDC Token Minting"
}

func (r *RuleOIDC002TriggerPRT) DefaultSeverity() Severity {
	return SeverityCritical
}

func (r *RuleOIDC002TriggerPRT) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	hasPRT := false
	for _, event := range wf.On.Events {
		if event == "pull_request_target" {
			hasPRT = true
			break
		}
	}

	if !hasPRT {
		return findings
	}

	for jobName, job := range wf.Jobs {
		if IsJobOIDCPrivileged(wf, jobName) {
			if job.GetEnvironmentName() == "" {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("pull_request_target with Ungated OIDC Token in Job '%s'", jobName),
					Severity:     r.DefaultSeverity(),
					WorkflowPath: wf.Path,
					JobName:      jobName,
					Description:  fmt.Sprintf("Job '%s' has 'id-token: write' permissions and triggers via 'pull_request_target' without an environment approval gate. Untrusted pull requests from forks can execute arbitrary code with base repository OIDC privileges.", jobName),
					Remediation:  "Use standard 'on: pull_request' for untrusted fork validations, or isolate token issuance into an environment-gated job requiring mandatory maintainer review.",
				})
			}
		}
	}

	return findings
}
