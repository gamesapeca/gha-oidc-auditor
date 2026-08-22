package analyzer

import (
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC007SelfHosted flags OIDC token issuance occurring inside non-ephemeral self-hosted runners.
type RuleOIDC007SelfHosted struct{}

func (r *RuleOIDC007SelfHosted) ID() string {
	return "OIDC-007"
}

func (r *RuleOIDC007SelfHosted) Name() string {
	return "Self-Hosted Runner in OIDC Privileged Job"
}

func (r *RuleOIDC007SelfHosted) DefaultSeverity() Severity {
	return SeverityHigh
}

func (r *RuleOIDC007SelfHosted) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	for jobName, job := range wf.Jobs {
		if !IsJobOIDCPrivileged(wf, jobName) {
			continue
		}

		if job.IsSelfHosted() {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				Title:        fmt.Sprintf("Self-Hosted Runner Used in OIDC Privileged Job '%s'", jobName),
				Severity:     r.DefaultSeverity(),
				WorkflowPath: wf.Path,
				JobName:      jobName,
				Description:  fmt.Sprintf("Job '%s' requests 'id-token: write' while running on a self-hosted runner. Non-ephemeral runner persistence allows subsequent unprivileged or fork jobs to access residual OIDC sessions, socket files, or credentials left in the filesystem.", jobName),
				Remediation:  "Run OIDC deployment jobs strictly on ephemeral GitHub-hosted runners (e.g. 'runs-on: ubuntu-latest') or strictly ephemeral container runners (Actions Runner Controller).",
			})
		}
	}

	return findings
}
