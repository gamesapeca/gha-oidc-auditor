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
			if job.GetEnvironmentName() != "" {
				// Job is protected by an environment approval gate
				continue
			}

			hasUntrustedCheckout, refVar := job.ChecksOutUntrustedForkRef()
			hasGuard, guardReason := job.HasActorOrRepoGuard()

			if hasUntrustedCheckout {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("CRITICAL: pull_request_target with Untrusted Code Checkout in OIDC Job '%s'", jobName),
					Category:     "Privilege Escalation",
					CWE:          "CWE-269",
					Severity:     SeverityCritical,
					WorkflowPath: wf.Path,
					JobName:      jobName,
					Description:  fmt.Sprintf("Job '%s' triggers on 'pull_request_target', holds 'id-token: write' permissions, and checks out untrusted fork code via '%s'. Attackers can submit malicious pull requests to achieve Remote Code Execution with base repository OIDC token minting privileges.", jobName, refVar),
					Remediation:  "Never checkout untrusted PR head refs in 'pull_request_target' workflows with write/OIDC permissions. Use 'on: pull_request' or gate with protected environments.",
				})
			} else if !hasGuard {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("Ungated pull_request_target with OIDC Token in Job '%s'", jobName),
					Category:     "Privilege Escalation",
					CWE:          "CWE-269",
					Severity:     SeverityHigh,
					WorkflowPath: wf.Path,
					JobName:      jobName,
					Description:  fmt.Sprintf("Job '%s' has 'id-token: write' permissions and triggers via 'pull_request_target' without environment approval gates or actor/repository conditions in 'if:'. Untrusted fork PRs can trigger privileged CI steps.", jobName),
					Remediation:  "Isolate token issuance into an environment-gated job requiring maintainer review, or add strict actor/repository guard conditions in 'if:'.",
				})
			} else {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("Guarded pull_request_target with OIDC Token in Job '%s'", jobName),
					Category:     "Privilege Escalation",
					CWE:          "CWE-269",
					Severity:     SeverityMedium,
					WorkflowPath: wf.Path,
					JobName:      jobName,
					Description:  fmt.Sprintf("Job '%s' triggers via 'pull_request_target' and holds 'id-token: write', but execution is guarded by '%s' and uses base checkout. Architectural risk remains if guard conditions change or trusted accounts are compromised.", jobName, guardReason),
					Remediation:  "Migrate to environment approval gates for cloud deployment jobs rather than software if: conditions.",
				})
			}

		}
	}

	return findings
}
