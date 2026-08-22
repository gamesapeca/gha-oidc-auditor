package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

var (
	gitShaRegex    = regexp.MustCompile(`@[0-9a-fA-F]{40}$`)
	dockerShaRegex = regexp.MustCompile(`^docker://.+@sha256:[0-9a-fA-F]{64}$`)
)

func isSafeActionRef(uses string) bool {
	uses = strings.TrimSpace(uses)
	if uses == "" {
		return true
	}
	// Local repository actions
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, ".\\") {
		return true
	}
	// Docker actions pinned by immutable sha256 digest
	if strings.HasPrefix(uses, "docker://") {
		return dockerShaRegex.MatchString(uses)
	}
	// Git actions pinned by immutable 40-character commit SHA
	return gitShaRegex.MatchString(uses)
}

// RuleOIDC003ActionPinning checks whether actions in OIDC-privileged jobs use mutable tags (@vX, @main).
type RuleOIDC003ActionPinning struct{}

func (r *RuleOIDC003ActionPinning) ID() string {
	return "OIDC-003"
}

func (r *RuleOIDC003ActionPinning) Name() string {
	return "Mutable Action Reference in OIDC Privileged Job"
}

func (r *RuleOIDC003ActionPinning) DefaultSeverity() Severity {
	return SeverityHigh
}

func (r *RuleOIDC003ActionPinning) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	for jobName, job := range wf.Jobs {
		if !IsJobOIDCPrivileged(wf, jobName) {
			continue
		}

		if job.Uses != "" && !isSafeActionRef(job.Uses) {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				Title:        fmt.Sprintf("Mutable Reusable Workflow Reference in Job '%s'", jobName),
				Severity:     r.DefaultSeverity(),
				WorkflowPath: wf.Path,
				JobName:      jobName,
				Description:  fmt.Sprintf("Job '%s' calls reusable workflow '%s' with a mutable tag in an OIDC-privileged context.", jobName, job.Uses),
				Remediation:  "Pin the reusable workflow version using a full immutable 40-character commit SHA.",
			})
		}

		for idx, step := range job.Steps {
			if step.Uses != "" && !isSafeActionRef(step.Uses) {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					Title:        fmt.Sprintf("Unpinned Action '%s' in OIDC Job '%s'", step.Uses, jobName),
					Severity:     r.DefaultSeverity(),
					WorkflowPath: wf.Path,
					JobName:      jobName,
					StepIndex:    idx + 1,
					Description:  fmt.Sprintf("Action '%s' uses a mutable tag in privileged job '%s'. Upstream tag hijacking allows attackers to compromise runner memory and exfiltrate OIDC tokens.", step.Uses, jobName),
					Remediation:  "Pin all actions to immutable 40-character commit SHAs instead of release tags.",
				})
			}
		}
	}

	return findings
}
