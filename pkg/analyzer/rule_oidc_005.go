package analyzer

import (
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// RuleOIDC005MultiCloudScope detects multiple distinct cloud providers authenticated in a single job.
type RuleOIDC005MultiCloudScope struct{}

func (r *RuleOIDC005MultiCloudScope) ID() string {
	return "OIDC-005"
}

func (r *RuleOIDC005MultiCloudScope) Name() string {
	return "Multi-Cloud Ambiguity or Unrestricted Target Scope"
}

func (r *RuleOIDC005MultiCloudScope) DefaultSeverity() Severity {
	return SeverityMedium
}

func (r *RuleOIDC005MultiCloudScope) Check(wf *parser.Workflow) []Finding {
	var findings []Finding
	if wf == nil {
		return findings
	}

	for jobName, job := range wf.Jobs {
		if !IsJobOIDCPrivileged(wf, jobName) {
			continue
		}

		providersFound := make(map[CloudProvider]int)
		for _, step := range job.Steps {
			if match, ok := MatchCloudAction(step); ok {
				providersFound[match.Provider]++
			}
		}

		if len(providersFound) > 1 {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				Title:        fmt.Sprintf("Multiple Cloud Providers Authenticated in Single Job '%s'", jobName),
				Category:     "Information Disclosure",
				CWE:          "CWE-200",
				Severity:     r.DefaultSeverity(),
				WorkflowPath: wf.Path,
				JobName:      jobName,
				Description:  fmt.Sprintf("Job '%s' authenticates against multiple cloud providers simultaneously. A vulnerability in one step exposes blast radius across multiple cloud environments.", jobName),
				Remediation:  "Segment cloud authentication into dedicated, isolated jobs following the principle of least privilege.",
			})
		}

	}

	return findings
}
