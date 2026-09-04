package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
)

// SARIFReport represents the root of a SARIF v2.1.0 document.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun describes an individual run of an analysis tool.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool that generated the run.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the primary analysis engine.
type SARIFDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion"`
	InformationURI  string      `json:"informationUri"`
	Rules           []SARIFRule `json:"rules"`
}

// SARIFRule represents metadata for an individual analysis rule.
type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     SARIFMultiformatText   `json:"shortDescription"`
	FullDescription      SARIFMultiformatText   `json:"fullDescription,omitempty"`
	HelpURI              string                 `json:"helpUri,omitempty"`
	DefaultConfiguration SARIFConfiguration     `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
}

// SARIFConfiguration defines rule configuration defaults.
type SARIFConfiguration struct {
	Level string `json:"level"`
}

// SARIFMultiformatText provides textual content.
type SARIFMultiformatText struct {
	Text string `json:"text"`
}

// SARIFResult represents a single finding emitted by the tool.
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    SARIFMultiformatText   `json:"message"`
	Locations  []SARIFLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFLocation identifies the physical location of an issue.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation identifies file path and line numbers.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation represents relative file URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion describes line and column coordinates.
type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// severityToSARIFLevel maps analyzer.Severity to SARIF standard levels (error, warning, note).
func severityToSARIFLevel(sev analyzer.Severity) string {
	switch sev {
	case analyzer.SeverityCritical, analyzer.SeverityHigh:
		return "error"
	case analyzer.SeverityMedium:
		return "warning"
	case analyzer.SeverityLow, analyzer.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// ExportSARIF converts an analyzer.AuditReport into an official OASIS SARIF v2.1.0 JSON string.
func ExportSARIF(auditReport *analyzer.AuditReport) (string, error) {
	if auditReport == nil {
		auditReport = analyzer.NewAuditReport("")
	}

	ruleMap := make(map[string]int)
	rules := make([]SARIFRule, 0)
	results := make([]SARIFResult, 0)

	getOrRegisterRule := func(ruleID, title, category, cwe, remediation string, sev analyzer.Severity) int {
		if idx, exists := ruleMap[ruleID]; exists {
			return idx
		}
		idx := len(rules)
		ruleMap[ruleID] = idx

		rule := SARIFRule{
			ID:   ruleID,
			Name: strings.ReplaceAll(title, " ", ""),
			ShortDescription: SARIFMultiformatText{
				Text: title,
			},
			FullDescription: SARIFMultiformatText{
				Text: fmt.Sprintf("%s. Remediation: %s", title, remediation),
			},
			HelpURI: fmt.Sprintf("https://github.com/gamesapeca/gha-oidc-auditor#rule-%s", strings.ToLower(ruleID)),
			DefaultConfiguration: SARIFConfiguration{
				Level: severityToSARIFLevel(sev),
			},
			Properties: map[string]interface{}{
				"category":  category,
				"cwe":       cwe,
				"precision": "high",
			},
		}
		rules = append(rules, rule)
		return idx
	}

	for _, f := range auditReport.Findings {
		ruleIdx := getOrRegisterRule(f.RuleID, f.Title, f.Category, f.CWE, f.Remediation, f.Severity)

		startLine := f.LineNumber
		if startLine <= 0 {
			startLine = 1
		}

		res := SARIFResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIdx,
			Level:     severityToSARIFLevel(f.Severity),
			Message: SARIFMultiformatText{
				Text: f.Description,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: f.WorkflowPath,
						},
						Region: &SARIFRegion{
							StartLine:   startLine,
							StartColumn: 1,
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"jobName":        f.JobName,
				"remediation":    f.Remediation,
				"severity":       string(f.Severity),
				"cloud_provider": string(f.Provider),
			},
		}
		results = append(results, res)
	}

	for _, chain := range auditReport.ExploitChains {
		chainRuleID := chain.ID
		chainTitle := fmt.Sprintf("Exploitable Attack Chain: %s", chain.Title)
		ruleIdx := getOrRegisterRule(chainRuleID, chainTitle, chain.Category, chain.CWE, chain.IngressVector, analyzer.SeverityCritical)

		res := SARIFResult{
			RuleID:    chainRuleID,
			RuleIndex: ruleIdx,
			Level:     "error",
			Message: SARIFMultiformatText{
				Text: fmt.Sprintf("Exploitable vector: %s on trigger %s (Target: %s)", chain.IngressVector, chain.TriggerEvent, chain.TargetCloud),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: chain.WorkflowPath,
						},
						Region: &SARIFRegion{
							StartLine:   1,
							StartColumn: 1,
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"jobName":       chain.JobName,
				"triggerEvent":  chain.TriggerEvent,
				"targetCloud":   string(chain.TargetCloud),
				"targetRoleARN": chain.TargetRoleARN,
				"ingressVector": chain.IngressVector,
			},
		}
		results = append(results, res)
	}

	sarifDoc := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            "gha-oidc-auditor",
						SemanticVersion: "1.1.0",
						InformationURI:  "https://github.com/gamesapeca/gha-oidc-auditor",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}

	bytes, err := json.MarshalIndent(sarifDoc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	return string(bytes), nil
}
