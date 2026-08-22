package remediation

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PolicyVerificationResult contains the findings from cross-auditing a cloud provider trust policy.
type PolicyVerificationResult struct {
	Valid          bool     `json:"valid"`
	Provider       string   `json:"provider"`
	Warnings       []string `json:"warnings"`
	Recommendations []string `json:"recommendations"`
}

type awsVerifyStatement struct {
	Effect    string                            `json:"Effect"`
	Principal map[string]interface{}            `json:"Principal"`
	Action    interface{}                       `json:"Action"`
	Condition map[string]map[string]interface{} `json:"Condition,omitempty"`
}

type awsVerifyPolicyDoc struct {
	Version   string               `json:"Version"`
	Statement []awsVerifyStatement `json:"Statement"`
}

// ValidateAWSTrustPolicyJSON cross-audits an existing AWS IAM AssumeRoleWithWebIdentity trust policy JSON document.
// It verifies whether the policy restricts the 'sub' claim to specific repositories/branches and flags wildcard patterns.
func ValidateAWSTrustPolicyJSON(policyJSON, expectedOrg, expectedRepo string) (*PolicyVerificationResult, error) {
	var doc awsVerifyPolicyDoc
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return nil, fmt.Errorf("invalid AWS trust policy JSON: %w", err)
	}

	result := &PolicyVerificationResult{
		Valid:    true,
		Provider: "AWS",
	}

	for idx, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		if len(stmt.Condition) == 0 {
			result.Valid = false
			result.Warnings = append(result.Warnings, fmt.Sprintf("Statement #%d has no Condition block. Anyone with an OIDC token can assume this role.", idx+1))
			continue
		}

		hasSubCondition := false
		hasAudCondition := false

		for operator, condMap := range stmt.Condition {
			for key, val := range condMap {
				normKey := strings.ToLower(key)
				valStr := fmt.Sprintf("%v", val)

				if strings.Contains(normKey, ":aud") {
					hasAudCondition = true
					if valStr != "sts.amazonaws.com" {
						result.Warnings = append(result.Warnings, fmt.Sprintf("Audience condition uses unexpected value '%s', expected 'sts.amazonaws.com'", valStr))
					}
				}

				if strings.Contains(normKey, ":sub") {
					hasSubCondition = true
					// Check for wildcard overprivilege
					if valStr == "*" || valStr == "repo:*" || strings.Contains(valStr, "/*") && !strings.Contains(valStr, ":ref:") && !strings.Contains(valStr, ":environment:") {
						result.Valid = false
						result.Warnings = append(result.Warnings, fmt.Sprintf("Statement #%d uses broad wildcard in 'sub' claim condition (%s: %s). Any repository in the organization can assume this role.", idx+1, operator, valStr))
					}

					// Check for 2026 immutable sub claims
					if !strings.Contains(valStr, "@") && !strings.Contains(valStr, "repo_id") {
						result.Recommendations = append(result.Recommendations, "Consider updating the sub claim condition to include July 2026 immutable numeric IDs (repo:org@ID/repo@ID:*) to prevent repository name-squatting risks.")
					}

					// Verify expected repo if specified
					if expectedOrg != "" && expectedRepo != "" {
						expectedPattern := fmt.Sprintf("repo:%s/%s", expectedOrg, expectedRepo)
						if !strings.Contains(valStr, expectedPattern) && !strings.Contains(valStr, fmt.Sprintf("repo:%s@", expectedOrg)) {
							result.Warnings = append(result.Warnings, fmt.Sprintf("Policy sub claim '%s' does not match expected repository '%s/%s'", valStr, expectedOrg, expectedRepo))
						}
					}
				}
			}
		}

		if !hasSubCondition {
			result.Valid = false
			result.Warnings = append(result.Warnings, fmt.Sprintf("Statement #%d lacks a 'token.actions.githubusercontent.com:sub' condition. Role is not scoped to a specific repository.", idx+1))
		}

		if !hasAudCondition {
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("Statement #%d is missing an explicit 'token.actions.githubusercontent.com:aud' check.", idx+1))
		}
	}

	return result, nil
}

type gcpWIFDoc struct {
	AttributeMapping   map[string]string `json:"attributeMapping"`
	AttributeCondition string            `json:"attributeCondition"`
	OIDC               map[string]string `json:"oidc"`
}

// ValidateGCPWIFConfigJSON cross-audits a Google Cloud Workload Identity Federation provider configuration.
func ValidateGCPWIFConfigJSON(wifJSON, expectedOrg, expectedRepo string) (*PolicyVerificationResult, error) {
	var doc gcpWIFDoc
	if err := json.Unmarshal([]byte(wifJSON), &doc); err != nil {
		return nil, fmt.Errorf("invalid GCP WIF JSON: %w", err)
	}

	result := &PolicyVerificationResult{
		Valid:    true,
		Provider: "GCP",
	}

	if doc.OIDC["issuerUri"] != "https://token.actions.githubusercontent.com" {
		result.Warnings = append(result.Warnings, fmt.Sprintf("OIDC issuerUri is '%s', expected 'https://token.actions.githubusercontent.com'", doc.OIDC["issuerUri"]))
	}

	if _, ok := doc.AttributeMapping["attribute.repository"]; !ok {
		result.Valid = false
		result.Warnings = append(result.Warnings, "attributeMapping lacks 'attribute.repository' mapping from assertion.repository.")
	}

	if _, ok := doc.AttributeMapping["attribute.repository_id"]; !ok {
		result.Recommendations = append(result.Recommendations, "Consider mapping 'attribute.repository_id' = 'assertion.repository_id' for July 2026 immutable repository validation.")
	}

	cond := strings.TrimSpace(doc.AttributeCondition)
	if cond == "" {
		result.Valid = false
		result.Warnings = append(result.Warnings, "attributeCondition is empty. Any GitHub repository can authenticate through this Workload Identity Pool.")
	} else {
		if expectedOrg != "" && expectedRepo != "" {
			expectedRef := fmt.Sprintf("%s/%s", expectedOrg, expectedRepo)
			if !strings.Contains(cond, expectedRef) {
				result.Warnings = append(result.Warnings, fmt.Sprintf("attributeCondition '%s' does not explicitly match expected repository '%s'", cond, expectedRef))
			}
		}
	}

	return result, nil
}

type azureFedDoc struct {
	Name      string   `json:"name"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Audiences []string `json:"audiences"`
}

// ValidateAzureFederationJSON cross-audits an Azure Entra ID federated credential JSON manifest.
func ValidateAzureFederationJSON(fedJSON, expectedOrg, expectedRepo string) (*PolicyVerificationResult, error) {
	var doc azureFedDoc
	if err := json.Unmarshal([]byte(fedJSON), &doc); err != nil {
		return nil, fmt.Errorf("invalid Azure Federated Credential JSON: %w", err)
	}

	result := &PolicyVerificationResult{
		Valid:    true,
		Provider: "Azure",
	}

	if doc.Issuer != "https://token.actions.githubusercontent.com" {
		result.Valid = false
		result.Warnings = append(result.Warnings, fmt.Sprintf("Issuer is '%s', expected 'https://token.actions.githubusercontent.com'", doc.Issuer))
	}

	hasValidAud := false
	for _, aud := range doc.Audiences {
		if aud == "api://AzureADTokenExchange" {
			hasValidAud = true
			break
		}
	}
	if !hasValidAud {
		result.Warnings = append(result.Warnings, "Audiences does not contain 'api://AzureADTokenExchange'")
	}

	if doc.Subject == "" || doc.Subject == "*" || doc.Subject == "repo:*" {
		result.Valid = false
		result.Warnings = append(result.Warnings, "Subject is empty or broad wildcard. Any repository can request federated credentials.")
	} else if expectedOrg != "" && expectedRepo != "" {
		expectedPattern := fmt.Sprintf("repo:%s/%s", expectedOrg, expectedRepo)
		if !strings.Contains(doc.Subject, expectedPattern) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Subject '%s' does not match expected repository '%s'", doc.Subject, expectedPattern))
		}
	}

	return result, nil
}

