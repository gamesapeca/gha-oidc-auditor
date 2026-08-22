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
