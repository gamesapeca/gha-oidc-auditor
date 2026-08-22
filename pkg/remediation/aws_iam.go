package remediation

import (
	"encoding/json"
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

type awsStatement struct {
	Effect    string                         `json:"Effect"`
	Principal map[string]string              `json:"Principal"`
	Action    string                         `json:"Action"`
	Condition map[string]map[string]string `json:"Condition"`
}

type awsPolicyDocument struct {
	Version   string         `json:"Version"`
	Statement []awsStatement `json:"Statement"`
}

// GenerateAWSTrustPolicy synthesizes a strict least-privilege IAM Trust Policy for AWS AssumeRoleWithWebIdentity.
func GenerateAWSTrustPolicy(accountID, owner, repo string, wf *parser.Workflow, job *parser.Job) (string, error) {
	if accountID == "" {
		accountID = "123456789012"
	}
	if owner == "" {
		owner = "OWNER"
	}
	if repo == "" {
		repo = "REPO"
	}

	subClaim := SynthesizeSubClaim(owner, repo, wf, job)
	audClaim := SynthesizeAudClaim(analyzer.ProviderAWS, owner)

	federatedARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/token.actions.githubusercontent.com", accountID)

	policy := awsPolicyDocument{
		Version: "2012-10-17",
		Statement: []awsStatement{
			{
				Effect: "Allow",
				Principal: map[string]string{
					"Federated": federatedARN,
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: map[string]map[string]string{
					"StringEquals": {
						"token.actions.githubusercontent.com:aud": audClaim,
						"token.actions.githubusercontent.com:sub": subClaim,
					},
				},
			},
		},
	}

	bytes, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize AWS IAM policy: %w", err)
	}

	return string(bytes), nil
}

type awsStatementMultiSub struct {
	Effect    string                            `json:"Effect"`
	Principal map[string]string                 `json:"Principal"`
	Action    string                            `json:"Action"`
	Condition map[string]map[string]interface{} `json:"Condition"`
}

type awsPolicyDocument2026 struct {
	Version   string                 `json:"Version"`
	Statement []awsStatementMultiSub `json:"Statement"`
}

// GenerateAWS2026TrustPolicy synthesizes an advanced IAM Trust Policy compatible with both the July 2026
// immutable ID subject format (repo:org@ID/repo@ID:*) and legacy name-based claims to guarantee deployment
// continuity while preventing name-squatting / repository-recycling attacks.
func GenerateAWS2026TrustPolicy(accountID, owner, repo string, wf *parser.Workflow, job *parser.Job) (string, error) {
	if accountID == "" {
		accountID = "123456789012"
	}
	if owner == "" {
		owner = "OWNER"
	}
	if repo == "" {
		repo = "REPO"
	}

	subClaim := SynthesizeSubClaim(owner, repo, wf, job)
	immutablePattern := SynthesizeImmutableSubClaimPattern(owner, repo, wf, job)
	audClaim := SynthesizeAudClaim(analyzer.ProviderAWS, owner)

	federatedARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/token.actions.githubusercontent.com", accountID)

	policy := awsPolicyDocument2026{
		Version: "2012-10-17",
		Statement: []awsStatementMultiSub{
			{
				Effect: "Allow",
				Principal: map[string]string{
					"Federated": federatedARN,
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: map[string]map[string]interface{}{
					"StringEquals": {
						"token.actions.githubusercontent.com:aud": audClaim,
					},
					"StringLike": {
						"token.actions.githubusercontent.com:sub": []string{
							subClaim,
							immutablePattern,
						},
					},
				},
			},
		},
	}

	bytes, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize AWS 2026 IAM policy: %w", err)
	}

	return string(bytes), nil
}

