package remediation

import (
	"encoding/json"
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

type gcpWIFConfig struct {
	Name               string            `json:"name"`
	AttributeMapping   map[string]string `json:"attribute_mapping"`
	AttributeCondition string            `json:"attribute_condition"`
	ServiceAccountRole string            `json:"service_account_binding"`
}

// GenerateGCPWorkloadIdentityAssertion generates the recommended attribute condition and mappings for GCP WIF.
func GenerateGCPWorkloadIdentityAssertion(projectNumber, poolID, providerID, owner, repo string, wf *parser.Workflow, job *parser.Job) (string, error) {
	if projectNumber == "" {
		projectNumber = "123456789012"
	}
	if poolID == "" {
		poolID = "github-pool"
	}
	if providerID == "" {
		providerID = "github-provider"
	}
	if owner == "" {
		owner = "OWNER"
	}
	if repo == "" {
		repo = "REPO"
	}

	subClaim := SynthesizeSubClaim(owner, repo, wf, job)

	providerResource := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectNumber, poolID, providerID)

	condition := fmt.Sprintf("assertion.repository == '%s/%s'", owner, repo)
	if job != nil && job.GetEnvironmentName() != "" {
		condition = fmt.Sprintf("%s && assertion.environment == '%s'", condition, job.GetEnvironmentName())
	} else if wf != nil && wf.On.Conditions != nil {
		if pushCond, ok := wf.On.Conditions["push"].(map[string]interface{}); ok {
			if branches, ok := pushCond["branches"].([]interface{}); ok && len(branches) > 0 {
				condition = fmt.Sprintf("%s && assertion.ref == 'refs/heads/%v'", condition, branches[0])
			}
		}
	}

	cfg := gcpWIFConfig{
		Name: providerResource,
		AttributeMapping: map[string]string{
			"google.subject":        "assertion.sub",
			"attribute.actor":       "assertion.actor",
			"attribute.repository":  "assertion.repository",
			"attribute.ref":         "assertion.ref",
			"attribute.environment": "assertion.environment",
		},
		AttributeCondition: condition,
		ServiceAccountRole: fmt.Sprintf("principal://iam.googleapis.com/%s/subject/%s", providerResource, subClaim),
	}

	bytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize GCP WIF configuration: %w", err)
	}

	return string(bytes), nil
}
