package remediation

import (
	"encoding/json"
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

type vaultJWTRoleConfig struct {
	RoleType       string            `json:"role_type"`
	BoundAudiences []string          `json:"bound_audiences"`
	UserClaim      string            `json:"user_claim"`
	BoundClaims    map[string]string `json:"bound_claims"`
	Policies       []string          `json:"policies"`
	TTL            string            `json:"ttl"`
}

// GenerateVaultJWTRole synthesizes a least-privilege HashiCorp Vault JWT Role definition for GitHub Actions OIDC.
func GenerateVaultJWTRole(owner, repo, roleName string, wf *parser.Workflow, job *parser.Job) (string, error) {
	if owner == "" {
		owner = "OWNER"
	}
	if repo == "" {
		repo = "REPO"
	}
	if roleName == "" {
		roleName = "deploy-role"
	}

	boundClaims := map[string]string{
		"repository": fmt.Sprintf("%s/%s", owner, repo),
	}

	if job != nil && job.GetEnvironmentName() != "" {
		boundClaims["environment"] = job.GetEnvironmentName()
	} else if wf != nil && wf.On.Conditions != nil {
		if pushCond, ok := wf.On.Conditions["push"].(map[string]interface{}); ok {
			if branches, ok := pushCond["branches"].([]interface{}); ok && len(branches) > 0 {
				boundClaims["ref"] = fmt.Sprintf("refs/heads/%v", branches[0])
			}
		}
	}

	role := vaultJWTRoleConfig{
		RoleType:       "jwt",
		BoundAudiences: []string{fmt.Sprintf("https://github.com/%s", owner)},
		UserClaim:      "actor",
		BoundClaims:    boundClaims,
		Policies:       []string{roleName},
		TTL:            "15m",
	}

	bytes, err := json.MarshalIndent(role, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize Vault JWT role: %w", err)
	}

	return string(bytes), nil
}
