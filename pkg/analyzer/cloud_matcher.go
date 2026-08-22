package analyzer

import (
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// CloudActionSpec defines known cloud authentication actions and target credential fields.
type CloudActionSpec struct {
	ActionPrefix string
	Provider     CloudProvider
	KeyFields    []string
}

// KnownCloudActions catalogs official OIDC cloud authentication actions.
var KnownCloudActions = []CloudActionSpec{
	{
		ActionPrefix: "aws-actions/configure-aws-credentials",
		Provider:     ProviderAWS,
		KeyFields:    []string{"role-to-assume", "aws-region", "role-session-name"},
	},
	{
		ActionPrefix: "google-github-actions/auth",
		Provider:     ProviderGCP,
		KeyFields:    []string{"workload_identity_provider", "service_account", "project_id"},
	},
	{
		ActionPrefix: "azure/login",
		Provider:     ProviderAzure,
		KeyFields:    []string{"client-id", "tenant-id", "subscription-id"},
	},
	{
		ActionPrefix: "hashicorp/vault-action",
		Provider:     ProviderVault,
		KeyFields:    []string{"url", "role", "method", "path"},
	},
}

// CloudMatchResult holds metadata extracted from an identified cloud authentication action step.
type CloudMatchResult struct {
	Provider   CloudProvider
	Action     string
	Extracted  map[string]string
	HasTarget  bool
	TargetInfo string
}

// MatchCloudAction inspects whether a step invokes an OIDC cloud provider action and extracts relevant parameters.
func MatchCloudAction(step parser.Step) (CloudMatchResult, bool) {
	if step.Uses == "" {
		return CloudMatchResult{}, false
	}

	for _, spec := range KnownCloudActions {
		if strings.HasPrefix(step.Uses, spec.ActionPrefix) {
			res := CloudMatchResult{
				Provider:  spec.Provider,
				Action:    step.Uses,
				Extracted: make(map[string]string),
			}

			for _, field := range spec.KeyFields {
				val := step.GetWithString(field)
				if val != "" {
					res.Extracted[field] = val
				}
			}

			// Extract primary target identity
			switch spec.Provider {
			case ProviderAWS:
				if role := res.Extracted["role-to-assume"]; role != "" {
					res.HasTarget = true
					res.TargetInfo = role
				}
			case ProviderGCP:
				if sa := res.Extracted["service_account"]; sa != "" {
					res.HasTarget = true
					res.TargetInfo = sa
				}
			case ProviderAzure:
				if clientID := res.Extracted["client-id"]; clientID != "" {
					res.HasTarget = true
					res.TargetInfo = clientID
				}
			case ProviderVault:
				if role := res.Extracted["role"]; role != "" {
					res.HasTarget = true
					res.TargetInfo = role
				}
			}

			return res, true
		}
	}

	return CloudMatchResult{}, false
}
