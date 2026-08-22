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
		ActionPrefix: "aws-actions/amazon-ecr-login",
		Provider:     ProviderAWS,
		KeyFields:    []string{"role-to-assume", "aws-region"},
	},
	{
		ActionPrefix: "google-github-actions/auth",
		Provider:     ProviderGCP,
		KeyFields:    []string{"service_account", "workload_identity_provider", "project_id"},
	},
	{
		ActionPrefix: "google-github-actions/setup-gcloud",
		Provider:     ProviderGCP,
		KeyFields:    []string{"service_account", "workload_identity_provider"},
	},
	{
		ActionPrefix: "azure/login",
		Provider:     ProviderAzure,
		KeyFields:    []string{"client-id", "tenant-id", "subscription-id"},
	},
	{
		ActionPrefix: "hashicorp/vault-action",
		Provider:     ProviderVault,
		KeyFields:    []string{"role", "url", "method", "path"},
	},
	{
		ActionPrefix: "actions/attest-build-provenance",
		Provider:     ProviderSigstore,
		KeyFields:    []string{"subject-path", "subject-checksums"},
	},
	{
		ActionPrefix: "actions/attest",
		Provider:     ProviderSigstore,
		KeyFields:    []string{"subject-path", "subject-name"},
	},
	{
		ActionPrefix: "tailscale/github-action",
		Provider:     ProviderTailscale,
		KeyFields:    []string{"oauth-client-id", "tags"},
	},
	{
		ActionPrefix: "azure/k8s-set-context",
		Provider:     ProviderKubernetes,
		KeyFields:    []string{"method", "cluster-name"},
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

	trimmedUses := strings.TrimSpace(step.Uses)
	lowerUses := strings.ToLower(trimmedUses)

	for _, spec := range KnownCloudActions {
		if strings.HasPrefix(lowerUses, strings.ToLower(spec.ActionPrefix)) {
			res := CloudMatchResult{
				Provider:  spec.Provider,
				Action:    trimmedUses,
				Extracted: make(map[string]string),
			}

			for _, key := range spec.KeyFields {
				val := step.GetWithString(key)
				if val == "" {
					val = step.GetEnvString(key)
				}
				if val != "" {
					res.Extracted[key] = val
					if res.TargetInfo == "" {
						res.TargetInfo = val
						res.HasTarget = true
					}
				}
			}

			return res, true
		}
	}

	return CloudMatchResult{}, false
}
