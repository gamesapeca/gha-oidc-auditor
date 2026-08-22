package remediation

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

var azureNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9-_]`)

type azureFederatedCredential struct {
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Description string   `json:"description"`
	Audiences   []string `json:"audiences"`
}

// GenerateAzureFederatedCredential generates the federated credential manifest for Azure Entra ID / Managed Identity.
func GenerateAzureFederatedCredential(owner, repo string, wf *parser.Workflow, job *parser.Job) (string, error) {
	if owner == "" {
		owner = "OWNER"
	}
	if repo == "" {
		repo = "REPO"
	}

	subClaim := SynthesizeSubClaim(owner, repo, wf, job)

	rawName := fmt.Sprintf("gha-%s-%s", owner, repo)
	sanitizedName := azureNameSanitizer.ReplaceAllString(rawName, "-")
	if len(sanitizedName) > 120 {
		sanitizedName = sanitizedName[:120]
	}

	cred := azureFederatedCredential{
		Name:        sanitizedName,
		Issuer:      "https://token.actions.githubusercontent.com",
		Subject:     subClaim,
		Description: fmt.Sprintf("GitHub Actions federated credential for %s/%s", owner, repo),
		Audiences:   []string{"api://AzureADTokenExchange"},
	}

	bytes, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize Azure federated credential: %w", err)
	}

	return string(bytes), nil
}
