package remediation

import (
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// SynthesizeSubClaim computes the least-privilege 'sub' claim based on workflow triggers and job execution environment.
func SynthesizeSubClaim(owner, repo string, wf *parser.Workflow, job *parser.Job) string {
	base := fmt.Sprintf("repo:%s/%s", owner, repo)

	// Precedence 1: If the job is bound to an Environment, GitHub Actions always issues an environment claim
	if job != nil {
		if envName := job.GetEnvironmentName(); envName != "" {
			return fmt.Sprintf("%s:environment:%s", base, envName)
		}
	}

	// Precedence 2: If push trigger defines explicit branch restrictions
	if wf != nil && wf.On.Conditions != nil {
		if pushCond, ok := wf.On.Conditions["push"].(map[string]interface{}); ok {
			if branches, ok := pushCond["branches"].([]interface{}); ok && len(branches) > 0 {
				return fmt.Sprintf("%s:ref:refs/heads/%v", base, branches[0])
			}
		}
	}

	// Safe fallback default: main branch
	return fmt.Sprintf("%s:ref:refs/heads/main", base)
}

// SynthesizeAudClaim returns the expected audience claim for the designated cloud provider.
func SynthesizeAudClaim(provider analyzer.CloudProvider, owner string) string {
	switch provider {
	case analyzer.ProviderAWS:
		return "sts.amazonaws.com"
	case analyzer.ProviderGCP:
		return "https://iam.googleapis.com"
	case analyzer.ProviderAzure:
		return "api://AzureADTokenExchange"
	default:
		if owner != "" {
			return fmt.Sprintf("https://github.com/%s", owner)
		}
		return "https://github.com"
	}
}
