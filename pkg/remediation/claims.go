package remediation

import (
	"fmt"
	"strings"

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
				branch := strings.TrimSpace(fmt.Sprintf("%v", branches[0]))
				branch = strings.TrimPrefix(branch, "refs/heads/")
				return fmt.Sprintf("%s:ref:refs/heads/%s", base, branch)
			}
			if branchStr, ok := pushCond["branches"].(string); ok && strings.TrimSpace(branchStr) != "" {
				branch := strings.TrimSpace(branchStr)
				branch = strings.TrimPrefix(branch, "refs/heads/")
				return fmt.Sprintf("%s:ref:refs/heads/%s", base, branch)
			}
		}

		if wrCond, ok := wf.On.Conditions["workflow_run"].(map[string]interface{}); ok {
			if branches, ok := wrCond["branches"].([]interface{}); ok && len(branches) > 0 {
				branch := strings.TrimSpace(fmt.Sprintf("%v", branches[0]))
				branch = strings.TrimPrefix(branch, "refs/heads/")
				return fmt.Sprintf("%s:ref:refs/heads/%s", base, branch)
			}
			if branchStr, ok := wrCond["branches"].(string); ok && strings.TrimSpace(branchStr) != "" {
				branch := strings.TrimSpace(branchStr)
				branch = strings.TrimPrefix(branch, "refs/heads/")
				return fmt.Sprintf("%s:ref:refs/heads/%s", base, branch)
			}
		}
	}

	// Safe default: main branch
	return fmt.Sprintf("%s:ref:refs/heads/main", base)
}

// SynthesizeImmutableSubClaimPattern generates the July 2026 immutable numeric-ID sub claim pattern.
// Format: repo:owner@OWNER_ID/repo@REPO_ID:<context> (or wildcard @* for resilient trust policies).
func SynthesizeImmutableSubClaimPattern(owner, repo string, wf *parser.Workflow, job *parser.Job) string {
	base := fmt.Sprintf("repo:%s@*/%s@*", owner, repo)

	if job != nil {
		if envName := job.GetEnvironmentName(); envName != "" {
			return fmt.Sprintf("%s:environment:%s", base, envName)
		}
	}

	if wf != nil && wf.On.Conditions != nil {
		if pushCond, ok := wf.On.Conditions["push"].(map[string]interface{}); ok {
			if branches, ok := pushCond["branches"].([]interface{}); ok && len(branches) > 0 {
				branch := strings.TrimSpace(fmt.Sprintf("%v", branches[0]))
				branch = strings.TrimPrefix(branch, "refs/heads/")
				return fmt.Sprintf("%s:ref:refs/heads/%s", base, branch)
			}
			if branchStr, ok := pushCond["branches"].(string); ok && strings.TrimSpace(branchStr) != "" {
				branch := strings.TrimSpace(branchStr)
				branch = strings.TrimPrefix(branch, "refs/heads/")
				return fmt.Sprintf("%s:ref:refs/heads/%s", base, branch)
			}
		}

		if wrCond, ok := wf.On.Conditions["workflow_run"].(map[string]interface{}); ok {
			if branches, ok := wrCond["branches"].([]interface{}); ok && len(branches) > 0 {
				branch := strings.TrimSpace(fmt.Sprintf("%v", branches[0]))
				branch = strings.TrimPrefix(branch, "refs/heads/")
				return fmt.Sprintf("%s:ref:refs/heads/%s", base, branch)
			}
			if branchStr, ok := wrCond["branches"].(string); ok && strings.TrimSpace(branchStr) != "" {
				branch := strings.TrimSpace(branchStr)
				branch = strings.TrimPrefix(branch, "refs/heads/")
				return fmt.Sprintf("%s:ref:refs/heads/%s", base, branch)
			}
		}
	}

	return fmt.Sprintf("%s:ref:refs/heads/main", base)
}

// SynthesizeCustomPropertyClaim formats a repository custom property claim for 2026 ABAC trust policies.
// All repository custom properties are exposed in the OIDC token with the 'repo_property_' prefix.
func SynthesizeCustomPropertyClaim(propertyName, expectedValue string) (string, string) {
	claimName := fmt.Sprintf("token.actions.githubusercontent.com:repo_property_%s", strings.TrimSpace(propertyName))
	return claimName, strings.TrimSpace(expectedValue)
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


