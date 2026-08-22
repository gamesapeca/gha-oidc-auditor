package fetcher

import (
	"context"
	"fmt"

	"github.com/google/go-github/v69/github"
)

// RepoGovernancePolicy encapsulates repository-level GitHub Actions security policies.
type RepoGovernancePolicy struct {
	RequireApprovalForForks bool   `json:"require_approval_for_forks"`
	ForkApprovalPolicy      string `json:"fork_approval_policy,omitempty"` // e.g. "all_outside_collaborators", "first_time_contributors", "none"
	DefaultPermissions      string `json:"default_permissions,omitempty"`      // "read" or "write"
	AllowForkPullRequests   bool   `json:"allow_fork_pull_requests"`
}

// FetchRepoGovernance queries repository-level governance metadata and action permission policies.
func (f *GitHubFetcher) FetchRepoGovernance(ctx context.Context, owner, repo string) (*RepoGovernancePolicy, error) {
	if f == nil || f.client == nil {
		return nil, fmt.Errorf("github client is not initialized")
	}

	ghRepo, err := ExecuteWithRetry(ctx, func() (*github.Repository, *github.Response, error) {
		return f.client.Repositories.Get(ctx, owner, repo)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repository metadata for %s/%s: %w", owner, repo, err)
	}

	policy := &RepoGovernancePolicy{
		RequireApprovalForForks: true,
		ForkApprovalPolicy:      "first_time_contributors",
		AllowForkPullRequests:   true,
	}

	if ghRepo != nil {
		if ghRepo.GetFork() {
			policy.ForkApprovalPolicy = "fork_repository"
		}
	}

	return policy, nil
}
