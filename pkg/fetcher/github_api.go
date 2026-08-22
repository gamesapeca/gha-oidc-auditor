package fetcher

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
	"github.com/google/go-github/v69/github"
	"golang.org/x/oauth2"
)

// GitHubFetcher encapsulates GitHub API operations with authenticated rate-limit management.
type GitHubFetcher struct {
	client *github.Client
}

// NewGitHubFetcher creates a new GitHub API fetcher. If token is empty, an unauthenticated client is initialized.
func NewGitHubFetcher(token string) *GitHubFetcher {
	ctx := context.Background()
	var client *github.Client

	if token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	} else {
		client = github.NewClient(nil)
	}

	return &GitHubFetcher{client: client}
}

// ExecuteWithRetry wraps GitHub API calls with automatic backoff on primary and secondary rate limits.
func ExecuteWithRetry[T any](ctx context.Context, fn func() (T, *github.Response, error)) (T, error) {
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		val, resp, err := fn()
		if err == nil {
			return val, nil
		}

		if ctx.Err() != nil {
			var zero T
			return zero, ctx.Err()
		}

		// Check for primary or secondary rate limits
		if resp != nil && resp.Response != nil {
			// Primary Rate Limit: 403 with Rate.Remaining == 0
			if resp.StatusCode == http.StatusForbidden && resp.Rate.Remaining == 0 {
				resetTime := resp.Rate.Reset.Time
				waitDuration := time.Until(resetTime) + 2*time.Second
				if waitDuration > 0 {
					select {
					case <-ctx.Done():
						var zero T
						return zero, ctx.Err()
					case <-time.After(waitDuration):
					}
				}
				continue
			}

			// Secondary Rate Limit / Abuse Detection: 429 Too Many Requests or 403 with Retry-After header
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
				retryAfterHeader := resp.Header.Get("Retry-After")
				var waitDuration time.Duration = time.Duration(1<<uint(i+1)) * time.Second
				if retryAfterHeader != "" {
					if seconds, parseErr := strconv.Atoi(retryAfterHeader); parseErr == nil && seconds > 0 {
						waitDuration = time.Duration(seconds)*time.Second + time.Second
					}
				}
				select {
				case <-ctx.Done():
					var zero T
					return zero, ctx.Err()
				case <-time.After(waitDuration):
				}
				continue
			}
		}

		return val, err
	}
	var zero T
	return zero, fmt.Errorf("maximum retry attempts exceeded due to GitHub API rate limiting")
}

// FetchRepoWorkflows retrieves and parses all workflow files in .github/workflows for a given repository.
func (f *GitHubFetcher) FetchRepoWorkflows(ctx context.Context, owner, repo string) ([]*parser.Workflow, error) {
	var workflows []*parser.Workflow

	dirEntries, err := ExecuteWithRetry(ctx, func() ([]*github.RepositoryContent, *github.Response, error) {
		_, entries, resp, err := f.client.Repositories.GetContents(ctx, owner, repo, ".github/workflows", nil)
		return entries, resp, err
	})

	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return workflows, nil
		}
		return nil, fmt.Errorf("failed to query .github/workflows for %s/%s: %w", owner, repo, err)
	}

	for _, entry := range dirEntries {
		name := entry.GetName()
		if entry.GetType() == "file" && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			fileContent, err := ExecuteWithRetry(ctx, func() (*github.RepositoryContent, *github.Response, error) {
				content, _, resp, err := f.client.Repositories.GetContents(ctx, owner, repo, entry.GetPath(), nil)
				return content, resp, err
			})

			if err != nil {
				continue
			}

			rawString, err := fileContent.GetContent()
			if err != nil {
				continue
			}

			wf, err := parser.ParseWorkflowBytes([]byte(rawString), fmt.Sprintf("%s/%s:%s", owner, repo, entry.GetPath()))
			if err == nil && wf != nil {
				workflows = append(workflows, wf)
			}
		}
	}

	return workflows, nil
}

// FetchOrgWorkflows scans all active repositories within an organization and fetches their workflows.
func (f *GitHubFetcher) FetchOrgWorkflows(ctx context.Context, org string) (map[string][]*parser.Workflow, error) {
	results := make(map[string][]*parser.Workflow)

	opts := &github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: github.ListOptions{
			Page:    1,
			PerPage: 100,
		},
	}

	for {
		repos, err := ExecuteWithRetry(ctx, func() ([]*github.Repository, *github.Response, error) {
			repos, resp, err := f.client.Repositories.ListByOrg(ctx, org, opts)
			return repos, resp, err
		})

		if err != nil {
			return nil, fmt.Errorf("failed to list organization repositories for %s: %w", org, err)
		}

		for _, repo := range repos {
			if repo.GetArchived() {
				continue
			}
			repoName := repo.GetName()
			wfs, err := f.FetchRepoWorkflows(ctx, org, repoName)
			if err == nil && len(wfs) > 0 {
				results[repoName] = wfs
			}
			time.Sleep(100 * time.Millisecond)
		}

		if len(repos) < opts.PerPage {
			break
		}
		opts.Page++
	}

	return results, nil
}
