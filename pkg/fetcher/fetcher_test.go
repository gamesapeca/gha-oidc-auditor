package fetcher_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/fetcher"
	"github.com/google/go-github/v62/github"
)

func TestScanLocalPath_Directory(t *testing.T) {
	wfs, err := fetcher.ScanLocalPath("../../testdata/vulnerable")
	if err != nil {
		t.Fatalf("failed to scan local directory: %v", err)
	}

	if len(wfs) < 5 {
		t.Errorf("expected at least 5 workflows in testdata/vulnerable, got: %d", len(wfs))
	}
}

func TestScanLocalPath_SingleFile(t *testing.T) {
	wfs, err := fetcher.ScanLocalPath("../../testdata/safe/sha_pinned_oidc.yml")
	if err != nil {
		t.Fatalf("failed to scan single file: %v", err)
	}

	if len(wfs) != 1 {
		t.Fatalf("expected 1 workflow, got: %d", len(wfs))
	}

	if wfs[0].Name != "Safe SHA Pinned OIDC" {
		t.Errorf("incorrect workflow name: %s", wfs[0].Name)
	}
}

func TestScanLocalPath_NonExistent(t *testing.T) {
	_, err := fetcher.ScanLocalPath("../../testdata/non_existent_dir")
	if err == nil {
		t.Errorf("expected error for non-existent path, got nil")
	}
}

func TestScanLocalPath_NonYAMLFile(t *testing.T) {
	_, err := fetcher.ScanLocalPath("../../Makefile")
	if err == nil {
		t.Errorf("expected error for non-YAML file target, got nil")
	}
}

func TestNewGitHubFetcher(t *testing.T) {
	fetcherUnauth := fetcher.NewGitHubFetcher("")
	if fetcherUnauth == nil {
		t.Fatalf("expected non-nil unauthenticated GitHubFetcher")
	}

	fetcherAuth := fetcher.NewGitHubFetcher("ghp_fake_token_12345")
	if fetcherAuth == nil {
		t.Fatalf("expected non-nil authenticated GitHubFetcher")
	}
}

func TestExecuteWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	val, err := fetcher.ExecuteWithRetry(ctx, func() (string, *github.Response, error) {
		callCount++
		return "success", nil, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "success" || callCount != 1 {
		t.Errorf("ExecuteWithRetry returned unexpected result: %s (calls: %d)", val, callCount)
	}
}

func TestExecuteWithRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	_, err := fetcher.ExecuteWithRetry(ctx, func() (string, *github.Response, error) {
		callCount++
		return "", nil, errors.New("generic fatal error")
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if callCount != 1 {
		t.Errorf("expected exactly 1 call for non-retryable error, got %d", callCount)
	}
}

func TestExecuteWithRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	resp := &github.Response{
		Response: &http.Response{
			StatusCode: http.StatusForbidden,
		},
		Rate: github.Rate{
			Remaining: 0,
			Reset:     github.Timestamp{Time: time.Now().Add(5 * time.Minute)},
		},
	}

	_, err := fetcher.ExecuteWithRetry(ctx, func() (string, *github.Response, error) {
		return "", resp, errors.New("rate limited")
	})

	if err == nil {
		t.Fatalf("expected context cancellation error, got nil")
	}
}

func TestExecuteWithRetry_SecondaryRateLimitRetry(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	header := http.Header{}
	header.Set("Retry-After", "1")

	resp429 := &github.Response{
		Response: &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     header,
		},
	}

	val, err := fetcher.ExecuteWithRetry(ctx, func() (string, *github.Response, error) {
		callCount++
		if callCount == 1 {
			return "", resp429, errors.New("secondary rate limit")
		}
		return "recovered", nil, nil
	})

	if err != nil {
		t.Fatalf("expected recovery after secondary rate limit, got error: %v", err)
	}
	if val != "recovered" || callCount != 2 {
		t.Errorf("expected 2 calls, got %d (val: %s)", callCount, val)
	}
}

func TestExecuteWithRetry_NilEmbeddedHTTPResponse(t *testing.T) {
	ctx := context.Background()

	// Response with nil embedded *http.Response
	resp := &github.Response{
		Response: nil,
	}

	_, err := fetcher.ExecuteWithRetry(ctx, func() (string, *github.Response, error) {
		return "", resp, errors.New("error with nil http.Response")
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
