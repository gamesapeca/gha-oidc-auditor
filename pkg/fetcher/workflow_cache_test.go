package fetcher

import (
	"bytes"
	"testing"
	"time"
)

func TestWorkflowCache_L1AndL2Persistence(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewWorkflowCacheWithDir(tempDir, 5*time.Minute)

	owner := "gamesapeca"
	repo := "shared-workflows"
	ref := "main"
	path := ".github/workflows/deploy.yml"
	content := []byte("name: Shared Deploy\non: workflow_call\n")

	// Initially empty
	if _, ok := cache.Get(owner, repo, ref, path); ok {
		t.Errorf("expected cache miss on fresh key")
	}

	// Set content
	cache.Set(owner, repo, ref, path, content)

	// L1 / L2 hit
	cached, ok := cache.Get(owner, repo, ref, path)
	if !ok {
		t.Fatalf("expected cache hit after Set")
	}
	if !bytes.Equal(cached, content) {
		t.Errorf("cached content mismatch: got %s, want %s", string(cached), string(content))
	}
}
