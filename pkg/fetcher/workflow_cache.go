package fetcher

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WorkflowCache manages an L1 (in-memory) and L2 (disk) cache for reusable workflow blobs.
type WorkflowCache struct {
	mu        sync.RWMutex
	memory    map[string][]byte
	cacheDir  string
	ttl       time.Duration
}

// NewWorkflowCache initializes the cache with default user cache directory and TTL.
func NewWorkflowCache(ttl time.Duration) *WorkflowCache {
	userCache, err := os.UserCacheDir()
	if err != nil {
		userCache = os.TempDir()
	}
	cacheDir := filepath.Join(userCache, "gha-oidc", "workflows")
	return NewWorkflowCacheWithDir(cacheDir, ttl)
}

// NewWorkflowCacheWithDir initializes the cache with an explicit directory and TTL.
func NewWorkflowCacheWithDir(cacheDir string, ttl time.Duration) *WorkflowCache {
	_ = os.MkdirAll(cacheDir, 0750)
	return &WorkflowCache{
		memory:   make(map[string][]byte),
		cacheDir: cacheDir,
		ttl:      ttl,
	}
}

func (c *WorkflowCache) generateKey(owner, repo, ref, path string) string {
	raw := fmt.Sprintf("%s/%s@%s:%s", owner, repo, ref, path)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// Get retrieves workflow YAML content from L1 or L2 cache.
func (c *WorkflowCache) Get(owner, repo, ref, path string) ([]byte, bool) {
	key := c.generateKey(owner, repo, ref, path)

	// Check L1 memory
	c.mu.RLock()
	if val, ok := c.memory[key]; ok {
		c.mu.RUnlock()
		return val, true
	}
	c.mu.RUnlock()

	// Check L2 disk
	filePath := filepath.Join(c.cacheDir, key+".yaml")
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, false
	}

	if c.ttl > 0 && time.Since(info.ModTime()) > c.ttl {
		_ = os.Remove(filePath)
		return nil, false
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false
	}

	// Populate L1
	c.mu.Lock()
	c.memory[key] = data
	c.mu.Unlock()

	return data, true
}

// Set stores workflow content in L1 memory and L2 disk.
func (c *WorkflowCache) Set(owner, repo, ref, path string, data []byte) {
	key := c.generateKey(owner, repo, ref, path)

	c.mu.Lock()
	c.memory[key] = data
	c.mu.Unlock()

	filePath := filepath.Join(c.cacheDir, key+".yaml")
	_ = os.WriteFile(filePath, data, 0600)
}
