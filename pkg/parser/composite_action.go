package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// CompositeActionRuns encapsulates the execution model of a GitHub Composite Action.
type CompositeActionRuns struct {
	Using string `yaml:"using"`
	Steps []Step `yaml:"steps"`
}

// CompositeAction represents a parsed GitHub Actions Composite Action (action.yml / action.yaml).
type CompositeAction struct {
	Path        string              `yaml:"-"`
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Inputs      map[string]any      `yaml:"inputs"`
	Runs        CompositeActionRuns `yaml:"runs"`
}

// ParseCompositeActionBytes parses a byte slice containing action.yml content into a CompositeAction AST.
func ParseCompositeActionBytes(data []byte, path string) (*CompositeAction, error) {
	var action CompositeAction
	if err := yaml.Unmarshal(data, &action); err != nil {
		return nil, fmt.Errorf("failed to unmarshal composite action YAML %s: %w", path, err)
	}
	action.Path = path
	return &action, nil
}

// ParseCompositeActionFile reads and parses a local action.yml or action.yaml file.
func ParseCompositeActionFile(filePath string) (*CompositeAction, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read composite action file %s: %w", filePath, err)
	}
	return ParseCompositeActionBytes(data, filePath)
}

// ResolveLocalCompositeAction resolves local action references (e.g. './.github/actions/deploy')
// relative to the workspace root and parses the underlying action.yml or action.yaml.
func ResolveLocalCompositeAction(repoRoot, actionRef string) (*CompositeAction, error) {
	actionRef = strings.TrimSpace(actionRef)
	if !strings.HasPrefix(actionRef, "./") && !strings.HasPrefix(actionRef, ".\\") {
		return nil, fmt.Errorf("not a local action reference: %s", actionRef)
	}

	cleanRef := filepath.Clean(actionRef)
	candidates := []string{
		filepath.Join(repoRoot, cleanRef, "action.yml"),
		filepath.Join(repoRoot, cleanRef, "action.yaml"),
		filepath.Join(cleanRef, "action.yml"),
		filepath.Join(cleanRef, "action.yaml"),
	}

	for _, cand := range candidates {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return ParseCompositeActionFile(cand)
		}
	}

	return nil, fmt.Errorf("composite action file not found for reference: %s", actionRef)
}
