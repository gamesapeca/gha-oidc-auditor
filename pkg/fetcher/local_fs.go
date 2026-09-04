package fetcher

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// MaxWorkflowFileSize sets a defensive 10 MB limit per file to prevent memory exhaustion DoS attacks.
const MaxWorkflowFileSize int64 = 10 * 1024 * 1024

// isYAMLFile checks if a filename ends with .yml or .yaml in a case-insensitive manner.
func isYAMLFile(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// ScanLocalPath traverses a target file or directory looking for GitHub Actions workflow files (.yml / .yaml) and parses them.
func ScanLocalPath(targetPath string) ([]*parser.Workflow, error) {
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("target path not found %s: %w", targetPath, err)
	}

	var workflows []*parser.Workflow

	// Single file target
	if !info.IsDir() {
		if isYAMLFile(targetPath) {
			if info.Size() > MaxWorkflowFileSize {
				return nil, fmt.Errorf("file %s exceeds maximum permitted size of 10MB", targetPath)
			}
			wf, err := parser.ParseWorkflowFile(targetPath)
			if err != nil {
				return nil, err
			}
			return []*parser.Workflow{wf}, nil
		}
		return nil, fmt.Errorf("specified file is not a YAML manifest: %s", targetPath)
	}

	// Directory target: traverse recursively, handling symlinks and mixed case extensions
	err = filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" || name == "venv" || name == "dist" || name == "build" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}

		// Handle regular files and symlinks
		if isYAMLFile(d.Name()) {
			fileInfo, statErr := os.Stat(path)
			if statErr == nil && !fileInfo.IsDir() && fileInfo.Size() <= MaxWorkflowFileSize {
				wf, parseErr := parser.ParseWorkflowFile(path)
				if parseErr == nil && wf != nil && (len(wf.Jobs) > 0 || len(wf.On.Events) > 0) {
					workflows = append(workflows, wf)
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error scanning directory %s: %w", targetPath, err)
	}

	return workflows, nil
}
