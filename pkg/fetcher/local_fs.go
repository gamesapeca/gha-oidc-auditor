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

// ScanLocalPath traverses a target file or directory looking for GitHub Actions workflow files (.yml / .yaml) and parses them.
func ScanLocalPath(targetPath string) ([]*parser.Workflow, error) {
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("target path not found %s: %w", targetPath, err)
	}

	var workflows []*parser.Workflow

	// Single file target
	if !info.IsDir() {
		if strings.HasSuffix(targetPath, ".yml") || strings.HasSuffix(targetPath, ".yaml") {
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

	// Directory target: traverse recursively
	err = filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		if strings.HasSuffix(d.Name(), ".yml") || strings.HasSuffix(d.Name(), ".yaml") {
			fileInfo, err := d.Info()
			if err == nil && fileInfo.Size() <= MaxWorkflowFileSize {
				wf, err := parser.ParseWorkflowFile(path)
				if err == nil && wf != nil {
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
