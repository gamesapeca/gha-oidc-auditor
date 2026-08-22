package parser

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ParseWorkflowFile reads a workflow file from the filesystem and unmarshals it into a *Workflow AST.
func ParseWorkflowFile(filePath string) (*Workflow, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow file %s: %w", filePath, err)
	}
	return ParseWorkflowBytes(data, filePath)
}

// ParseWorkflowBytes parses raw YAML bytes into a typed *Workflow structure.
func ParseWorkflowBytes(content []byte, filePath string) (*Workflow, error) {
	var wf Workflow
	if err := yaml.Unmarshal(content, &wf); err != nil {
		return nil, fmt.Errorf("failed to parse YAML for %s: %w", filePath, err)
	}

	wf.Path = filePath
	wf.RawContent = string(content)

	// Ensure job names fallback to map keys when the name property is omitted
	for jobKey, job := range wf.Jobs {
		if job.Name == "" {
			job.Name = jobKey
			wf.Jobs[jobKey] = job
		}
	}

	return &wf, nil
}
