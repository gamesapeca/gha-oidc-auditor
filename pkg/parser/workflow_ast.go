package parser

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Workflow represents a parsed GitHub Actions workflow AST.
type Workflow struct {
	Path           string            `yaml:"-"`
	Name           string            `yaml:"name"`
	RawContent     string            `yaml:"-"`
	Permissions    map[string]string `yaml:"-"`
	PermissionsAll string            `yaml:"-"`
	On             TriggerConfig     `yaml:"on"`
	Jobs           map[string]Job    `yaml:"jobs"`
}

// UnmarshalYAML implements yaml.Unmarshaler for Workflow.
func (w *Workflow) UnmarshalYAML(value *yaml.Node) error {
	type rawWorkflow struct {
		Name        string         `yaml:"name"`
		Permissions yaml.Node      `yaml:"permissions"`
		On          TriggerConfig  `yaml:"on"`
		Jobs        map[string]Job `yaml:"jobs"`
	}

	var raw rawWorkflow
	if err := value.Decode(&raw); err != nil {
		return err
	}

	w.Name = raw.Name
	w.On = raw.On
	w.Jobs = raw.Jobs

	switch raw.Permissions.Kind {
	case yaml.ScalarNode:
		w.PermissionsAll = raw.Permissions.Value
	case yaml.MappingNode:
		var m map[string]string
		if err := raw.Permissions.Decode(&m); err == nil {
			w.Permissions = m
		}
	}

	return nil
}

// TriggerConfig holds parsed event triggers and optional conditions.
type TriggerConfig struct {
	Events     []string               `yaml:"-"`
	Conditions map[string]interface{} `yaml:"-"`
}

// UnmarshalYAML implements yaml.Unmarshaler for TriggerConfig.
func (tc *TriggerConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		tc.Events = []string{value.Value}
		return nil

	case yaml.SequenceNode:
		for _, item := range value.Content {
			tc.Events = append(tc.Events, item.Value)
		}
		return nil

	case yaml.MappingNode:
		var m map[string]interface{}
		if err := value.Decode(&m); err != nil {
			return err
		}
		for k := range m {
			tc.Events = append(tc.Events, k)
		}
		tc.Conditions = m
		return nil

	default:
		return fmt.Errorf("unsupported trigger structure kind %v", value.Kind)
	}
}

// Job represents a single job definition within a workflow.
type Job struct {
	Name           string                 `yaml:"name"`
	Uses           string                 `yaml:"uses"`
	Permissions    map[string]string      `yaml:"-"`
	PermissionsAll string                 `yaml:"-"`
	Environment    interface{}            `yaml:"environment"`
	Steps          []Step                 `yaml:"steps"`
}

// UnmarshalYAML implements yaml.Unmarshaler for Job.
func (j *Job) UnmarshalYAML(value *yaml.Node) error {
	type rawJob struct {
		Name        string                 `yaml:"name"`
		Uses        string                 `yaml:"uses"`
		Permissions yaml.Node              `yaml:"permissions"`
		Environment interface{}            `yaml:"environment"`
		Steps       []Step                 `yaml:"steps"`
	}

	var raw rawJob
	if err := value.Decode(&raw); err != nil {
		return err
	}

	j.Name = raw.Name
	j.Uses = raw.Uses
	j.Environment = raw.Environment
	j.Steps = raw.Steps

	switch raw.Permissions.Kind {
	case yaml.ScalarNode:
		j.PermissionsAll = raw.Permissions.Value
	case yaml.MappingNode:
		var m map[string]string
		if err := raw.Permissions.Decode(&m); err == nil {
			j.Permissions = m
		}
	}

	return nil
}

// GetEnvironmentName extracts the environment name whether specified as string or object map.
func (j *Job) GetEnvironmentName() string {
	if j == nil || j.Environment == nil {
		return ""
	}
	switch v := j.Environment.(type) {
	case string:
		return v
	case map[string]interface{}:
		if name, ok := v["name"].(string); ok {
			return name
		}
	}
	return ""
}

// Step represents a sequential step execution within a Job.
type Step struct {
	Name string                 `yaml:"name"`
	Uses string                 `yaml:"uses"`
	Run  string                 `yaml:"run"`
	With map[string]interface{} `yaml:"with"`
	Env  map[string]interface{} `yaml:"env"`
}

// GetWithString safely returns the string representation of a parameter from 'with'.
func (s *Step) GetWithString(key string) string {
	if s == nil || s.With == nil {
		return ""
	}
	val, ok := s.With[key]
	if !ok || val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}

// GetEnvString safely returns the string representation of an environment variable from 'env'.
func (s *Step) GetEnvString(key string) string {
	if s == nil || s.Env == nil {
		return ""
	}
	val, ok := s.Env[key]
	if !ok || val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}
