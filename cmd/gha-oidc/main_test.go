package main

import (
	"bytes"
	"testing"
)

func TestCLI_SubcommandsHierarchy(t *testing.T) {
	rootCmd := buildRootCommand()

	commands := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		commands[cmd.Name()] = true
	}

	expectedCmds := []string{"scan", "policy", "hcl"}
	for _, exp := range expectedCmds {
		if !commands[exp] {
			t.Errorf("Expected subcommand %q to be registered on root command", exp)
		}
	}

	// Verify policy subcommands
	policyCmd, _, err := rootCmd.Find([]string{"policy"})
	if err != nil || policyCmd == nil {
		t.Fatalf("Failed to locate policy command: %v", err)
	}

	policyChildren := make(map[string]bool)
	for _, child := range policyCmd.Commands() {
		policyChildren[child.Name()] = true
	}

	if !policyChildren["verify"] {
		t.Errorf("Expected 'policy verify' subcommand")
	}
	if !policyChildren["generate"] {
		t.Errorf("Expected 'policy generate' subcommand")
	}

	// Verify hcl subcommands
	hclCmd, _, err := rootCmd.Find([]string{"hcl"})
	if err != nil || hclCmd == nil {
		t.Fatalf("Failed to locate hcl command: %v", err)
	}

	hclChildren := make(map[string]bool)
	for _, child := range hclCmd.Commands() {
		hclChildren[child.Name()] = true
	}

	if !hclChildren["generate"] {
		t.Errorf("Expected 'hcl generate' subcommand")
	}
}

func TestCLI_HelpExecution(t *testing.T) {
	subcommands := [][]string{
		{"--help"},
		{"scan", "--help"},
		{"policy", "--help"},
		{"policy", "verify", "--help"},
		{"policy", "generate", "--help"},
		{"hcl", "--help"},
		{"hcl", "generate", "--help"},
	}

	for _, args := range subcommands {
		t.Run("Args_"+args[0], func(t *testing.T) {
			rootCmd := buildRootCommand()
			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs(args)

			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("Executing with args %v failed: %v", args, err)
			}

			out := buf.String()
			if len(out) == 0 {
				t.Errorf("Expected non-empty output for args %v", args)
			}
		})
	}
}
