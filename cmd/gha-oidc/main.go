package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/orchestrator"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/report"
	"github.com/spf13/cobra"
)

var (
	flagPath             string
	flagRepo             string
	flagOrg              string
	flagToken            string
	flagFormat           string
	flagFailOn           string
	flagConcurrency      int
	flagGeneratePolicies bool
	flagOutput           string
	flagBountyMode       bool
	flagGeneratePoC      bool
	flagPoCOutput        string
	flagGenerateHCL      bool
	flagHCLOutput        string
	flagVerifyPolicy     string
	flagCloudProvider    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "gha-oidc",
		Version: "0.2.0",
		Short:   "Security static analyzer, least-privilege cloud trust policy & IaC generator for GitHub Actions OIDC",
		Long: `gha-oidc-auditor is an enterprise static security analysis engine for GitHub Actions workflows.
It detects supply-chain and privilege escalation risks in ephemeral OIDC token lifecycles (id-token: write),
vulnerable execution triggers (pull_request_target, workflow_run), and synthesizes minimal-privilege
Cloud Trust Policies & Terraform/OpenTofu HCL for AWS, GCP, and Azure.`,
		RunE: runAudit,
	}

	rootCmd.Flags().StringVarP(&flagPath, "path", "p", "", "Local path to workflow file or directory (.github/workflows)")
	rootCmd.Flags().StringVarP(&flagRepo, "repo", "r", "", "Remote repository in owner/repo format (e.g. gamesapeca/gha-oidc-auditor)")
	rootCmd.Flags().StringVarP(&flagOrg, "org", "o", "", "GitHub organization name to audit all repositories")
	rootCmd.Flags().StringVarP(&flagToken, "token", "t", "", "GitHub Personal Access Token (or read from $GITHUB_TOKEN)")
	rootCmd.Flags().StringVarP(&flagFormat, "format", "f", "console", "Output format: console, json, sarif, markdown, hcl")
	rootCmd.Flags().StringVar(&flagFailOn, "fail-on", "critical", "Severity threshold for non-zero exit code: critical, high, medium, all, none")
	rootCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", runtime.NumCPU(), "Number of parallel workers for workflow analysis")
	rootCmd.Flags().BoolVar(&flagGeneratePolicies, "generate-policies", false, "Synthesize least-privilege cloud trust policies for audited workflows")
	rootCmd.Flags().StringVar(&flagOutput, "output", "", "Output file path to save the generated audit report")
	rootCmd.Flags().BoolVar(&flagBountyMode, "bounty-mode", false, "Filter report to display only exploitable zero-prerequisite attack chains")
	rootCmd.Flags().BoolVar(&flagGeneratePoC, "generate-poc", false, "Generate a submission-ready Bug Bounty PoC Markdown report")
	rootCmd.Flags().StringVar(&flagPoCOutput, "poc-output", "", "Output file path to save the generated Bug Bounty PoC report")
	rootCmd.Flags().BoolVar(&flagGenerateHCL, "generate-hcl", false, "Synthesize Remediation-as-Code Terraform / OpenTofu HCL modules")
	rootCmd.Flags().StringVar(&flagHCLOutput, "hcl-output", "", "Directory path to write synthesized Terraform .tf files")
	rootCmd.Flags().StringVar(&flagVerifyPolicy, "verify-policy", "", "Cross-audit an existing local cloud trust policy JSON file (AWS IAM, GCP WIF, Azure)")
	rootCmd.Flags().StringVar(&flagCloudProvider, "cloud-provider", "aws", "Cloud provider type for --verify-policy: aws, gcp, azure")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(report.ExitInvalidArgs)
	}
}

func runAudit(cmd *cobra.Command, args []string) error {
	cfg := orchestrator.Config{
		Path:             flagPath,
		Repo:             flagRepo,
		Org:              flagOrg,
		Token:            flagToken,
		Format:           flagFormat,
		FailOn:           flagFailOn,
		Concurrency:      flagConcurrency,
		GeneratePolicies: flagGeneratePolicies,
		OutputFile:       flagOutput,
		BountyMode:       flagBountyMode,
		GeneratePoC:      flagGeneratePoC,
		PoCOutputFile:    flagPoCOutput,
		GenerateHCL:      flagGenerateHCL,
		HCLOutputDir:     flagHCLOutput,
		VerifyPolicy:     flagVerifyPolicy,
		CloudProvider:    flagCloudProvider,
	}

	pipeline := orchestrator.NewPipeline(cfg)
	res, err := pipeline.Run(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
		os.Exit(report.ExitParseError)
	}

	if flagOutput == "" && res.FormattedOutput != "" {
		fmt.Print(res.FormattedOutput)
	} else if flagOutput != "" {
		fmt.Printf("Audit report written to %s\n", flagOutput)
	}

	if flagHCLOutput != "" && len(res.SynthesizedHCL) > 0 {
		fmt.Printf("Synthesized %d Terraform modules into %s\n", len(res.SynthesizedHCL), flagHCLOutput)
	}

	if flagPoCOutput != "" && res.PoCContent != "" {
		fmt.Printf("Bug Bounty PoC report written to %s\n", flagPoCOutput)
	}

	os.Exit(res.ExitCode)
	return nil
}
