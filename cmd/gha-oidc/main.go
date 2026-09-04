package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/orchestrator"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/report"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	rootCmd := buildRootCommand()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(report.ExitInvalidArgs)
	}
}

func buildRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "gha-oidc",
		Version: "1.1.0",
		Short:   "Security static analyzer, least-privilege cloud trust policy & IaC generator for GitHub Actions OIDC",
		Long: `gha-oidc-auditor is an enterprise static security analysis engine for GitHub Actions workflows.
It detects supply-chain and privilege escalation risks in ephemeral OIDC token lifecycles (id-token: write),
vulnerable execution triggers (pull_request_target, workflow_run), and synthesizes minimal-privilege
Cloud Trust Policies & Terraform/OpenTofu HCL for AWS, GCP, and Azure.`,
		RunE: runAudit,
	}

	// Global / root flags for direct execution
	registerScanFlags(rootCmd.Flags())
	rootCmd.Flags().StringVar(&flagVerifyPolicy, "verify-policy", "", "Cross-audit an existing local cloud trust policy JSON file (AWS IAM, GCP WIF, Azure)")
	rootCmd.Flags().StringVar(&flagCloudProvider, "cloud-provider", "aws", "Cloud provider type for --verify-policy: aws, gcp, azure")

	// 1. "scan" subcommand
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Audit workflows for OIDC and CI/CD security vulnerabilities",
		RunE:  runAudit,
	}
	registerScanFlags(scanCmd.Flags())
	rootCmd.AddCommand(scanCmd)

	// 2. "policy" subcommands
	policyCmd := &cobra.Command{
		Use:   "policy",
		Short: "Cloud trust policy synthesis and CIEM verification operations",
	}

	policyVerifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Cross-audit an existing local cloud trust policy JSON file (AWS IAM, GCP WIF, Azure)",
		RunE:  runPolicyVerify,
	}
	policyVerifyCmd.Flags().StringVarP(&flagVerifyPolicy, "file", "f", "", "Path to cloud trust policy JSON file")
	policyVerifyCmd.Flags().StringVarP(&flagCloudProvider, "provider", "c", "aws", "Cloud provider: aws, gcp, azure")
	policyVerifyCmd.Flags().StringVarP(&flagRepo, "repo", "r", "", "Remote repository (owner/repo) for subject verification")
	_ = policyVerifyCmd.MarkFlagRequired("file")
	policyCmd.AddCommand(policyVerifyCmd)

	policyGenerateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Synthesize least-privilege cloud trust policies for audited workflows",
		RunE: func(cmd *cobra.Command, args []string) error {
			flagGeneratePolicies = true
			return runAudit(cmd, args)
		},
	}
	registerScanFlags(policyGenerateCmd.Flags())
	policyCmd.AddCommand(policyGenerateCmd)

	rootCmd.AddCommand(policyCmd)

	// 3. "hcl" subcommand
	hclCmd := &cobra.Command{
		Use:   "hcl",
		Short: "IaC Terraform / OpenTofu remediation modules generator",
	}

	hclGenerateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Synthesize Remediation-as-Code Terraform / OpenTofu HCL modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			flagGenerateHCL = true
			return runAudit(cmd, args)
		},
	}
	registerScanFlags(hclGenerateCmd.Flags())
	hclCmd.AddCommand(hclGenerateCmd)

	rootCmd.AddCommand(hclCmd)

	return rootCmd
}

func registerScanFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&flagPath, "path", "p", "", "Local path to workflow file or directory (.github/workflows)")
	fs.StringVarP(&flagRepo, "repo", "r", "", "Remote repository in owner/repo format (e.g. gamesapeca/gha-oidc-auditor)")
	fs.StringVarP(&flagOrg, "org", "o", "", "GitHub organization name to audit all repositories")
	fs.StringVarP(&flagToken, "token", "t", "", "GitHub Personal Access Token (or read from $GITHUB_TOKEN)")
	fs.StringVarP(&flagFormat, "format", "f", "console", "Output format: console, json, jsonl, ndjson, sarif, markdown, hcl")
	fs.StringVar(&flagFailOn, "fail-on", "critical", "Severity threshold for non-zero exit code: critical, high, medium, all, none")
	fs.IntVarP(&flagConcurrency, "concurrency", "c", runtime.NumCPU(), "Number of parallel workers for workflow analysis")
	fs.BoolVar(&flagGeneratePolicies, "generate-policies", false, "Synthesize least-privilege cloud trust policies for audited workflows")
	fs.StringVar(&flagOutput, "output", "", "Output file path to save the generated audit report")
	fs.BoolVar(&flagBountyMode, "bounty-mode", false, "Filter report to display only exploitable zero-prerequisite attack chains")
	fs.BoolVar(&flagGeneratePoC, "generate-poc", false, "Generate a submission-ready Bug Bounty PoC Markdown report")
	fs.StringVar(&flagPoCOutput, "poc-output", "", "Output file path to save the generated Bug Bounty PoC report")
	fs.BoolVar(&flagGenerateHCL, "generate-hcl", false, "Synthesize Remediation-as-Code Terraform / OpenTofu HCL modules")
	fs.StringVar(&flagHCLOutput, "hcl-output", "", "Directory path to write synthesized Terraform .tf files")
}

func runPolicyVerify(cmd *cobra.Command, args []string) error {
	cfg := orchestrator.Config{
		VerifyPolicy:  flagVerifyPolicy,
		CloudProvider: flagCloudProvider,
		Repo:          flagRepo,
	}

	pipeline := orchestrator.NewPipeline(cfg)
	res, err := pipeline.Run(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Policy verification error: %v\n", err)
		os.Exit(report.ExitParseError)
	}

	if res.FormattedOutput != "" {
		fmt.Print(res.FormattedOutput)
	}

	os.Exit(res.ExitCode)
	return nil
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
