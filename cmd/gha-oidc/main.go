package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/fetcher"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/remediation"
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
		Version: "0.1.0",
		Short:   "Security static analyzer, least-privilege cloud trust policy & IaC generator for GitHub Actions OIDC",
		Long: `gha-oidc-auditor is a static security analysis tool for GitHub Actions workflows.
It detects supply-chain and privilege escalation risks in ephemeral OIDC token lifecycles (id-token: write),
vulnerable execution triggers (pull_request_target, workflow_run), and synthesizes minimal-privilege
Cloud Trust Policies & Terraform/OpenTofu HCL for AWS, GCP, and Azure.`,
		RunE: runAudit,
	}

	rootCmd.Flags().StringVarP(&flagPath, "path", "p", "", "Local path to workflow file or directory (.github/workflows)")
	rootCmd.Flags().StringVarP(&flagRepo, "repo", "r", "", "Remote repository in owner/repo format (e.g. gamesapeca/gha-oidc-auditor)")
	rootCmd.Flags().StringVarP(&flagOrg, "org", "o", "", "GitHub organization name to audit all repositories")
	rootCmd.Flags().StringVarP(&flagToken, "token", "t", "", "GitHub Personal Access Token (or read from $GITHUB_TOKEN)")
	rootCmd.Flags().StringVarP(&flagFormat, "format", "f", "console", "Output format: console, json, markdown, hcl")
	rootCmd.Flags().StringVar(&flagFailOn, "fail-on", "critical", "Severity threshold for non-zero exit code: critical, high, medium, all, none")
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
	// Offline Cloud Trust Policy Verification Mode (CIEM)
	if flagVerifyPolicy != "" {
		policyBytes, err := os.ReadFile(flagVerifyPolicy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading policy file %s: %v\n", flagVerifyPolicy, err)
			os.Exit(report.ExitParseError)
		}

		var res *remediation.PolicyVerificationResult
		owner := "OWNER"
		repo := "REPO"
		if flagRepo != "" {
			parts := strings.Split(flagRepo, "/")
			if len(parts) == 2 {
				owner = parts[0]
				repo = parts[1]
			}
		}

		switch strings.ToLower(flagCloudProvider) {
		case "gcp", "wif":
			res, err = remediation.ValidateGCPWIFConfigJSON(string(policyBytes), owner, repo)
		case "azure", "entra":
			res, err = remediation.ValidateAzureFederationJSON(string(policyBytes), owner, repo)
		default:
			res, err = remediation.ValidateAWSTrustPolicyJSON(string(policyBytes), owner, repo)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Policy verification error: %v\n", err)
			os.Exit(report.ExitParseError)
		}

		fmt.Printf("=== Cloud Trust Policy Audit (%s) ===\n", res.Provider)
		fmt.Printf("Status: %s\n", map[bool]string{true: "VALID (Least-Privilege Compliant)", false: "OVERPRIVILEGED / INVALID"}[res.Valid])
		if len(res.Warnings) > 0 {
			fmt.Println("\n[!] Security Warnings:")
			for _, w := range res.Warnings {
				fmt.Printf("  - %s\n", w)
			}
		}
		if len(res.Recommendations) > 0 {
			fmt.Println("\n[*] Hardening Recommendations:")
			for _, r := range res.Recommendations {
				fmt.Printf("  - %s\n", r)
			}
		}
		if !res.Valid {
			os.Exit(report.ExitCriticalFound)
		}
		os.Exit(report.ExitOK)
	}

	token := flagToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	ctx := context.Background()
	engine := analyzer.NewDefaultEngine()

	var allWorkflows []*parser.Workflow
	targetName := "local"

	switch {
	case flagPath != "":
		targetName = flagPath
		wfs, err := fetcher.ScanLocalPath(flagPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning local path %s: %v\n", flagPath, err)
			os.Exit(report.ExitParseError)
		}
		allWorkflows = wfs

	case flagRepo != "":
		targetName = flagRepo
		parts := strings.Split(flagRepo, "/")
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid repository format. Expected owner/repo (e.g. gamesapeca/gha-oidc-auditor)\n")
			os.Exit(report.ExitInvalidArgs)
		}

		ghFetcher := fetcher.NewGitHubFetcher(token)
		wfs, err := ghFetcher.FetchRepoWorkflows(ctx, parts[0], parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error querying GitHub API: %v\n", err)
			os.Exit(report.ExitAPIError)
		}
		allWorkflows = wfs

	case flagOrg != "":
		targetName = flagOrg
		ghFetcher := fetcher.NewGitHubFetcher(token)
		orgWorkflows, err := ghFetcher.FetchOrgWorkflows(ctx, flagOrg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error querying organization on GitHub API: %v\n", err)
			os.Exit(report.ExitAPIError)
		}
		for _, wfs := range orgWorkflows {
			allWorkflows = append(allWorkflows, wfs...)
		}

	default:
		if _, err := os.Stat(".github/workflows"); err == nil {
			targetName = ".github/workflows"
			wfs, err := fetcher.ScanLocalPath(".github/workflows")
			if err == nil {
				allWorkflows = wfs
			}
		} else {
			_ = cmd.Help()
			os.Exit(report.ExitOK)
		}
	}

	if len(allWorkflows) == 0 {
		fmt.Fprintf(os.Stderr, "No workflow files (.yml / .yaml) found for target %s.\n", targetName)
		os.Exit(report.ExitOK)
	}

	auditReport := engine.AnalyzeWorkflows(targetName, allWorkflows)

	if flagBountyMode {
		// In bounty mode, clear non-exploit findings to maximize signal-to-noise ratio
		auditReport.Findings = nil
		auditReport.Summary = map[analyzer.Severity]int{
			analyzer.SeverityCritical: len(auditReport.ExploitChains),
			analyzer.SeverityHigh:     0,
			analyzer.SeverityMedium:   0,
			analyzer.SeverityLow:      0,
			analyzer.SeverityInfo:     0,
		}
	}

	if flagGeneratePoC {
		pocContent := report.GenerateBugBountyReport(auditReport)
		pocDest := flagPoCOutput
		if pocDest == "" {
			pocDest = flagOutput
		}

		if pocDest != "" {
			if err := os.WriteFile(pocDest, []byte(pocContent), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing PoC report to %s: %v\n", pocDest, err)
				os.Exit(report.ExitParseError)
			}
			fmt.Printf("Bug Bounty PoC report written to %s\n", pocDest)
		} else {
			fmt.Println(pocContent)
		}

		if len(auditReport.ExploitChains) > 0 {
			os.Exit(report.ExitCriticalFound)
		}
		os.Exit(report.ExitOK)
	}

	generatedPolicies := make(map[string]string)
	if flagGeneratePolicies {
		for _, wf := range allWorkflows {
			owner := "OWNER"
			repo := "REPO"
			if flagRepo != "" {
				parts := strings.Split(flagRepo, "/")
				if len(parts) == 2 {
					owner = parts[0]
					repo = parts[1]
				}
			}

			for jobName, job := range wf.Jobs {
				if !analyzer.IsJobOIDCPrivileged(wf, jobName) {
					continue
				}

				for _, step := range job.Steps {
					match, ok := analyzer.MatchCloudAction(step)
					if !ok {
						continue
					}

					switch match.Provider {
					case analyzer.ProviderAWS:
						policy, err := remediation.GenerateAWSTrustPolicy("123456789012", owner, repo, wf, &job)
						if err == nil {
							key := fmt.Sprintf("%s_%s_AWS_TrustPolicy.json", wf.Name, jobName)
							generatedPolicies[key] = policy
						}
					case analyzer.ProviderGCP:
						policy, err := remediation.GenerateGCPWorkloadIdentityAssertion("123456789012", "pool-id", "github-provider", owner, repo, wf, &job)
						if err == nil {
							key := fmt.Sprintf("%s_%s_GCP_WIF.json", wf.Name, jobName)
							generatedPolicies[key] = policy
						}
					case analyzer.ProviderAzure:
						policy, err := remediation.GenerateAzureFederatedCredential(owner, repo, wf, &job)
						if err == nil {
							key := fmt.Sprintf("%s_%s_Azure_Federation.json", wf.Name, jobName)
							generatedPolicies[key] = policy
						}
					case analyzer.ProviderVault:
						policy, err := remediation.GenerateVaultJWTRole(owner, repo, "deployer-role", wf, &job)
						if err == nil {
							key := fmt.Sprintf("%s_%s_Vault_JWTRole.json", wf.Name, jobName)
							generatedPolicies[key] = policy
						}
					}
				}
			}
		}
	}

	generatedHCL := make(map[string]string)
	if flagGenerateHCL || strings.ToLower(flagFormat) == "hcl" {
		for _, wf := range allWorkflows {
			owner := "OWNER"
			repo := "REPO"
			if flagRepo != "" {
				parts := strings.Split(flagRepo, "/")
				if len(parts) == 2 {
					owner = parts[0]
					repo = parts[1]
				}
			}

			for jobName, job := range wf.Jobs {
				if !analyzer.IsJobOIDCPrivileged(wf, jobName) {
					continue
				}

				matchedAny := false
				for _, step := range job.Steps {
					match, ok := analyzer.MatchCloudAction(step)
					if !ok {
						continue
					}
					matchedAny = true

					switch match.Provider {
					case analyzer.ProviderAWS:
						hcl := remediation.GenerateAWSTerraformHCL("123456789012", owner, repo, wf, &job)
						key := fmt.Sprintf("%s_%s_aws_oidc.tf", wf.Name, jobName)
						generatedHCL[key] = hcl
					case analyzer.ProviderGCP:
						hcl := remediation.GenerateGCPTerraformHCL("projects/123/locations/global/workloadIdentityPools/gha-pool", owner, repo, wf, &job)
						key := fmt.Sprintf("%s_%s_gcp_wif.tf", wf.Name, jobName)
						generatedHCL[key] = hcl
					case analyzer.ProviderAzure:
						hcl := remediation.GenerateAzureTerraformHCL("${azuread_application.gha_app.object_id}", owner, repo, wf, &job)
						key := fmt.Sprintf("%s_%s_azure_federation.tf", wf.Name, jobName)
						generatedHCL[key] = hcl
					}
				}

				if !matchedAny {
					hcl := remediation.GenerateAWSTerraformHCL("123456789012", owner, repo, wf, &job)
					key := fmt.Sprintf("%s_%s_aws_oidc.tf", wf.Name, jobName)
					generatedHCL[key] = hcl
				}
			}
		}

		if flagHCLOutput != "" {
			_ = os.MkdirAll(flagHCLOutput, 0755)
			for fname, content := range generatedHCL {
				dest := filepath.Join(flagHCLOutput, fname)
				if err := os.WriteFile(dest, []byte(content), 0644); err == nil {
					fmt.Printf("Terraform HCL module written to %s\n", dest)
				}
			}
		}
	}

	var outputContent string
	switch strings.ToLower(flagFormat) {
	case "json":
		jsonStr, err := report.ExportJSON(auditReport)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting JSON: %v\n", err)
			os.Exit(report.ExitParseError)
		}
		outputContent = jsonStr

	case "markdown", "md":
		outputContent = report.ExportMarkdown(auditReport, generatedPolicies)

	case "hcl":
		var sb strings.Builder
		for name, hcl := range generatedHCL {
			sb.WriteString(fmt.Sprintf("# File: %s\n%s\n\n", name, hcl))
		}
		outputContent = sb.String()

	default:
		if flagOutput == "" {
			report.RenderConsole(os.Stdout, auditReport)
			if len(generatedPolicies) > 0 {
				fmt.Println("--- Synthesized Cloud Trust Policies (Least-Privilege) ---")
				for name, p := range generatedPolicies {
					fmt.Printf("\n[+] Policy: %s\n%s\n", name, p)
				}
			}
			if len(generatedHCL) > 0 && flagHCLOutput == "" {
				fmt.Println("\n--- Synthesized Remediation-as-Code (Terraform HCL) ---")
				for name, hcl := range generatedHCL {
					fmt.Printf("\n[+] Module: %s\n%s\n", name, hcl)
				}
			}
		} else {
			var sb strings.Builder
			report.RenderConsole(&sb, auditReport)
			outputContent = sb.String()
		}
	}

	if flagOutput != "" {
		if err := os.WriteFile(flagOutput, []byte(outputContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing report to %s: %v\n", flagOutput, err)
			os.Exit(report.ExitParseError)
		}
		fmt.Printf("Audit report written to %s\n", flagOutput)
	} else if outputContent != "" {
		fmt.Println(outputContent)
	}

	exitCode := report.DetermineExitCode(auditReport, flagFailOn)
	os.Exit(exitCode)
	return nil
}

