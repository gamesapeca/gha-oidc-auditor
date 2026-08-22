package main

import (
	"context"
	"fmt"
	"os"
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
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "gha-oidc",
		Short: "Security static analyzer & least-privilege cloud trust policy generator for GitHub Actions OIDC",
		Long: `gha-oidc-auditor is a static security analysis tool for GitHub Actions workflows.
It detects supply-chain and privilege escalation risks in ephemeral OIDC token lifecycles (id-token: write),
vulnerable execution triggers (pull_request_target, workflow_run), and synthesizes minimal-privilege
Cloud Trust Policies for AWS, GCP, and Azure.`,
		RunE: runAudit,
	}

	rootCmd.Flags().StringVarP(&flagPath, "path", "p", "", "Local path to workflow file or directory (.github/workflows)")
	rootCmd.Flags().StringVarP(&flagRepo, "repo", "r", "", "Remote repository in owner/repo format (e.g. gamesapeca/gha-oidc-auditor)")
	rootCmd.Flags().StringVarP(&flagOrg, "org", "o", "", "GitHub organization name to audit all repositories")
	rootCmd.Flags().StringVarP(&flagToken, "token", "t", "", "GitHub Personal Access Token (or read from $GITHUB_TOKEN)")
	rootCmd.Flags().StringVarP(&flagFormat, "format", "f", "console", "Output format: console, json, markdown")
	rootCmd.Flags().StringVar(&flagFailOn, "fail-on", "critical", "Severity threshold for non-zero exit code: critical, high, medium, all, none")
	rootCmd.Flags().BoolVar(&flagGeneratePolicies, "generate-policies", false, "Synthesize least-privilege cloud trust policies for audited workflows")
	rootCmd.Flags().StringVar(&flagOutput, "output", "", "Output file path to save the generated audit report")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(report.ExitInvalidArgs)
	}
}

func runAudit(cmd *cobra.Command, args []string) error {
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

	default:
		if flagOutput == "" {
			report.RenderConsole(os.Stdout, auditReport)
			if len(generatedPolicies) > 0 {
				fmt.Println("--- Synthesized Cloud Trust Policies (Least-Privilege) ---")
				for name, p := range generatedPolicies {
					fmt.Printf("\n[+] Policy: %s\n%s\n", name, p)
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
