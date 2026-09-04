package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/fetcher"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/remediation"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/report"
)

// Pipeline coordinates the end-to-end execution of security auditing, synthesis, and reporting.
type Pipeline struct {
	cfg    Config
	engine *analyzer.Engine
}

// NewPipeline constructs an initialized Pipeline instance.
func NewPipeline(cfg Config) *Pipeline {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	return &Pipeline{
		cfg:    cfg,
		engine: analyzer.NewDefaultEngine(),
	}
}

// Run executes the complete audit lifecycle according to configuration.
func (p *Pipeline) Run(ctx context.Context) (*RunResult, error) {
	startTime := time.Now()

	// Stage 1: Offline Cloud Trust Policy Verification
	if p.cfg.VerifyPolicy != "" {
		return p.verifyCloudPolicy()
	}

	// Stage 2: Target Resolution & Workflow Ingestion
	wfs, targetName, err := p.ResolveWorkflows(ctx)
	if err != nil {
		return nil, err
	}
	if len(wfs) == 0 {
		return &RunResult{
			Target:     targetName,
			ExitCode:   report.ExitOK,
			DurationMs: time.Since(startTime).Milliseconds(),
		}, fmt.Errorf("no workflow files (.yml / .yaml) found for target %s", targetName)
	}

	// Stage 3: Concurrent Workflow Security Analysis
	auditReport := p.AnalyzeWorkflows(ctx, targetName, wfs)

	// Stage 4: Bug Bounty Mode Filtering (if enabled)
	if p.cfg.BountyMode {
		auditReport.Findings = nil
		auditReport.Summary = map[analyzer.Severity]int{
			analyzer.SeverityCritical: len(auditReport.ExploitChains),
			analyzer.SeverityHigh:     0,
			analyzer.SeverityMedium:   0,
			analyzer.SeverityLow:      0,
			analyzer.SeverityInfo:     0,
		}
	}

	// Stage 5: Bug Bounty PoC Report Generation (if enabled)
	var pocContent string
	if p.cfg.GeneratePoC {
		pocContent = report.GenerateBugBountyReport(auditReport)
		if p.cfg.PoCOutputFile != "" {
			if err := os.WriteFile(p.cfg.PoCOutputFile, []byte(pocContent), 0644); err != nil {
				return nil, fmt.Errorf("failed writing PoC report to %s: %w", p.cfg.PoCOutputFile, err)
			}
		}
	}

	// Stage 6: Least-Privilege Cloud Trust Policy Synthesis
	var policies map[string]string
	if p.cfg.GeneratePolicies {
		policies = p.SynthesizePolicies(wfs)
	}

	// Stage 7: Remediation-as-Code Terraform HCL Generation
	var hclModules map[string]string
	if p.cfg.GenerateHCL || strings.ToLower(p.cfg.Format) == "hcl" {
		hclModules = p.SynthesizeHCL(wfs)
		if p.cfg.HCLOutputDir != "" {
			_ = os.MkdirAll(p.cfg.HCLOutputDir, 0755)
			for fname, content := range hclModules {
				dest := filepath.Join(p.cfg.HCLOutputDir, fname)
				_ = os.WriteFile(dest, []byte(content), 0644)
			}
		}
	}

	durationMs := time.Since(startTime).Milliseconds()

	// Stage 8: Multi-Format Report Serialization
	formattedOut, err := p.FormatReport(auditReport, policies, hclModules, targetName, durationMs)
	if err != nil {
		return nil, err
	}

	// Write main report artifact if requested
	if p.cfg.OutputFile != "" {
		if err := os.WriteFile(p.cfg.OutputFile, []byte(formattedOut), 0644); err != nil {
			return nil, fmt.Errorf("failed writing report to %s: %w", p.cfg.OutputFile, err)
		}
	}

	exitCode := report.DetermineExitCode(auditReport, p.cfg.FailOn)
	if p.cfg.GeneratePoC && len(auditReport.ExploitChains) > 0 {
		exitCode = report.ExitCriticalFound
	}

	return &RunResult{
		Target:              targetName,
		ExitCode:            exitCode,
		DurationMs:          durationMs,
		AuditReport:         auditReport,
		FormattedOutput:     formattedOut,
		SynthesizedPolicies: policies,
		SynthesizedHCL:      hclModules,
		PoCContent:          pocContent,
	}, nil
}

// ResolveWorkflows loads and parses workflow definitions from local files, git repository, or organization.
func (p *Pipeline) ResolveWorkflows(ctx context.Context) ([]*parser.Workflow, string, error) {
	token := p.cfg.Token
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	switch {
	case p.cfg.Path != "":
		wfs, err := fetcher.ScanLocalPath(p.cfg.Path)
		if err != nil {
			return nil, p.cfg.Path, fmt.Errorf("error scanning local path %s: %w", p.cfg.Path, err)
		}
		return wfs, p.cfg.Path, nil

	case p.cfg.Repo != "":
		parts := strings.Split(p.cfg.Repo, "/")
		if len(parts) != 2 {
			return nil, p.cfg.Repo, fmt.Errorf("invalid repository format %q. Expected owner/repo", p.cfg.Repo)
		}
		ghFetcher := fetcher.NewGitHubFetcher(token)
		wfs, err := ghFetcher.FetchRepoWorkflows(ctx, parts[0], parts[1])
		if err != nil {
			return nil, p.cfg.Repo, fmt.Errorf("error querying GitHub API for repo %s: %w", p.cfg.Repo, err)
		}
		return wfs, p.cfg.Repo, nil

	case p.cfg.Org != "":
		ghFetcher := fetcher.NewGitHubFetcher(token)
		orgWorkflows, err := ghFetcher.FetchOrgWorkflows(ctx, p.cfg.Org)
		if err != nil {
			return nil, p.cfg.Org, fmt.Errorf("error querying GitHub API for org %s: %w", p.cfg.Org, err)
		}
		var allWorkflows []*parser.Workflow
		for _, wfs := range orgWorkflows {
			allWorkflows = append(allWorkflows, wfs...)
		}
		return allWorkflows, p.cfg.Org, nil

	default:
		if _, err := os.Stat(".github/workflows"); err == nil {
			wfs, err := fetcher.ScanLocalPath(".github/workflows")
			if err != nil {
				return nil, ".github/workflows", err
			}
			return wfs, ".github/workflows", nil
		}
		return nil, "default", fmt.Errorf("no target specified and .github/workflows directory does not exist")
	}
}

// AnalyzeWorkflows executes rules concurrently across all resolved workflows.
func (p *Pipeline) AnalyzeWorkflows(ctx context.Context, targetName string, wfs []*parser.Workflow) *analyzer.AuditReport {
	return p.engine.AnalyzeWorkflowsConcurrently(ctx, targetName, wfs, p.cfg.Concurrency)
}

// SynthesizePolicies generates least-privilege cloud trust policies for all OIDC-privileged jobs.
func (p *Pipeline) SynthesizePolicies(wfs []*parser.Workflow) map[string]string {
	policies := make(map[string]string)
	owner, repo := p.resolveOwnerRepo()

	for _, wf := range wfs {
		if wf == nil {
			continue
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
						policies[key] = policy
					}
				case analyzer.ProviderGCP:
					policy, err := remediation.GenerateGCPWorkloadIdentityAssertion("123456789012", "pool-id", "github-provider", owner, repo, wf, &job)
					if err == nil {
						key := fmt.Sprintf("%s_%s_GCP_WIF.json", wf.Name, jobName)
						policies[key] = policy
					}
				case analyzer.ProviderAzure:
					policy, err := remediation.GenerateAzureFederatedCredential(owner, repo, wf, &job)
					if err == nil {
						key := fmt.Sprintf("%s_%s_Azure_Federation.json", wf.Name, jobName)
						policies[key] = policy
					}
				case analyzer.ProviderVault:
					policy, err := remediation.GenerateVaultJWTRole(owner, repo, "deployer-role", wf, &job)
					if err == nil {
						key := fmt.Sprintf("%s_%s_Vault_JWTRole.json", wf.Name, jobName)
						policies[key] = policy
					}
				}
			}
		}
	}
	return policies
}

// SynthesizeHCL synthesizes Remediation-as-Code Terraform / OpenTofu HCL modules.
func (p *Pipeline) SynthesizeHCL(wfs []*parser.Workflow) map[string]string {
	hclModules := make(map[string]string)
	owner, repo := p.resolveOwnerRepo()

	for _, wf := range wfs {
		if wf == nil {
			continue
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
					hclModules[key] = hcl
				case analyzer.ProviderGCP:
					hcl := remediation.GenerateGCPTerraformHCL("projects/123/locations/global/workloadIdentityPools/gha-pool", owner, repo, wf, &job)
					key := fmt.Sprintf("%s_%s_gcp_wif.tf", wf.Name, jobName)
					hclModules[key] = hcl
				case analyzer.ProviderAzure:
					hcl := remediation.GenerateAzureTerraformHCL("${azuread_application.gha_app.object_id}", owner, repo, wf, &job)
					key := fmt.Sprintf("%s_%s_azure_federation.tf", wf.Name, jobName)
					hclModules[key] = hcl
				}
			}

			if !matchedAny {
				hcl := remediation.GenerateAWSTerraformHCL("123456789012", owner, repo, wf, &job)
				key := fmt.Sprintf("%s_%s_aws_oidc.tf", wf.Name, jobName)
				hclModules[key] = hcl
			}
		}
	}
	return hclModules
}

// FormatReport serializes the audit report into the requested representation.
func (p *Pipeline) FormatReport(auditReport *analyzer.AuditReport, policies, hcl map[string]string, target string, durationMs int64) (string, error) {
	switch strings.ToLower(p.cfg.Format) {
	case "json":
		return report.ExportFullJSON(auditReport, policies, hcl, target, durationMs)

	case "sarif":
		return report.ExportSARIF(auditReport)

	case "markdown", "md":
		return report.ExportMarkdown(auditReport, policies), nil

	case "hcl":
		var sb strings.Builder
		for name, moduleContent := range hcl {
			sb.WriteString(fmt.Sprintf("# File: %s\n%s\n\n", name, moduleContent))
		}
		return sb.String(), nil

	default: // "console"
		var sb strings.Builder
		report.RenderConsole(&sb, auditReport)

		if len(policies) > 0 {
			sb.WriteString("\n--- Synthesized Cloud Trust Policies (Least-Privilege) ---\n")
			for name, pol := range policies {
				sb.WriteString(fmt.Sprintf("\n[+] Policy: %s\n%s\n", name, pol))
			}
		}

		if len(hcl) > 0 && p.cfg.HCLOutputDir == "" {
			sb.WriteString("\n--- Synthesized Remediation-as-Code (Terraform HCL) ---\n")
			for name, moduleContent := range hcl {
				sb.WriteString(fmt.Sprintf("\n[+] Module: %s\n%s\n", name, moduleContent))
			}
		}

		return sb.String(), nil
	}
}

func (p *Pipeline) verifyCloudPolicy() (*RunResult, error) {
	policyBytes, err := os.ReadFile(p.cfg.VerifyPolicy)
	if err != nil {
		return nil, fmt.Errorf("error reading policy file %s: %w", p.cfg.VerifyPolicy, err)
	}

	owner, repo := p.resolveOwnerRepo()
	var res *remediation.PolicyVerificationResult

	switch strings.ToLower(p.cfg.CloudProvider) {
	case "gcp", "wif":
		res, err = remediation.ValidateGCPWIFConfigJSON(string(policyBytes), owner, repo)
	case "azure", "entra":
		res, err = remediation.ValidateAzureFederationJSON(string(policyBytes), owner, repo)
	default:
		res, err = remediation.ValidateAWSTrustPolicyJSON(string(policyBytes), owner, repo)
	}

	if err != nil {
		return nil, fmt.Errorf("policy verification error: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Cloud Trust Policy Audit (%s) ===\n", res.Provider))
	statusText := "OVERPRIVILEGED / INVALID"
	if res.Valid {
		statusText = "VALID (Least-Privilege Compliant)"
	}
	sb.WriteString(fmt.Sprintf("Status: %s\n", statusText))

	if len(res.Warnings) > 0 {
		sb.WriteString("\n[!] Security Warnings:\n")
		for _, w := range res.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", w))
		}
	}
	if len(res.Recommendations) > 0 {
		sb.WriteString("\n[*] Hardening Recommendations:\n")
		for _, r := range res.Recommendations {
			sb.WriteString(fmt.Sprintf("  - %s\n", r))
		}
	}

	exitCode := report.ExitOK
	if !res.Valid {
		exitCode = report.ExitCriticalFound
	}

	return &RunResult{
		Target:          p.cfg.VerifyPolicy,
		ExitCode:        exitCode,
		FormattedOutput: sb.String(),
	}, nil
}

func (p *Pipeline) resolveOwnerRepo() (string, string) {
	owner := "OWNER"
	repo := "REPO"
	if p.cfg.Repo != "" {
		parts := strings.Split(p.cfg.Repo, "/")
		if len(parts) == 2 {
			owner = parts[0]
			repo = parts[1]
		}
	}
	return owner, repo
}
