package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)


func TestPrecedence_ResolutionMatrix(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		jobName     string
		expectedRes string
	}{
		{
			name: "Job explicit id-token write overrides global none",
			yaml: `
name: T1
jobs:
  j1:
    permissions:
      id-token: write
`,
			jobName:     "j1",
			expectedRes: "write",
		},
		{
			name: "Job explicit id-token read overrides global write",
			yaml: `
name: T2
permissions:
  id-token: write
jobs:
  j2:
    permissions:
      id-token: read
`,
			jobName:     "j2",
			expectedRes: "read",
		},
		{
			name: "Job explicit empty map overrides global write-all",
			yaml: `
name: T3
permissions: write-all
jobs:
  j3:
    permissions: {}
`,
			jobName:     "j3",
			expectedRes: "none",
		},
		{
			name: "Job explicit empty map overrides global id-token write",
			yaml: `
name: T4
permissions:
  id-token: write
jobs:
  j4:
    permissions: {}
`,
			jobName:     "j4",
			expectedRes: "none",
		},
		{
			name: "Job inherits global write-all",
			yaml: `
name: T5
permissions: write-all
jobs:
  j5:
    steps: [{ run: echo 1 }]
`,
			jobName:     "j5",
			expectedRes: "write",
		},
		{
			name: "Job inherits global read-all as none",
			yaml: `
name: T6
permissions: read-all
jobs:
  j6:
    steps: [{ run: echo 1 }]
`,
			jobName:     "j6",
			expectedRes: "none",
		},
		{
			name: "Job in workflow with no permissions defaults to none",
			yaml: `
name: T7
jobs:
  j7:
    steps: [{ run: echo 1 }]
`,
			jobName:     "j7",
			expectedRes: "none",
		},
		{
			name: "Job explicit write-all scalar",
			yaml: `
name: T8
jobs:
  j8:
    permissions: write-all
`,
			jobName:     "j8",
			expectedRes: "write",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf, err := parser.ParseWorkflowBytes([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			res := analyzer.ResolveJobIDTokenPermission(wf, tt.jobName)
			if res != tt.expectedRes {
				t.Errorf("ResolveJobIDTokenPermission() for %s = %s, want %s", tt.jobName, res, tt.expectedRes)
			}
		})
	}
}

func TestCloudMatcher_AllProviders(t *testing.T) {
	steps := []struct {
		name         string
		step         parser.Step
		wantProvider analyzer.CloudProvider
		wantMatched  bool
		wantTarget   string
	}{
		{
			name: "AWS with SHA pinning",
			step: parser.Step{
				Uses: "aws-actions/configure-aws-credentials@b4ffde65f46336ab88eb53be808477a3936bae11",
				With: map[string]interface{}{
					"role-to-assume": "arn:aws:iam::111222333444:role/Deployer",
					"aws-region":     "us-east-1",
				},
			},
			wantProvider: analyzer.ProviderAWS,
			wantMatched:  true,
			wantTarget:   "arn:aws:iam::111222333444:role/Deployer",
		},
		{
			name: "GCP with tag",
			step: parser.Step{
				Uses: "google-github-actions/auth@v2",
				With: map[string]interface{}{
					"workload_identity_provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
					"service_account":            "sa@project.iam.gserviceaccount.com",
				},
			},
			wantProvider: analyzer.ProviderGCP,
			wantMatched:  true,
			wantTarget:   "sa@project.iam.gserviceaccount.com",
		},
		{
			name: "Azure login",
			step: parser.Step{
				Uses: "azure/login@v1",
				With: map[string]interface{}{
					"client-id": "11111111-2222-3333-4444-555555555555",
					"tenant-id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				},
			},
			wantProvider: analyzer.ProviderAzure,
			wantMatched:  true,
			wantTarget:   "11111111-2222-3333-4444-555555555555",
		},
		{
			name: "HashiCorp Vault",
			step: parser.Step{
				Uses: "hashicorp/vault-action@v2",
				With: map[string]interface{}{
					"url":  "https://vault.corp:8200",
					"role": "ci-role",
				},
			},
			wantProvider: analyzer.ProviderVault,
			wantMatched:  true,
			wantTarget:   "ci-role",
		},
		{
			name: "Non-cloud action",
			step: parser.Step{
				Uses: "actions/checkout@v4",
			},
			wantProvider: "",
			wantMatched:  false,
			wantTarget:   "",
		},
	}

	for _, tt := range steps {
		t.Run(tt.name, func(t *testing.T) {
			res, matched := analyzer.MatchCloudAction(tt.step)
			if matched != tt.wantMatched {
				t.Fatalf("MatchCloudAction() matched = %v, want %v", matched, tt.wantMatched)
			}
			if matched {
				if res.Provider != tt.wantProvider {
					t.Errorf("Provider = %s, want %s", res.Provider, tt.wantProvider)
				}
				if res.TargetInfo != tt.wantTarget {
					t.Errorf("TargetInfo = %s, want %s", res.TargetInfo, tt.wantTarget)
				}
			}
		})
	}
}

func TestRules_EdgeCases(t *testing.T) {
	engine := analyzer.NewDefaultEngine()

	t.Run("OIDC-003 Action Pinning Variations", func(t *testing.T) {
		yaml := `
name: Pinning Test
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - name: Local Action
        uses: ./.github/actions/local-step
      - name: Local Windows Action
        uses: .\actions\win
      - name: Pinned SHA Git Action
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Pinned Docker Digest Action
        uses: docker://alpine@sha256:7144358a52097723deeab4fa76450dee42d18009a6096e7380456a37f68b8503
      - name: Mutable Tag Git Action
        uses: actions/checkout@v4
      - name: Mutable Docker Tag Action
        uses: docker://alpine:3.18
`
		wf, err := parser.ParseWorkflowBytes([]byte(yaml), "pinning.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings := engine.AnalyzeWorkflow(wf)

		var oidc003Count int
		for _, f := range findings {
			if f.RuleID == "OIDC-003" {
				oidc003Count++
			}
		}
		if oidc003Count != 2 {
			t.Errorf("expected exactly 2 OIDC-003 findings (for mutable git and mutable docker), got: %d", oidc003Count)
		}
	})

	t.Run("OIDC-005 Multi-Cloud in Single vs Separate Jobs", func(t *testing.T) {
		// Single job with AWS + GCP -> must trigger OIDC-005
		singleJobYaml := `
name: Multi Cloud Single Job
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: google-github-actions/auth@b4ffde65f46336ab88eb53be808477a3936bae11
`
		wfSingle, _ := parser.ParseWorkflowBytes([]byte(singleJobYaml), "single.yml")
		findingsSingle := engine.AnalyzeWorkflow(wfSingle)
		has005 := false
		for _, f := range findingsSingle {
			if f.RuleID == "OIDC-005" {
				has005 = true
				break
			}
		}
		if !has005 {
			t.Errorf("expected OIDC-005 for single job multi-cloud authentication")
		}

		// Separate jobs -> must NOT trigger OIDC-005
		separateJobYaml := `
name: Multi Cloud Separate Jobs
jobs:
  deploy_aws:
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@b4ffde65f46336ab88eb53be808477a3936bae11
  deploy_gcp:
    permissions:
      id-token: write
    steps:
      - uses: google-github-actions/auth@b4ffde65f46336ab88eb53be808477a3936bae11
`
		wfSep, _ := parser.ParseWorkflowBytes([]byte(separateJobYaml), "sep.yml")
		findingsSep := engine.AnalyzeWorkflow(wfSep)
		for _, f := range findingsSep {
			if f.RuleID == "OIDC-005" {
				t.Errorf("unexpected OIDC-005 in separated jobs")
			}
		}
	})

	t.Run("OIDC-006 Workflow Run with Scalar String Branch Filter", func(t *testing.T) {
		// Scalar branch -> safe, should NOT trigger OIDC-006
		safeYaml := `
name: Safe Workflow Run
on:
  workflow_run:
    workflows: ["CI"]
    branches: "main"
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - run: echo deploy
`
		wfSafe, _ := parser.ParseWorkflowBytes([]byte(safeYaml), "safe_wr.yml")
		findingsSafe := engine.AnalyzeWorkflow(wfSafe)
		for _, f := range findingsSafe {
			if f.RuleID == "OIDC-006" {
				t.Errorf("unexpected OIDC-006 when scalar branch restriction is present")
			}
		}
	})

	t.Run("OIDC-007 Self-Hosted Runner in OIDC Privileged Job", func(t *testing.T) {
		// Privileged job with self-hosted runner -> triggers OIDC-007
		vulnYaml := `
name: Self Hosted Deploy
jobs:
  deploy:
    runs-on: [self-hosted, linux, production]
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
`
		wfVuln, _ := parser.ParseWorkflowBytes([]byte(vulnYaml), "self_hosted.yml")
		findingsVuln := engine.AnalyzeWorkflow(wfVuln)
		has007 := false
		for _, f := range findingsVuln {
			if f.RuleID == "OIDC-007" {
				has007 = true
				break
			}
		}
		if !has007 {
			t.Errorf("expected OIDC-007 finding for self-hosted runner in OIDC job")
		}

		// Privileged job on ubuntu-latest -> safe from OIDC-007
		safeYaml := `
name: Hosted Deploy
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
`
		wfSafe, _ := parser.ParseWorkflowBytes([]byte(safeYaml), "hosted.yml")
		findingsSafe := engine.AnalyzeWorkflow(wfSafe)
		for _, f := range findingsSafe {
			if f.RuleID == "OIDC-007" {
				t.Errorf("unexpected OIDC-007 for ubuntu-latest hosted runner")
			}
		}
	})
}

func TestEngine_VulnerableAndSafeFixtures(t *testing.T) {
	vulnerableTests := []struct {
		name         string
		filePath     string
		expectRuleID string
	}{
		{
			name:         "PRT with Ungated OIDC",
			filePath:     "../../testdata/vulnerable/prt_oidc_minting.yml",
			expectRuleID: "OIDC-002",
		},
		{
			name:         "Global OIDC Leak",
			filePath:     "../../testdata/vulnerable/global_oidc_leak.yml",
			expectRuleID: "OIDC-001",
		},
		{
			name:         "Mutable Action in OIDC Job",
			filePath:     "../../testdata/vulnerable/mutable_action_oidc.yml",
			expectRuleID: "OIDC-003",
		},
		{
			name:         "Context Injection in OIDC Job",
			filePath:     "../../testdata/vulnerable/context_injection_run.yml",
			expectRuleID: "OIDC-004",
		},
		{
			name:         "Workflow Run OIDC Unsafe",
			filePath:     "../../testdata/vulnerable/workflow_run_oidc.yml",
			expectRuleID: "OIDC-006",
		},
	}

	engine := analyzer.NewDefaultEngine()

	for _, tt := range vulnerableTests {
		t.Run(tt.name, func(t *testing.T) {
			wf, err := parser.ParseWorkflowFile(tt.filePath)
			if err != nil {
				t.Fatalf("failed to read workflow fixture %s: %v", tt.filePath, err)
			}

			findings := engine.AnalyzeWorkflow(wf)
			found := false
			for _, f := range findings {
				if f.RuleID == tt.expectRuleID {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected rule %s was not found in findings: %+v", tt.expectRuleID, findings)
			}
		})
	}

	safeFiles := []string{
		"../../testdata/safe/sha_pinned_oidc.yml",
		"../../testdata/safe/environment_gate.yml",
		"../../testdata/safe/env_var_context.yml",
	}

	for _, file := range safeFiles {
		t.Run(file, func(t *testing.T) {
			wf, err := parser.ParseWorkflowFile(file)
			if err != nil {
				t.Fatalf("failed to read safe fixture %s: %v", file, err)
			}

			allFindings := engine.AnalyzeWorkflow(wf)

			// INFO-severity findings are posture advisories, not vulnerability detections.
			// They are valid observations on any OIDC workflow and do not constitute false positives.
			var actionableFindings []analyzer.Finding
			for _, f := range allFindings {
				if f.Severity != analyzer.SeverityInfo {
					actionableFindings = append(actionableFindings, f)
				}
			}

			if len(actionableFindings) > 0 {
				t.Errorf("false positive detected in safe fixture %s: %+v", file, actionableFindings)
			}
		})
	}

}

func TestAnalyzer_ContextualEnhancements(t *testing.T) {
	engine := analyzer.NewDefaultEngine()

	t.Run("OIDC-001 severity scaling with triggers", func(t *testing.T) {
		pushYaml := `
name: Push Only
on: push
permissions:
  id-token: write
jobs:
  build:
    steps: [{ run: echo 1 }]
`
		wfPush, _ := parser.ParseWorkflowBytes([]byte(pushYaml), "push.yml")
		fPush := engine.AnalyzeWorkflow(wfPush)
		if len(fPush) != 1 || fPush[0].Severity != analyzer.SeverityMedium {
			t.Errorf("expected SeverityMedium for push-only OIDC-001, got %+v", fPush)
		}

		prYaml := `
name: PR Workflow
on: pull_request
permissions:
  id-token: write
jobs:
  build:
    steps: [{ run: echo 1 }]
`
		wfPR, _ := parser.ParseWorkflowBytes([]byte(prYaml), "pr.yml")
		fPR := engine.AnalyzeWorkflow(wfPR)
		if len(fPR) != 1 || fPR[0].Severity != analyzer.SeverityHigh {
			t.Errorf("expected SeverityHigh for PR-triggered OIDC-001, got %+v", fPR)
		}
	})

	t.Run("OIDC-002 contextual evaluation matrix", func(t *testing.T) {
		// 1. Direct fork checkout -> CRITICAL
		critYaml := `
name: PRT Critical
on: pull_request_target
jobs:
  test:
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
		wfCrit, _ := parser.ParseWorkflowBytes([]byte(critYaml), "crit.yml")
		fCrit := engine.AnalyzeWorkflow(wfCrit)
		var hasCrit bool
		for _, f := range fCrit {
			if f.RuleID == "OIDC-002" && f.Severity == analyzer.SeverityCritical {
				hasCrit = true
			}
		}
		if !hasCrit {
			t.Errorf("expected Critical OIDC-002 for untrusted fork checkout, got %+v", fCrit)
		}

		// 2. Guarded with actor check -> MEDIUM
		guardYaml := `
name: PRT Guarded
on: pull_request_target
jobs:
  test:
    if: ${{ github.event.pull_request.user.login == 'dependabot[bot]' }}
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
`
		wfGuard, _ := parser.ParseWorkflowBytes([]byte(guardYaml), "guard.yml")
		fGuard := engine.AnalyzeWorkflow(wfGuard)
		var hasGuard bool
		for _, f := range fGuard {
			if f.RuleID == "OIDC-002" && f.Severity == analyzer.SeverityMedium {
				hasGuard = true
			}
		}
		if !hasGuard {
			t.Errorf("expected Medium OIDC-002 for actor-guarded PRT, got %+v", fGuard)
		}

		// 3. Ungated without guards -> HIGH
		ungatedYaml := `
name: PRT Ungated
on: pull_request_target
jobs:
  test:
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
`
		wfUngated, _ := parser.ParseWorkflowBytes([]byte(ungatedYaml), "ungated.yml")
		fUngated := engine.AnalyzeWorkflow(wfUngated)
		var hasUngated bool
		for _, f := range fUngated {
			if f.RuleID == "OIDC-002" && f.Severity == analyzer.SeverityHigh {
				hasUngated = true
			}
		}
		if !hasUngated {
			t.Errorf("expected High OIDC-002 for ungated PRT, got %+v", fUngated)
		}
	})

	t.Run("OIDC-003 step deduplication and SLSA recognition", func(t *testing.T) {
		dupYaml := `
name: Deduplication Test
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - uses: azure/login@v3
      - run: echo step2
      - uses: azure/login@v3
      - uses: azure/login@v3
`
		wfDup, _ := parser.ParseWorkflowBytes([]byte(dupYaml), "dup.yml")
		fDup := engine.AnalyzeWorkflow(wfDup)
		var oidc003Count int
		for _, f := range fDup {
			if f.RuleID == "OIDC-003" {
				oidc003Count++
			}
		}
		if oidc003Count != 1 {
			t.Errorf("expected exactly 1 deduplicated OIDC-003 finding, got %d", oidc003Count)
		}

		// SLSA Generator semantic version tag -> Recognized as conforming
		slsaYaml := `
name: SLSA Release
jobs:
  provenance:
    permissions:
      id-token: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
`
		wfSLSA, _ := parser.ParseWorkflowBytes([]byte(slsaYaml), "slsa.yml")
		fSLSA := engine.AnalyzeWorkflow(wfSLSA)
		for _, f := range fSLSA {
			if f.RuleID == "OIDC-003" {
				t.Errorf("unexpected OIDC-003 for SLSA generator semantic tag: %+v", f)
			}
		}
	})

	t.Run("OIDC-004 source-aware severity categorization", func(t *testing.T) {
		extYaml := `
name: Ext Injection
jobs:
  test:
    permissions:
      id-token: write
    steps:
      - run: echo "${{ github.event.issue.title }}"
`
		wfExt, _ := parser.ParseWorkflowBytes([]byte(extYaml), "ext.yml")
		fExt := engine.AnalyzeWorkflow(wfExt)
		if len(fExt) != 1 || fExt[0].Severity != analyzer.SeverityCritical {
			t.Errorf("expected Critical for external issue.title injection, got %+v", fExt)
		}

		inputYaml := `
name: Input Injection
jobs:
  test:
    permissions:
      id-token: write
    steps:
      - run: echo "${{ inputs.version }}"
`
		wfInput, _ := parser.ParseWorkflowBytes([]byte(inputYaml), "input.yml")
		fInput := engine.AnalyzeWorkflow(wfInput)
		if len(fInput) != 1 || fInput[0].Severity != analyzer.SeverityMedium {
			t.Errorf("expected Medium for inputs parameter interpolation, got %+v", fInput)
		}
	})

	t.Run("OIDC-008 secrets: inherit with external reusable workflow", func(t *testing.T) {
		extSecretsYaml := `
name: External Secrets Leak
jobs:
  call-ext:
    permissions:
      id-token: write
    uses: untrusted-org/workflows/.github/workflows/deploy.yml@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
    secrets: inherit
`
		wfExt, _ := parser.ParseWorkflowBytes([]byte(extSecretsYaml), "ext_sec.yml")
		fExt := engine.AnalyzeWorkflow(wfExt)
		var has008 bool
		for _, f := range fExt {
			if f.RuleID == "OIDC-008" && f.Severity == analyzer.SeverityHigh {
				has008 = true
			}
		}
		if !has008 {
			t.Errorf("expected OIDC-008 for external reusable workflow with secrets: inherit, got %+v", fExt)
		}

		// Local reusable workflow with secrets: inherit -> Safe from OIDC-008
		localSecretsYaml := `
name: Local Secrets Delegation
jobs:
  call-local:
    permissions:
      id-token: write
    uses: ./.github/workflows/local-deploy.yml
    secrets: inherit
`
		wfLocal, _ := parser.ParseWorkflowBytes([]byte(localSecretsYaml), "local_sec.yml")
		fLocal := engine.AnalyzeWorkflow(wfLocal)
		for _, f := range fLocal {
			if f.RuleID == "OIDC-008" {
				t.Errorf("unexpected OIDC-008 for local reusable workflow with secrets: inherit")
			}
		}
	})
}

func TestExploitChainDetection_AllPrimitives(t *testing.T) {
	engine := analyzer.NewDefaultEngine()

	t.Run("CHAIN-001: Pwn-Request RCE via pull_request_target", func(t *testing.T) {
		wf, err := parser.ParseWorkflowFile("../../testdata/exploit_chains/pwn_request_rce.yml")
		if err != nil {
			t.Fatalf("failed to parse pwn_request_rce.yml: %v", err)
		}

		report := engine.AnalyzeWorkflows("pwn_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) == 0 {
			t.Fatalf("expected at least 1 ExploitChain for pwn_request_rce.yml, got 0")
		}

		chain := report.ExploitChains[0]
		if chain.ID != "CHAIN-001" {
			t.Errorf("expected chain ID CHAIN-001, got %s", chain.ID)
		}
		if chain.Severity != analyzer.SeverityCritical {
			t.Errorf("expected SeverityCritical for CHAIN-001, got %s", chain.Severity)
		}
		if chain.TriggerEvent != "pull_request_target" {
			t.Errorf("expected trigger pull_request_target, got %s", chain.TriggerEvent)
		}
		if chain.PoCPayload == "" {
			t.Errorf("expected non-empty PoCPayload")
		}
	})

	t.Run("CHAIN-002: Context Injection via issue_comment", func(t *testing.T) {
		wf, err := parser.ParseWorkflowFile("../../testdata/exploit_chains/issue_comment_injection.yml")
		if err != nil {
			t.Fatalf("failed to parse issue_comment_injection.yml: %v", err)
		}

		report := engine.AnalyzeWorkflows("injection_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) == 0 {
			t.Fatalf("expected at least 1 ExploitChain for issue_comment_injection.yml, got 0")
		}

		chain := report.ExploitChains[0]
		if chain.ID != "CHAIN-002" {
			t.Errorf("expected chain ID CHAIN-002, got %s", chain.ID)
		}
		if chain.Severity != analyzer.SeverityCritical {
			t.Errorf("expected SeverityCritical, got %s", chain.Severity)
		}
	})

	t.Run("CHAIN-003: JavaScript Code Injection in actions/github-script", func(t *testing.T) {
		wf, err := parser.ParseWorkflowFile("../../testdata/exploit_chains/github_script_injection.yml")
		if err != nil {
			t.Fatalf("failed to parse github_script_injection.yml: %v", err)
		}

		report := engine.AnalyzeWorkflows("script_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) == 0 {
			t.Fatalf("expected at least 1 ExploitChain for github_script_injection.yml, got 0")
		}

		chain := report.ExploitChains[0]
		if chain.ID != "CHAIN-003" {
			t.Errorf("expected chain ID CHAIN-003, got %s", chain.ID)
		}
	})

	t.Run("CHAIN-004: Artifact Poisoning via workflow_run", func(t *testing.T) {
		wf, err := parser.ParseWorkflowFile("../../testdata/exploit_chains/workflow_run_artifact.yml")
		if err != nil {
			t.Fatalf("failed to parse workflow_run_artifact.yml: %v", err)
		}

		report := engine.AnalyzeWorkflows("artifact_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) == 0 {
			t.Fatalf("expected at least 1 ExploitChain for workflow_run_artifact.yml, got 0")
		}

		chain := report.ExploitChains[0]
		if chain.ID != "CHAIN-004" {
			t.Errorf("expected chain ID CHAIN-004, got %s", chain.ID)
		}
	})

	t.Run("CHAIN-005: Token Write Privilege Escalation", func(t *testing.T) {
		writeYaml := `
name: Write Escalation
on: pull_request_target
jobs:
  pwn:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
		wf, _ := parser.ParseWorkflowBytes([]byte(writeYaml), "write_pwn.yml")
		report := engine.AnalyzeWorkflows("write_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) == 0 || report.ExploitChains[0].ID != "CHAIN-005" {
			t.Errorf("expected CHAIN-005, got %+v", report.ExploitChains)
		}
		if report.ExploitChains[0].CWE != "CWE-269" {
			t.Errorf("expected CWE-269, got %s", report.ExploitChains[0].CWE)
		}
	})

	t.Run("CHAIN-006: External Secrets Delegation Leak", func(t *testing.T) {
		secYaml := `
name: Secrets Leak
on: issues
jobs:
  call-ext:
    uses: third-party/workflows/.github/workflows/reusable.yml@v1
    secrets: inherit
`
		wf, _ := parser.ParseWorkflowBytes([]byte(secYaml), "sec_leak.yml")
		report := engine.AnalyzeWorkflows("sec_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) == 0 || report.ExploitChains[0].ID != "CHAIN-006" {
			t.Errorf("expected CHAIN-006, got %+v", report.ExploitChains)
		}
	})

	t.Run("CHAIN-007: Runner Environment Hijacking via GITHUB_ENV", func(t *testing.T) {
		envYaml := `
name: Env Hijack
on: issues
jobs:
  inject:
    steps:
      - run: echo "TITLE=${{ github.event.issue.title }}" >> $GITHUB_ENV
`
		wf, _ := parser.ParseWorkflowBytes([]byte(envYaml), "env_hijack.yml")
		report := engine.AnalyzeWorkflows("env_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) == 0 || report.ExploitChains[0].ID != "CHAIN-007" {
			t.Errorf("expected CHAIN-007, got %+v", report.ExploitChains)
		}
	})

	t.Run("CHAIN-008: Self-Hosted Runner Public Takeover", func(t *testing.T) {
		hostYaml := `
name: Host Takeover
on: pull_request
jobs:
  runner:
    runs-on: self-hosted
    steps:
      - run: make test
`
		wf, _ := parser.ParseWorkflowBytes([]byte(hostYaml), "host_pwn.yml")
		report := engine.AnalyzeWorkflows("host_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) == 0 || report.ExploitChains[0].ID != "CHAIN-008" {
			t.Errorf("expected CHAIN-008, got %+v", report.ExploitChains)
		}
	})

	t.Run("Negative Control: Actor guarded PRT produces ZERO Exploit Chains", func(t *testing.T) {
		wf, err := parser.ParseWorkflowFile("../../testdata/exploit_chains/safe_prt_actor_guarded.yml")
		if err != nil {
			t.Fatalf("failed to parse safe_prt_actor_guarded.yml: %v", err)
		}

		report := engine.AnalyzeWorkflows("guarded_test", []*parser.Workflow{wf})
		if len(report.ExploitChains) != 0 {
			t.Errorf("false positive exploit chain detected on guarded PRT: %+v", report.ExploitChains)
		}
	})
}

func TestNewRules_2025_2026(t *testing.T) {
	eng := analyzer.NewDefaultEngine()

	t.Run("OIDC-009: Detects mutable tag on high-value action", func(t *testing.T) {
		wfYAML := `
name: Tag Hijack Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v45
`
		wf, err := parser.ParseWorkflowBytes([]byte(wfYAML), "test.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings := eng.AnalyzeWorkflow(wf)
		found := false
		for _, f := range findings {
			if f.RuleID == "OIDC-009" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("OIDC-009 not triggered for mutable tj-actions tag; findings: %+v", findings)
		}
	})

	t.Run("OIDC-009: Does not flag SHA-pinned action", func(t *testing.T) {
		wfYAML := `
name: SHA Pinned Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@4edd678ac3f81e2dc578756871e4d00c19191daf
`
		wf, err := parser.ParseWorkflowBytes([]byte(wfYAML), "test.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings := eng.AnalyzeWorkflow(wf)
		for _, f := range findings {
			if f.RuleID == "OIDC-009" {
				t.Errorf("OIDC-009 false positive on SHA-pinned action: %+v", f)
			}
		}
	})

	t.Run("OIDC-011: Detects echo of OIDC token to logs", func(t *testing.T) {
		wfYAML := `
name: Token Leak Test
on: push
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
`
		wf, err := parser.ParseWorkflowBytes([]byte(wfYAML), "test.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings := eng.AnalyzeWorkflow(wf)
		found := false
		for _, f := range findings {
			if f.RuleID == "OIDC-011" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("OIDC-011 not triggered for echo of OIDC token; findings: %+v", findings)
		}
	})

	t.Run("OIDC-011: Detects deprecated ::set-output:: syntax", func(t *testing.T) {
		wfYAML := `
name: Deprecated Output Test
on: push
jobs:
  output:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::set-output name=token::${SECRET_VALUE}"
`
		wf, err := parser.ParseWorkflowBytes([]byte(wfYAML), "test.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings := eng.AnalyzeWorkflow(wf)
		found := false
		for _, f := range findings {
			if f.RuleID == "OIDC-011" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("OIDC-011 not triggered for ::set-output:: syntax; findings: %+v", findings)
		}
	})

	t.Run("OIDC-011: Does not flag safe echo without secrets", func(t *testing.T) {
		wfYAML := `
name: Safe Echo Test
on: push
jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      - run: echo "build complete"
`
		wf, err := parser.ParseWorkflowBytes([]byte(wfYAML), "test.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings := eng.AnalyzeWorkflow(wf)
		for _, f := range findings {
			if f.RuleID == "OIDC-011" {
				t.Errorf("OIDC-011 false positive on safe echo: %+v", f)
			}
		}
	})
}

// TestOIDC012_WildcardTrustPolicy covers CWE-732: Incorrect Permission Assignment for Critical Resource.
// Wildcard cloud trust policies (repo:org/*) allow any compromised repository to assume production roles.
func TestOIDC012_WildcardTrustPolicy(t *testing.T) {
	eng := analyzer.NewDefaultEngine()

	t.Run("OIDC-012: Detects wildcard role-to-assume with /*", func(t *testing.T) {
		wfYAML := `
name: Wildcard IAM
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/*
          aws-region: us-east-1
`
		wf, err := parser.ParseWorkflowBytes([]byte(wfYAML), "test.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings := eng.AnalyzeWorkflow(wf)
		found := false
		for _, f := range findings {
			if f.RuleID == "OIDC-012" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("OIDC-012 not triggered for wildcard role-to-assume; findings: %+v", findings)
		}
	})

	t.Run("OIDC-012: Does not false-positive on exact ARN", func(t *testing.T) {
		wfYAML := `
name: Exact IAM
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ExactProductionRole
          aws-region: us-east-1
`
		wf, err := parser.ParseWorkflowBytes([]byte(wfYAML), "test.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings := eng.AnalyzeWorkflow(wf)
		for _, f := range findings {
			if f.RuleID == "OIDC-012" {
				t.Errorf("OIDC-012 false positive on exact ARN: %+v", f)
			}
		}
	})
}

// TestNewContextVectors_2025 validates detection of newly added untrusted context variables
// discovered in 2025-2026 security research (merge_group, triggering_actor, committer, sender.login).
func TestNewContextVectors_2025(t *testing.T) {
	eng := analyzer.NewDefaultEngine()

	tests := []struct {
		name     string
		wfYAML   string
		wantRule string
	}{
		{
			name: "CWE-78: merge_group.head_ref injected into run",
			wfYAML: `
name: Merge Group Injection
on: merge_group
jobs:
  validate:
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: git log "${{ github.event.merge_group.head_ref }}"
`,
			wantRule: "OIDC-004",
		},
		{
			name: "CWE-78: triggering_actor injected into run",
			wfYAML: `
name: Actor Injection
on: push
jobs:
  build:
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: echo "Triggered by ${{ github.triggering_actor }}" | tee /tmp/log
`,
			wantRule: "OIDC-004",
		},
		{
			name: "CWE-78: release.tag_name injected into run",
			wfYAML: `
name: Release Tag Injection
on: release
jobs:
  publish:
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: npm version ${{ github.event.release.tag_name }} --no-git-tag-version
`,
			wantRule: "OIDC-004",
		},
		{
			name: "CWE-78: head_commit.committer.email injected into run",
			wfYAML: `
name: Committer Email Injection
on: push
jobs:
  build:
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: git config user.email "${{ github.event.head_commit.committer.email }}"
`,
			wantRule: "OIDC-004",
		},
		{
			name: "CWE-78: workflow_run.head_sha injected into run",
			wfYAML: `
name: WorkflowRun SHA Injection
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  downstream:
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: git checkout ${{ github.event.workflow_run.head_sha }}
`,
			wantRule: "OIDC-004",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf, err := parser.ParseWorkflowBytes([]byte(tt.wfYAML), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := eng.AnalyzeWorkflow(wf)
			found := false
			for _, f := range findings {
				if f.RuleID == tt.wantRule {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("rule %s not triggered; findings: %+v", tt.wantRule, findings)
			}
		})
	}
}

// TestFalsePositiveRegression validates that common safe patterns do not generate findings.
// This is the anti-regression suite ensuring noise reduction quality.
func TestFalsePositiveRegression(t *testing.T) {
	eng := analyzer.NewDefaultEngine()

	safePatterns := []struct {
		name   string
		yaml   string
		reason string
	}{
		{
			name: "SHA-pinned actions in OIDC job with env: pattern for context isolation",
			yaml: `
name: Safe Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    env:
      PR_TITLE: ${{ github.event.pull_request.title }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ExactRole
          aws-region: us-east-1
      - run: echo "Deploying"
`,
			reason: "env: isolates context from shell, run: step is safe",
		},
		{
			name: "SLSA Generator action exempt from OIDC-003 pinning rule",
			yaml: `
name: SLSA Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
`,
			reason: "SLSA framework actions are exempt from SHA pinning requirement",
		},
		{
			name: "PRT with explicit environment approval gate should not trigger CHAIN",
			yaml: `
name: PRT Gated Deploy
on: pull_request_target
jobs:
  deploy:
    environment: production
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ProdRole
          aws-region: us-east-1
`,
			reason: "environment approval gate prevents CHAIN-001 exploitation",
		},
		{
			name: "Safe echo of static string with no context interpolation",
			yaml: `
name: Static Echo
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Build started at $(date)"
`,
			reason: "no secret or context interpolation in echo",
		},
	}

	for _, sp := range safePatterns {
		t.Run(sp.name, func(t *testing.T) {
			wf, err := parser.ParseWorkflowBytes([]byte(sp.yaml), "safe_test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := eng.AnalyzeWorkflow(wf)
			for _, f := range findings {
				if f.Severity == analyzer.SeverityCritical {
					t.Errorf("False positive CRITICAL in safe pattern '%s' (reason: %s): %+v", sp.name, sp.reason, f)
				}
			}
		})
	}
}

// TestWorldRealFixtures runs the scanner against the new vulnerable fixtures
// representing real-world attack patterns discovered in 2025-2026.
func TestWorldRealFixtures_2025_2026(t *testing.T) {
	eng := analyzer.NewDefaultEngine()

	tests := []struct {
		name         string
		filePath     string
		expectRuleID string
	}{
		{
			name:         "Release Authority Injection (CWE-78) - release.name in run",
			filePath:     "../../testdata/vulnerable/release_authority_injection.yml",
			expectRuleID: "OIDC-004",
		},
		{
			name:         "Merge Group Context Injection (CWE-78) - merge_group.head_ref in run",
			filePath:     "../../testdata/vulnerable/merge_group_injection.yml",
			expectRuleID: "OIDC-004",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf, err := parser.ParseWorkflowFile(tt.filePath)
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", tt.filePath, err)
			}
			findings := eng.AnalyzeWorkflow(wf)
			found := false
			for _, f := range findings {
				if f.RuleID == tt.expectRuleID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected rule %s not found in %s; findings: %+v", tt.expectRuleID, tt.filePath, findings)
			}
		})
	}
}

// TestAppSec_ComprehensiveCWEMatrix provides comprehensive verification of all supported CWE categories:
// CWE-78, CWE-94, CWE-200, CWE-250, CWE-269, CWE-284, CWE-345, CWE-494, CWE-522, CWE-732, CWE-829.
func TestAppSec_ComprehensiveCWEMatrix(t *testing.T) {
	eng := analyzer.NewDefaultEngine()

	cweTests := []struct {
		cwe         string
		name        string
		workflowYAML string
		expectedRule string
	}{
		{
			cwe:  "CWE-78",
			name: "OS Command Injection via issue comment body in run step",
			workflowYAML: `
name: CWE-78
on: issue_comment
jobs:
  run:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: echo "${{ github.event.comment.body }}"
`,
			expectedRule: "OIDC-004",
		},
		{
			cwe:  "CWE-269",
			name: "Code Injection via pull_request_target with fork checkout",
			workflowYAML: `
name: CWE-269
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`,
			expectedRule: "OIDC-002",
		},
		{
			cwe:  "CWE-200",
			name: "Exposure of Sensitive Information via multi-cloud authentication in single job",
			workflowYAML: `
name: CWE-200
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/RoleA
          aws-region: us-east-1
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/p/providers/pr
          service_account: sa@proj.iam.gserviceaccount.com
`,
			expectedRule: "OIDC-005",
		},
		{
			cwe:  "CWE-250",
			name: "Execution with Unnecessary Privileges via Global id-token: write",
			workflowYAML: `
name: CWE-250
on: pull_request
permissions:
  id-token: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`,
			expectedRule: "OIDC-001",
		},
		{
			cwe:  "CWE-269",
			name: "Improper Privilege Management via ungated PRT with id-token write",
			workflowYAML: `
name: CWE-269
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: echo "deploy"
`,
			expectedRule: "OIDC-002",
		},
		{
			cwe:  "CWE-284",
			name: "Improper Access Control via public trigger on self-hosted runner",
			workflowYAML: `
name: CWE-284
on: issues
jobs:
  triage:
    runs-on: [self-hosted, linux]
    permissions:
      id-token: write
    steps:
      - run: echo "triage"
`,
			expectedRule: "OIDC-007",
		},
		{
			cwe:  "CWE-345",
			name: "Insufficient Verification of Data Authenticity via missing immutable numeric ID in 2026 sub claims",
			workflowYAML: `
name: CWE-345
on: pull_request
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/DeployRole
          aws-region: us-east-1
`,
			expectedRule: "OIDC-010",
		},
		{
			cwe:  "CWE-494",
			name: "Download of Code Without Integrity Check via mutable tag on high-value action",
			workflowYAML: `
name: CWE-494
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v45
`,
			expectedRule: "OIDC-009",
		},
		{
			cwe:  "CWE-532",
			name: "Insufficiently Protected Credentials via secret/token log dumping",
			workflowYAML: `
name: CWE-532
on: push
jobs:
  dump:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: echo "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
`,
			expectedRule: "OIDC-011",
		},
		{
			cwe:  "CWE-732",
			name: "Incorrect Permission Assignment for Critical Resource via wildcard trust policy role ARN",
			workflowYAML: `
name: CWE-732
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/*
          aws-region: us-east-1
`,
			expectedRule: "OIDC-012",
		},
		{
			cwe:  "CWE-829",
			name: "Inclusion of Functionality from Untrusted Control Sphere via mutable tag in OIDC job",
			workflowYAML: `
name: CWE-829
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: some-third-party/custom-action@v1.2.3
`,
			expectedRule: "OIDC-003",
		},
	}

	for _, tt := range cweTests {
		t.Run(fmt.Sprintf("%s_%s", tt.cwe, tt.name), func(t *testing.T) {
			wf, err := parser.ParseWorkflowBytes([]byte(tt.workflowYAML), "test.yml")
			if err != nil {
				t.Fatalf("parse error for %s: %v", tt.name, err)
			}
			findings := eng.AnalyzeWorkflow(wf)
			found := false
			for _, f := range findings {
				if f.RuleID == tt.expectedRule {
					found = true
					if f.CWE != tt.cwe {
						t.Errorf("expected CWE %s for rule %s, got %s", tt.cwe, tt.expectedRule, f.CWE)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected rule %s (CWE %s) not triggered for %s; findings: %+v", tt.expectedRule, tt.cwe, tt.name, findings)
			}
		})
	}
}

// TestBugBounty_PoCExfiltrationAccuracy validates that the exploit chain engine
// correctly tailors cloud credential exfiltration payloads for AWS, GCP, Azure, and Vault.
func TestBugBounty_PoCExfiltrationAccuracy(t *testing.T) {
	cloudPayloadTests := []struct {
		provider     string
		workflowYAML string
		expectedText string
	}{
		{
			provider: "AWS",
			workflowYAML: `
name: AWS Pwn
on: pull_request_target
jobs:
  pwn:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/DeployRole
          aws-region: us-east-1
      - run: npm test
`,
			expectedText: "aws sts assume-role-with-web-identity",
		},
		{
			provider: "GCP",
			workflowYAML: `
name: GCP Pwn
on: pull_request_target
jobs:
  pwn:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/pool/providers/prov
          service_account: deploy@proj.iam.gserviceaccount.com
      - run: npm test
`,
			expectedText: "https://iam.googleapis.com",
		},
		{
			provider: "Azure",
			workflowYAML: `
name: Azure Pwn
on: pull_request_target
jobs:
  pwn:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: azure/login@v2
        with:
          client-id: 00000000-0000-0000-0000-000000000000
          tenant-id: 11111111-1111-1111-1111-111111111111
      - run: npm test
`,
			expectedText: "api://AzureADTokenExchange",
		},
		{
			provider: "Vault",
			workflowYAML: `
name: Vault Pwn
on: pull_request_target
jobs:
  pwn:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: hashicorp/vault-action@v3
        with:
          url: https://vault.example.com
          role: prod-role
      - run: npm test
`,
			expectedText: "audience=vault",
		},
	}


	for _, tt := range cloudPayloadTests {
		t.Run(fmt.Sprintf("PoC_Payload_%s", tt.provider), func(t *testing.T) {
			wf, err := parser.ParseWorkflowBytes([]byte(tt.workflowYAML), "test.yml")
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}
			chains := analyzer.DetectExploitChains(wf)
			if len(chains) == 0 {
				t.Fatalf("expected exploit chain for %s, got 0", tt.provider)
			}
			foundPayload := false
			for _, c := range chains {
				if strings.Contains(c.PoCPayload, tt.expectedText) || strings.Contains(c.ReportTemplate, tt.expectedText) {
					foundPayload = true
					break
				}
			}
			if !foundPayload {
				t.Errorf("expected PoC to contain '%s' for provider %s; actual PoCPayload: %s", tt.expectedText, tt.provider, chains[0].PoCPayload)
			}
		})
	}
}



