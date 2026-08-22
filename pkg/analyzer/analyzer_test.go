package analyzer_test

import (
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

			findings := engine.AnalyzeWorkflow(wf)
			if len(findings) > 0 {
				t.Errorf("false positive detected in safe fixture %s: %+v", file, findings)
			}
		})
	}
}
