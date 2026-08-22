package remediation_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/remediation"
)

func TestGenerateAWSTrustPolicy_BranchScoping(t *testing.T) {
	yamlContent := `
name: Deploy Main
on:
  push:
    branches: [main]
jobs:
  deploy:
    steps:
      - run: echo deploy
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "deploy.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	job := wf.Jobs["deploy"]
	policyJSON, err := remediation.GenerateAWSTrustPolicy("111222333444", "gamesapeca", "infrastructure-sentinel", wf, &job)
	if err != nil {
		t.Fatalf("failed to generate AWS Trust Policy: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &parsed); err != nil {
		t.Fatalf("generated JSON is invalid: %v", err)
	}

	expectedSub := "repo:gamesapeca/infrastructure-sentinel:ref:refs/heads/main"
	if !strings.Contains(policyJSON, expectedSub) {
		t.Errorf("policy does not contain expected sub claim '%s'. Content:\n%s", expectedSub, policyJSON)
	}

	if !strings.Contains(policyJSON, "sts.amazonaws.com") {
		t.Errorf("policy does not contain audience 'sts.amazonaws.com'")
	}
}

func TestGenerateAWSTrustPolicy_EnvironmentScoping(t *testing.T) {
	yamlContent := `
name: Deploy Prod
on: push
jobs:
  deploy:
    environment: production
    steps:
      - run: echo deploy
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "deploy_prod.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	job := wf.Jobs["deploy"]
	policyJSON, err := remediation.GenerateAWSTrustPolicy("111222333444", "acme-corp", "core-api", wf, &job)
	if err != nil {
		t.Fatalf("failed to generate policy: %v", err)
	}

	expectedSub := "repo:acme-corp/core-api:environment:production"
	if !strings.Contains(policyJSON, expectedSub) {
		t.Errorf("policy does not contain expected environment claim '%s'. Content:\n%s", expectedSub, policyJSON)
	}
}

func TestGenerateGCPWorkloadIdentityAssertion(t *testing.T) {
	yamlContent := `
name: GCP Deploy
on:
  push:
    branches: [release/v1]
jobs:
  deploy_gcp:
    steps:
      - run: echo gcp
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "gcp.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	job := wf.Jobs["deploy_gcp"]
	gcpConfigJSON, err := remediation.GenerateGCPWorkloadIdentityAssertion("987654321098", "prod-pool", "github-prov", "gamesapeca", "gha-oidc-auditor", wf, &job)
	if err != nil {
		t.Fatalf("failed to generate GCP WIF config: %v", err)
	}

	if !strings.Contains(gcpConfigJSON, "assertion.repository == 'gamesapeca/gha-oidc-auditor'") {
		t.Errorf("GCP config missing repository attribute_condition")
	}
	if !strings.Contains(gcpConfigJSON, "assertion.ref == 'refs/heads/release/v1'") {
		t.Errorf("GCP config missing branch restriction in condition")
	}
}

func TestGenerateAzureFederatedCredential(t *testing.T) {
	yamlContent := `
name: Azure Deploy
on: push
jobs:
  deploy_azure:
    environment: staging
    steps:
      - run: echo azure
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "azure.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	job := wf.Jobs["deploy_azure"]
	azureJSON, err := remediation.GenerateAzureFederatedCredential("gamesapeca", "code-flow-analyzer-v6", wf, &job)
	if err != nil {
		t.Fatalf("failed to generate Azure credential: %v", err)
	}

	expectedSub := "repo:gamesapeca/code-flow-analyzer-v6:environment:staging"
	if !strings.Contains(azureJSON, expectedSub) {
		t.Errorf("Azure config does not contain expected subject: '%s'", expectedSub)
	}
}
