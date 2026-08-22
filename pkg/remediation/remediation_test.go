package remediation_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/remediation"
)

type awsStatement struct {
	Effect    string                         `json:"Effect"`
	Principal map[string]string              `json:"Principal"`
	Action    string                         `json:"Action"`
	Condition map[string]map[string]string `json:"Condition"`
}

type awsPolicyDocument struct {
	Version   string         `json:"Version"`
	Statement []awsStatement `json:"Statement"`
}

type gcpWIFDoc struct {
	Name               string            `json:"name"`
	AttributeMapping   map[string]string `json:"attribute_mapping"`
	AttributeCondition string            `json:"attribute_condition"`
	ServiceAccountRole string            `json:"service_account_binding"`
}

type azureDoc struct {
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Description string   `json:"description"`
	Audiences   []string `json:"audiences"`
}

func TestGenerateAWSTrustPolicy_Validation(t *testing.T) {
	t.Run("Branch Scoped", func(t *testing.T) {
		yamlContent := `
name: Deploy Main
on:
  push:
    branches: [main]
jobs:
  deploy:
    steps: [{ run: echo deploy }]
`
		wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "deploy.yml")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		job := wf.Jobs["deploy"]
		policyJSON, err := remediation.GenerateAWSTrustPolicy("111222333444", "gamesapeca", "infrastructure-sentinel", wf, &job)
		if err != nil {
			t.Fatalf("failed to generate AWS policy: %v", err)
		}

		var doc awsPolicyDocument
		if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
			t.Fatalf("failed to parse AWS policy JSON: %v", err)
		}

		if doc.Version != "2012-10-17" {
			t.Errorf("AWS version mismatch: %s", doc.Version)
		}
		if len(doc.Statement) != 1 {
			t.Fatalf("expected 1 statement, got %d", len(doc.Statement))
		}

		stmt := doc.Statement[0]
		if stmt.Effect != "Allow" {
			t.Errorf("Effect = %s, want Allow", stmt.Effect)
		}
		if stmt.Action != "sts:AssumeRoleWithWebIdentity" {
			t.Errorf("Action = %s, want sts:AssumeRoleWithWebIdentity", stmt.Action)
		}

		expectedFederated := "arn:aws:iam::111222333444:oidc-provider/token.actions.githubusercontent.com"
		if stmt.Principal["Federated"] != expectedFederated {
			t.Errorf("Principal = %s, want %s", stmt.Principal["Federated"], expectedFederated)
		}

		stringEquals, ok := stmt.Condition["StringEquals"]
		if !ok {
			t.Fatalf("Condition missing StringEquals operator")
		}

		if stringEquals["token.actions.githubusercontent.com:aud"] != "sts.amazonaws.com" {
			t.Errorf("aud mismatch: %s", stringEquals["token.actions.githubusercontent.com:aud"])
		}

		expectedSub := "repo:gamesapeca/infrastructure-sentinel:ref:refs/heads/main"
		if stringEquals["token.actions.githubusercontent.com:sub"] != expectedSub {
			t.Errorf("sub mismatch: %s, want %s", stringEquals["token.actions.githubusercontent.com:sub"], expectedSub)
		}

		// Ensure no wildcard was injected
		if strings.Contains(policyJSON, "*") {
			t.Errorf("AWS policy contains wildcard '*' which violates strict least-privilege: %s", policyJSON)
		}
	})

	t.Run("Environment Scoped", func(t *testing.T) {
		yamlContent := `
name: Deploy Prod
on: push
jobs:
  deploy:
    environment: production
    steps: [{ run: echo prod }]
`
		wf, _ := parser.ParseWorkflowBytes([]byte(yamlContent), "deploy_prod.yml")
		job := wf.Jobs["deploy"]
		policyJSON, err := remediation.GenerateAWSTrustPolicy("111222333444", "acme-corp", "core-api", wf, &job)
		if err != nil {
			t.Fatalf("failed to generate policy: %v", err)
		}

		var doc awsPolicyDocument
		_ = json.Unmarshal([]byte(policyJSON), &doc)

		subClaim := doc.Statement[0].Condition["StringEquals"]["token.actions.githubusercontent.com:sub"]
		expectedSub := "repo:acme-corp/core-api:environment:production"
		if subClaim != expectedSub {
			t.Errorf("sub claim = %s, want %s", subClaim, expectedSub)
		}
	})
}

func TestGenerateGCPWorkloadIdentityAssertion_Validation(t *testing.T) {
	yamlContent := `
name: GCP Deploy
on:
  push:
    branches: "release/v1"
jobs:
  deploy_gcp:
    environment:
      name: production
    steps: [{ run: echo gcp }]
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

	var doc gcpWIFDoc
	if err := json.Unmarshal([]byte(gcpConfigJSON), &doc); err != nil {
		t.Fatalf("failed to parse GCP WIF JSON: %v", err)
	}

	if doc.AttributeMapping["google.subject"] != "assertion.sub" {
		t.Errorf("missing google.subject mapping")
	}
	if doc.AttributeMapping["attribute.repository"] != "assertion.repository" {
		t.Errorf("missing attribute.repository mapping")
	}

	expectedCondition := "assertion.repository == 'gamesapeca/gha-oidc-auditor' && assertion.environment == 'production'"
	if doc.AttributeCondition != expectedCondition {
		t.Errorf("AttributeCondition = %s, want %s", doc.AttributeCondition, expectedCondition)
	}

	expectedBinding := "principal://iam.googleapis.com/projects/987654321098/locations/global/workloadIdentityPools/prod-pool/providers/github-prov/subject/repo:gamesapeca/gha-oidc-auditor:environment:production"
	if doc.ServiceAccountRole != expectedBinding {
		t.Errorf("ServiceAccountRole = %s, want %s", doc.ServiceAccountRole, expectedBinding)
	}
}

func TestGenerateAzureFederatedCredential_Validation(t *testing.T) {
	yamlContent := `
name: Azure Deploy
on:
  workflow_run:
    workflows: ["Build"]
    branches: ["main"]
jobs:
  deploy_azure:
    steps: [{ run: echo azure }]
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "azure.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	job := wf.Jobs["deploy_azure"]
	azureJSON, err := remediation.GenerateAzureFederatedCredential("special@owner!", "repo#name", wf, &job)
	if err != nil {
		t.Fatalf("failed to generate Azure credential: %v", err)
	}

	var doc azureDoc
	if err := json.Unmarshal([]byte(azureJSON), &doc); err != nil {
		t.Fatalf("failed to parse Azure JSON: %v", err)
	}

	if doc.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Issuer = %s, want https://token.actions.githubusercontent.com", doc.Issuer)
	}
	if len(doc.Audiences) != 1 || doc.Audiences[0] != "api://AzureADTokenExchange" {
		t.Errorf("Audiences mismatch: %+v", doc.Audiences)
	}

	// Name sanitization check: special characters replaced with hyphens
	if strings.ContainsAny(doc.Name, "@!#") {
		t.Errorf("Azure Name not sanitized: %s", doc.Name)
	}
}

func TestSynthesizeSubClaim_Precedence(t *testing.T) {
	// Case 1: Environment precedence over branch
	wfWithBranchAndEnv := `
name: Test
on:
  push:
    branches: [staging]
jobs:
  deploy:
    environment: prod-env
    steps: [{ run: echo 1 }]
`
	wf1, _ := parser.ParseWorkflowBytes([]byte(wfWithBranchAndEnv), "t1.yml")
	job1 := wf1.Jobs["deploy"]
	sub1 := remediation.SynthesizeSubClaim("org", "repo", wf1, &job1)
	if sub1 != "repo:org/repo:environment:prod-env" {
		t.Errorf("Environment should take highest precedence, got: %s", sub1)
	}

	// Case 2: Branch with refs/heads prefix
	wfWithRefBranch := `
name: Test Ref
on:
  push:
    branches: ["refs/heads/release/2.0"]
jobs:
  deploy:
    steps: [{ run: echo 1 }]
`
	wf2, _ := parser.ParseWorkflowBytes([]byte(wfWithRefBranch), "t2.yml")
	job2 := wf2.Jobs["deploy"]
	sub2 := remediation.SynthesizeSubClaim("org", "repo", wf2, &job2)
	if sub2 != "repo:org/repo:ref:refs/heads/release/2.0" {
		t.Errorf("Branch ref not normalized correctly, got: %s", sub2)
	}

	// Case 3: Fallback default
	sub3 := remediation.SynthesizeSubClaim("org", "repo", nil, nil)
	if sub3 != "repo:org/repo:ref:refs/heads/main" {
		t.Errorf("Fallback should be main, got: %s", sub3)
	}
}
