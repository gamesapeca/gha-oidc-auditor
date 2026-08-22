package remediation_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
	"github.com/gamesapeca/gha-oidc-auditor/pkg/remediation"
)

type awsStatement struct {
	Effect    string                       `json:"Effect"`
	Principal map[string]string            `json:"Principal"`
	Action    string                       `json:"Action"`
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

type vaultDoc struct {
	RoleType       string            `json:"role_type"`
	BoundAudiences []string          `json:"bound_audiences"`
	UserClaim      string            `json:"user_claim"`
	BoundClaims    map[string]string `json:"bound_claims"`
	Policies       []string          `json:"policies"`
	TTL            string            `json:"ttl"`
}

type k8sSADoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
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
			t.Fatalf("failed to parse generated AWS JSON: %v", err)
		}

		if doc.Version != "2012-10-17" {
			t.Errorf("Version = %s, want 2012-10-17", doc.Version)
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
		wantPrincipal := "arn:aws:iam::111222333444:oidc-provider/token.actions.githubusercontent.com"
		if stmt.Principal["Federated"] != wantPrincipal {
			t.Errorf("Principal.Federated = %s, want %s", stmt.Principal["Federated"], wantPrincipal)
		}

		stringEquals := stmt.Condition["StringEquals"]
		if stringEquals["token.actions.githubusercontent.com:aud"] != "sts.amazonaws.com" {
			t.Errorf("Audience mismatch: %s", stringEquals["token.actions.githubusercontent.com:aud"])
		}
		wantSub := "repo:gamesapeca/infrastructure-sentinel:ref:refs/heads/main"
		if stringEquals["token.actions.githubusercontent.com:sub"] != wantSub {
			t.Errorf("Sub mismatch: %s, want %s", stringEquals["token.actions.githubusercontent.com:sub"], wantSub)
		}
	})

	t.Run("Environment Scoped", func(t *testing.T) {
		yamlContent := `
name: Deploy Prod
on: push
jobs:
  deploy:
    environment: production
    steps: [{ run: echo deploy }]
`
		wf, _ := parser.ParseWorkflowBytes([]byte(yamlContent), "deploy.yml")
		job := wf.Jobs["deploy"]
		policyJSON, err := remediation.GenerateAWSTrustPolicy("111222333444", "gamesapeca", "infrastructure-sentinel", wf, &job)
		if err != nil {
			t.Fatalf("failed to generate AWS policy: %v", err)
		}

		var doc awsPolicyDocument
		_ = json.Unmarshal([]byte(policyJSON), &doc)
		stringEquals := doc.Statement[0].Condition["StringEquals"]
		wantSub := "repo:gamesapeca/infrastructure-sentinel:environment:production"
		if stringEquals["token.actions.githubusercontent.com:sub"] != wantSub {
			t.Errorf("Sub environment mismatch: %s, want %s", stringEquals["token.actions.githubusercontent.com:sub"], wantSub)
		}
	})
}

func TestGenerateGCPWorkloadIdentityAssertion_Validation(t *testing.T) {
	yamlContent := `
name: GCP Deploy
on:
  push:
    branches: [release]
jobs:
  deploy:
    steps: [{ run: echo deploy }]
`
	wf, _ := parser.ParseWorkflowBytes([]byte(yamlContent), "gcp.yml")
	job := wf.Jobs["deploy"]
	gcpJSON, err := remediation.GenerateGCPWorkloadIdentityAssertion("1234567890", "gh-pool", "gh-provider", "gamesapeca", "infrastructure-sentinel", wf, &job)
	if err != nil {
		t.Fatalf("failed to generate GCP WIF: %v", err)
	}

	var doc gcpWIFDoc
	if err := json.Unmarshal([]byte(gcpJSON), &doc); err != nil {
		t.Fatalf("failed to parse GCP JSON: %v", err)
	}

	if doc.AttributeMapping["google.subject"] != "assertion.sub" {
		t.Errorf("google.subject mapping mismatch")
	}
	if doc.AttributeMapping["attribute.actor"] != "assertion.actor" {
		t.Errorf("attribute.actor mapping mismatch")
	}
	if doc.AttributeMapping["attribute.repository"] != "assertion.repository" {
		t.Errorf("attribute.repository mapping mismatch")
	}

	if !strings.Contains(doc.AttributeCondition, "assertion.repository == 'gamesapeca/infrastructure-sentinel'") {
		t.Errorf("attribute_condition missing repository assertion: %s", doc.AttributeCondition)
	}
	if !strings.Contains(doc.AttributeCondition, "assertion.ref == 'refs/heads/release'") {
		t.Errorf("attribute_condition missing branch ref assertion: %s", doc.AttributeCondition)
	}
}

func TestGenerateAzureFederatedCredential_Validation(t *testing.T) {
	yamlContent := `
name: Azure Deploy
on: push
jobs:
  deploy:
    environment: prod-azure
    steps: [{ run: echo deploy }]
`
	wf, _ := parser.ParseWorkflowBytes([]byte(yamlContent), "azure.yml")
	job := wf.Jobs["deploy"]
	azureJSON, err := remediation.GenerateAzureFederatedCredential("gamesapeca", "infrastructure-sentinel", wf, &job)
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

	if strings.ContainsAny(doc.Name, "@!#") {
		t.Errorf("Azure Name not sanitized: %s", doc.Name)
	}
}

func TestGenerateVaultJWTRole_Validation(t *testing.T) {
	yamlContent := `
name: Vault Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    environment: prod
    steps: [{ run: echo vault }]
`
	wf, _ := parser.ParseWorkflowBytes([]byte(yamlContent), "vault.yml")
	job := wf.Jobs["deploy"]
	vaultJSON, err := remediation.GenerateVaultJWTRole("gamesapeca", "infra", "prod-deployer", wf, &job)
	if err != nil {
		t.Fatalf("failed to generate Vault JWT role: %v", err)
	}

	var doc vaultDoc
	if err := json.Unmarshal([]byte(vaultJSON), &doc); err != nil {
		t.Fatalf("failed to parse Vault JSON: %v", err)
	}

	if doc.RoleType != "jwt" {
		t.Errorf("RoleType = %s, want jwt", doc.RoleType)
	}
	if doc.UserClaim != "actor" {
		t.Errorf("UserClaim = %s, want actor", doc.UserClaim)
	}
	if doc.BoundClaims["repository"] != "gamesapeca/infra" {
		t.Errorf("BoundClaims.repository mismatch: %s", doc.BoundClaims["repository"])
	}
	if doc.BoundClaims["environment"] != "prod" {
		t.Errorf("BoundClaims.environment mismatch: %s", doc.BoundClaims["environment"])
	}
}

func TestGenerateKubernetesServiceAccountManifest_Validation(t *testing.T) {
	saJSON, err := remediation.GenerateKubernetesServiceAccountManifest("production", "cd-agent", "arn:aws:iam::111222333444:role/EKSDeployer", "", "", nil, nil)
	if err != nil {
		t.Fatalf("failed to generate K8s SA manifest: %v", err)
	}

	var doc k8sSADoc
	if err := json.Unmarshal([]byte(saJSON), &doc); err != nil {
		t.Fatalf("failed to parse K8s JSON: %v", err)
	}

	if doc.Kind != "ServiceAccount" || doc.APIVersion != "v1" {
		t.Errorf("Kind/APIVersion mismatch: %s/%s", doc.Kind, doc.APIVersion)
	}
	if doc.Metadata.Namespace != "production" || doc.Metadata.Name != "cd-agent" {
		t.Errorf("Metadata mismatch: namespace=%s, name=%s", doc.Metadata.Namespace, doc.Metadata.Name)
	}
	if doc.Metadata.Annotations["eks.amazonaws.com/role-arn"] != "arn:aws:iam::111222333444:role/EKSDeployer" {
		t.Errorf("EKS annotation mismatch: %s", doc.Metadata.Annotations["eks.amazonaws.com/role-arn"])
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

func TestGenerateAWS2026TrustPolicy_Validation(t *testing.T) {
	yamlContent := `
name: Deploy Prod
on:
  push:
    branches: [main]
jobs:
  deploy:
    environment: production
    steps: [{ run: echo 1 }]
`
	wf, err := parser.ParseWorkflowBytes([]byte(yamlContent), "deploy.yml")
	if err != nil {
		t.Fatalf("failed to parse workflow: %v", err)
	}

	job := wf.Jobs["deploy"]
	policyJSON, err := remediation.GenerateAWS2026TrustPolicy("112233445566", "my-org", "my-repo", wf, &job)
	if err != nil {
		t.Fatalf("GenerateAWS2026TrustPolicy failed: %v", err)
	}

	if !strings.Contains(policyJSON, "token.actions.githubusercontent.com:aud") {
		t.Errorf("missing audience condition in 2026 policy: %s", policyJSON)
	}
	if !strings.Contains(policyJSON, "repo:my-org/my-repo:environment:production") {
		t.Errorf("missing legacy sub claim in 2026 policy: %s", policyJSON)
	}
	if !strings.Contains(policyJSON, "repo:my-org@*/my-repo@*:environment:production") {
		t.Errorf("missing immutable numeric ID sub claim pattern in 2026 policy: %s", policyJSON)
	}
}

func TestSynthesizeCustomPropertyClaim_Validation(t *testing.T) {
	claimName, val := remediation.SynthesizeCustomPropertyClaim("tier", "production")
	if claimName != "token.actions.githubusercontent.com:repo_property_tier" {
		t.Errorf("unexpected claim name: %s", claimName)
	}
	if val != "production" {
		t.Errorf("unexpected claim value: %s", val)
	}
}

