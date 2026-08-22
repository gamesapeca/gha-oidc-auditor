package remediation

import (
	"encoding/json"
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

type k8sObjectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type k8sServiceAccount struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Metadata   k8sObjectMeta `json:"metadata"`
}

// GenerateKubernetesServiceAccountManifest generates a Kubernetes ServiceAccount manifest with cloud OIDC federated annotations.
func GenerateKubernetesServiceAccountManifest(namespace, saName, awsRoleARN, gcpServiceAccount, azureClientID string, wf *parser.Workflow, job *parser.Job) (string, error) {
	if namespace == "" {
		namespace = "default"
	}
	if saName == "" {
		saName = "gha-deployer"
	}

	annotations := make(map[string]string)
	if awsRoleARN != "" {
		annotations["eks.amazonaws.com/role-arn"] = awsRoleARN
	}
	if gcpServiceAccount != "" {
		annotations["iam.gke.io/gcp-service-account"] = gcpServiceAccount
	}
	if azureClientID != "" {
		annotations["azure.workload.identity/client-id"] = azureClientID
	}

	sa := k8sServiceAccount{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
		Metadata: k8sObjectMeta{
			Name:        saName,
			Namespace:   namespace,
			Annotations: annotations,
		},
	}

	bytes, err := json.MarshalIndent(sa, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize Kubernetes ServiceAccount manifest: %w", err)
	}

	return string(bytes), nil
}
