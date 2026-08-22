package report

import (
	"encoding/json"
	"fmt"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/analyzer"
)

// ExportJSON serializes the AuditReport into a formatted JSON string.
func ExportJSON(report *analyzer.AuditReport) (string, error) {
	bytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to export JSON report: %w", err)
	}
	return string(bytes), nil
}
