package analyzer

import (
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// ResolveJobIDTokenPermission computes the effective 'id-token' permission for a job,
// evaluating job-level overrides before falling back to workflow-level definitions.
func ResolveJobIDTokenPermission(wf *parser.Workflow, jobName string) string {
	if wf == nil {
		return "none"
	}

	job, exists := wf.Jobs[jobName]
	if !exists {
		return "none"
	}

	if perm, ok := job.Permissions["id-token"]; ok {
		return perm
	}
	if job.PermissionsAll == "write-all" {
		return "write"
	}
	if job.PermissionsAll == "read-all" {
		return "none"
	}
	if job.Permissions != nil && len(job.Permissions) == 0 {
		return "none"
	}

	if perm, ok := wf.Permissions["id-token"]; ok {
		return perm
	}
	if wf.PermissionsAll == "write-all" {
		return "write"
	}
	if wf.PermissionsAll == "read-all" {
		return "none"
	}
	if wf.Permissions != nil && len(wf.Permissions) == 0 {
		return "none"
	}

	return "none"
}

// IsJobOIDCPrivileged returns whether the given job has active 'id-token: write' privileges.
func IsJobOIDCPrivileged(wf *parser.Workflow, jobName string) bool {
	return ResolveJobIDTokenPermission(wf, jobName) == "write"
}
