package analyzer

import (
	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

// ResolveJobIDTokenPermission computes the effective 'id-token' permission for a target job.
// Follows GitHub Actions strict precedence matrix:
// 1. Job level (granular map, scalar string, or empty map)
// 2. Workflow level (granular map, scalar string, or empty map)
// 3. Organization / Repository default (treated as restricted/none for static security modeling)
func ResolveJobIDTokenPermission(wf *parser.Workflow, jobName string) string {
	if wf == nil {
		return "none"
	}

	job, exists := wf.Jobs[jobName]
	if !exists {
		return "none"
	}

	// 1.1 Job explicit granular permissions
	if perm, ok := job.Permissions["id-token"]; ok {
		return perm
	}

	// 1.2 Job scalar permissions ("write-all" / "read-all")
	if job.PermissionsAll == "write-all" {
		return "write"
	}
	if job.PermissionsAll == "read-all" {
		return "none"
	}

	// 1.3 Job explicit empty map permissions: {} -> all set to none
	if job.Permissions != nil && len(job.Permissions) == 0 {
		return "none"
	}

	// 2.1 Workflow root granular permissions
	if perm, ok := wf.Permissions["id-token"]; ok {
		return perm
	}

	// 2.2 Workflow scalar permissions ("write-all" / "read-all")
	if wf.PermissionsAll == "write-all" {
		return "write"
	}
	if wf.PermissionsAll == "read-all" {
		return "none"
	}

	// 2.3 Workflow explicit empty map permissions: {} -> all set to none
	if wf.Permissions != nil && len(wf.Permissions) == 0 {
		return "none"
	}

	return "none"
}

// IsJobOIDCPrivileged returns true if the job holds active token minting capability ('write').
func IsJobOIDCPrivileged(wf *parser.Workflow, jobName string) bool {
	return ResolveJobIDTokenPermission(wf, jobName) == "write"
}
