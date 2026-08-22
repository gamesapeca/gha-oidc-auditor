package parser

import (
	"regexp"
	"strings"
)

var (
	// actorCheckPatterns identifies explicit equality or function checks on actors
	actorCheckRegex = regexp.MustCompile(`(?i)(github\.event\.pull_request\.user\.login|github\.actor|github\.triggering_actor)\s*==\s*['"][a-zA-Z0-9_\-]+['"]`)

	// repoCheckPatterns identifies repository or fork validation
	repoCheckRegex = regexp.MustCompile(`(?i)(github\.repository\s*==|github\.event\.pull_request\.head\.repo\.full_name\s*==|\.head\.repo\.fork\s*==\s*false|\.head\.repo\.full_name\s*==\s*github\.repository)`)

	// containsFunctionRegex matches contains(list/str, actor/repo)
	containsActorRegex = regexp.MustCompile(`(?i)contains\s*\(\s*(fromJson\s*\([^)]+\)|\[[^\]]+\]|[^,]+)\s*,\s*(github\.actor|github\.triggering_actor|github\.event\.pull_request\.user\.login)\s*\)`)

	// startsWithActorRegex matches startsWith(actor, prefix)
	startsWithActorRegex = regexp.MustCompile(`(?i)startsWith\s*\(\s*(github\.actor|github\.triggering_actor|github\.event\.pull_request\.user\.login)\s*,\s*['"][a-zA-Z0-9_\-]+['"]\s*\)`)

	// labelGateRegex matches label checks (e.g. contains(github.event.pull_request.labels.*.name, 'safe-to-test'))
	labelGateRegex = regexp.MustCompile(`(?i)contains\s*\(\s*github\.event\.pull_request\.labels.*\.name\s*,\s*['"][a-zA-Z0-9_\-]+['"]\s*\)`)
)

// EvaluateConditionGuards inspects complex GitHub Actions boolean expressions for actor, repo, fork, or label gates.
// Supports boolean operators (&&, ||, !), functions (contains, startsWith, fromJson), and canonical properties.
func EvaluateConditionGuards(condition string) (bool, string) {
	norm := strings.TrimSpace(condition)
	if norm == "" {
		return false, ""
	}

	norm = NormalizeExpression(norm)

	// 1. Direct actor equality comparison
	if actorCheckRegex.MatchString(norm) {
		return true, "Actor check via equality (github.actor / pull_request.user.login)"
	}

	// 2. Repository isolation or non-fork PR check
	if repoCheckRegex.MatchString(norm) {
		return true, "Repository boundary validation (head.repo.fork == false / full_name == repository)"
	}

	// 3. Functional actor check via contains(list, actor) or contains(fromJson(...), actor)
	if containsActorRegex.MatchString(norm) {
		return true, "Authorized actor membership check via contains(list, actor)"
	}

	// 4. Prefix actor check via startsWith(actor, 'prefix')
	if startsWithActorRegex.MatchString(norm) {
		return true, "Prefix actor validation via startsWith(actor, prefix)"
	}

	// 5. Explicit label gate (e.g. 'safe-to-test' or 'approved')
	if labelGateRegex.MatchString(norm) {
		return true, "Maintainer PR label gate check via contains(labels.*.name, '...')"
	}

	// 6. Substring checks for fallback patterns
	fallbackPatterns := []struct {
		substr string
		reason string
	}{
		{"github.event.pull_request.user.login ==", "Actor check on pull_request user.login"},
		{"github.actor ==", "Actor check on github.actor"},
		{"github.triggering_actor ==", "Actor check on triggering_actor"},
		{"github.repository ==", "Repository check on base repository"},
		{".head.repo.full_name == github.repository", "Fork isolation check (internal branch only)"},
		{"github.event.pull_request.head.repo.full_name ==", "Explicit head repo validation"},
		{".head.repo.fork == false", "Non-fork PR validation"},
		{"github.event.pull_request.head.repo.fork == false", "Non-fork PR validation"},
		{"github.repository_owner ==", "Repository owner namespace check"},
	}

	for _, fp := range fallbackPatterns {
		if strings.Contains(norm, strings.ToLower(fp.substr)) {
			return true, fp.reason
		}
	}

	return false, ""
}
