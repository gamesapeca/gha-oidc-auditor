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
// It uses AST parsing to structurally verify equality comparisons and gate functions (contains, startsWith),
// with deterministic fallback to pattern matching.
func EvaluateConditionGuards(condition string) (bool, string) {
	norm := strings.TrimSpace(condition)
	if norm == "" {
		return false, ""
	}

	clean := norm
	if strings.HasPrefix(clean, "${{") && strings.HasSuffix(clean, "}}") {
		clean = strings.TrimSpace(clean[3 : len(clean)-2])
	}

	// 1. AST-based structural evaluation
	if astNode, err := ParseExpression(clean); err == nil && astNode != nil {
		var matchedReason string
		found := false

		WalkAST(astNode, func(n Node) bool {
			if found {
				return false
			}

			switch expr := n.(type) {
			case *BinaryNode:
				if expr.Op == "==" {
					leftPath, leftOk := ResolveContextPath(expr.Left)
					rightPath, rightOk := ResolveContextPath(expr.Right)

					// Check actor equality
					if (leftOk && isActorContext(leftPath)) || (rightOk && isActorContext(rightPath)) {
						found = true
						matchedReason = "Actor check via equality (github.actor / pull_request.user.login)"
						return false
					}

					// Check repository or fork validation
					if (leftOk && isRepoContext(leftPath)) || (rightOk && isRepoContext(rightPath)) {
						found = true
						matchedReason = "Repository boundary validation (head.repo.fork == false / full_name == repository)"
						return false
					}
				}

			case *FunctionCallNode:
				fnName := strings.ToLower(expr.Name)
				if fnName == "contains" {
					for _, arg := range expr.Args {
						if p, ok := ResolveContextPath(arg); ok {
							if isActorContext(p) {
								found = true
								matchedReason = "Authorized actor membership check via contains(list, actor)"
								return false
							}
							if strings.Contains(p, "labels") {
								found = true
								matchedReason = "Maintainer PR label gate check via contains(labels.*.name, '...')"
								return false
							}
						}
					}
				} else if fnName == "startswith" && len(expr.Args) > 0 {
					if p, ok := ResolveContextPath(expr.Args[0]); ok && isActorContext(p) {
						found = true
						matchedReason = "Prefix actor validation via startsWith(actor, prefix)"
						return false
					}
				}
			}

			return true
		})

		if found {
			return true, matchedReason
		}
	}

	norm = NormalizeExpression(norm)

	// Fallback 1: Direct actor equality comparison regex
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

func isActorContext(path string) bool {
	p := strings.ToLower(path)
	return p == "github.actor" ||
		p == "github.triggering_actor" ||
		p == "github.event.pull_request.user.login" ||
		p == "github.event.sender.login" ||
		strings.HasSuffix(p, ".user.login") ||
		strings.HasSuffix(p, ".sender.login")
}

func isRepoContext(path string) bool {
	p := strings.ToLower(path)
	return p == "github.repository" ||
		p == "github.event.pull_request.head.repo.full_name" ||
		p == "github.event.pull_request.head.repo.fork" ||
		strings.HasSuffix(p, ".head.repo.fork") ||
		strings.HasSuffix(p, ".head.repo.full_name") ||
		p == "github.repository_owner"
}
