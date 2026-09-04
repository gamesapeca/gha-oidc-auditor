package parser

import (
	"strings"
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

	norm = strings.ToLower(norm)

	// Fallback substring checks for unparsed non-standard expression constructs
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
