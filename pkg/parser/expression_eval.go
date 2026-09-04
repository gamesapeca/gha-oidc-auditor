package parser

import (
	"regexp"
	"strings"
)

// UntrustedContexts lists GitHub Actions context variables that carry untrusted, externally-controlled input.
// Direct inline interpolation of these expressions in 'run:' steps allows command injection / RCE.
// Updated with research findings from 2025-2026 security publications.
var UntrustedContexts = []string{
	// Issue and discussion events
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.discussion_comment.body",
	// Pull request metadata
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo.default_branch",
	"github.event.pull_request.head.repo.full_name",
	"github.event.pull_request.head.repo.name",
	// Comment and review bodies
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	// Release metadata — can be set by anyone with release permissions
	"github.event.release.body",
	"github.event.release.name",
	"github.event.release.tag_name",
	// Dispatch and webhook payloads
	"github.event.client_payload",
	"github.event.pages",
	// Commit data — can be forged in unsigned commits
	"github.event.commits",
	"github.event.head_commit.message",
	"github.event.head_commit.author.email",
	"github.event.head_commit.author.name",
	"github.event.head_commit.committer.email",
	"github.event.head_commit.committer.name",
	// workflow_run: head branch/commit from the triggering upstream workflow (untrusted fork)
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.event.workflow_run.head_commit.author.name",
	"github.event.workflow_run.head_commit.author.email",
	"github.event.workflow_run.head_sha",
	// Sender/actor — account login can be arbitrary
	"github.event.sender.login",
	// merge_group trigger (new in 2023, attack surface confirmed 2025)
	"github.event.merge_group.head_ref",
	"github.event.merge_group.base_ref",
	// github.head_ref and triggering_actor — can be attacker-controlled
	"github.head_ref",
	"github.triggering_actor",
	// Workflow dispatch/call inputs
	"github.event.inputs.",
	"inputs.",
}

var (
	// ExprRegex is preserved for backwards compatibility with external callers.
	ExprRegex = regexp.MustCompile(`\$\{\{((?s:.)*?)\}\}`)

	// bracketIndexRegex matches ['property'] or ["property"] index expressions
	bracketIndexRegex = regexp.MustCompile(`\[\s*['"]([a-zA-Z0-9_\-]+)['"]\s*\]`)

	// dotSpaceRegex normalizes spaces around dots (e.g. "github . event" -> "github.event")
	dotSpaceRegex = regexp.MustCompile(`\s*\.\s*`)
)

// NormalizeExpression transforms expressions into canonical dot-notation for invariant matching.
func NormalizeExpression(expr string) string {
	normalized := strings.ToLower(expr)
	normalized = bracketIndexRegex.ReplaceAllString(normalized, ".$1")
	normalized = dotSpaceRegex.ReplaceAllString(normalized, ".")
	return normalized
}

// ContainsUntrustedContext checks whether a shell run block contains inline untrusted context interpolation.
// It parses extracted ${{ ... }} expressions into a concrete AST (via Lexer and ExpressionParser) and traverses
// member/index access chains. String literals (e.g. 'github.event.issue.title') are formally excluded to prevent
// false positives.
func ContainsUntrustedContext(runBlock string) (bool, string) {
	if runBlock == "" {
		return false, ""
	}

	expressions := ExtractExpressions(runBlock)
	for _, rawExpr := range expressions {
		astNode, err := ParseExpression(rawExpr)
		if err != nil {
			// Fallback to normalized substring inspection on syntax error
			normalized := NormalizeExpression(rawExpr)
			for _, untrusted := range UntrustedContexts {
				if strings.Contains(normalized, untrusted) {
					return true, untrusted
				}
			}
			continue
		}

		var matchedUntrusted string
		found := false

		WalkAST(astNode, func(n Node) bool {
			if found {
				return false
			}

			// Do not flag string literals
			if _, isString := n.(*StringLiteralNode); isString {
				return false
			}

			// Check if this node resolves to an untrusted context path
			path, ok := ResolveContextPath(n)
			if ok && path != "" {
				for _, untrusted := range UntrustedContexts {
					if path == untrusted || strings.HasPrefix(path, untrusted) || strings.Contains(path, untrusted) {
						found = true
						matchedUntrusted = untrusted
						return false
					}
				}
			}
			return true
		})

		if found {
			return true, matchedUntrusted
		}
	}

	return false, ""
}

// IsExternalAttackerPayload returns true if the context variable is an externally-controllable event payload (issue, PR, comment, head_ref).
func IsExternalAttackerPayload(contextVar string) bool {
	norm := strings.ToLower(contextVar)
	if strings.HasPrefix(norm, "inputs.") || strings.HasPrefix(norm, "github.event.inputs.") {
		return false
	}
	return true
}

