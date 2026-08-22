package parser

import (
	"regexp"
	"strings"
)

// UntrustedContexts lists GitHub Actions context variables that carry untrusted, externally-controlled input.
// Direct inline interpolation of these expressions in 'run:' steps allows command injection / RCE.
var UntrustedContexts = []string{
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo.default_branch",
	"github.event.pull_request.head.repo.full_name",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.release.body",
	"github.event.release.name",
	"github.event.client_payload",
	"github.event.pages",
	"github.event.commits",
	"github.event.head_commit.message",
	"github.event.head_commit.author.email",
	"github.event.head_commit.author.name",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.head_ref",
	"github.event.inputs.",
	"inputs.",
}

var (
	// ExprRegex matches any ${{ ... }} expression, including multiline expressions.
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
// Handles case-insensitive expressions, bracket indexing, and nested functions (e.g. format, toJSON).
func ContainsUntrustedContext(runBlock string) (bool, string) {
	if runBlock == "" {
		return false, ""
	}

	matches := ExprRegex.FindAllStringSubmatch(runBlock, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := NormalizeExpression(match[1])
			for _, untrusted := range UntrustedContexts {
				if strings.Contains(normalized, untrusted) {
					return true, untrusted
				}
			}
		}
	}
	return false, ""
}

// ExtractExpressions extracts all interpolated expressions from a given block of text.
func ExtractExpressions(content string) []string {
	if content == "" {
		return nil
	}

	var results []string
	matches := ExprRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			results = append(results, strings.TrimSpace(match[1]))
		}
	}
	return results
}

// IsExternalAttackerPayload returns true if the context variable is an externally-controllable event payload (issue, PR, comment, head_ref).
func IsExternalAttackerPayload(contextVar string) bool {
	norm := strings.ToLower(contextVar)
	if strings.HasPrefix(norm, "inputs.") || strings.HasPrefix(norm, "github.event.inputs.") {
		return false
	}
	return true
}

