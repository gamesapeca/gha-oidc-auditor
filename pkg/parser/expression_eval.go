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
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.pages",
	"github.event.commits",
	"github.event.head_commit.message",
	"github.event.head_commit.author.email",
	"github.event.head_commit.author.name",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.head_ref",
	"github.event.inputs.",
}

// ExprRegex matches any ${{ ... }} expression, including multiline expressions.
var ExprRegex = regexp.MustCompile(`\$\{\{((?s:.)*?)\}\}`)

// ContainsUntrustedContext checks whether a shell run block contains inline untrusted context interpolation.
// Handles case-insensitive expressions and nested functions (e.g. format, toJSON).
func ContainsUntrustedContext(runBlock string) (bool, string) {
	if runBlock == "" {
		return false, ""
	}

	matches := ExprRegex.FindAllStringSubmatch(runBlock, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := strings.ToLower(strings.TrimSpace(match[1]))
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
