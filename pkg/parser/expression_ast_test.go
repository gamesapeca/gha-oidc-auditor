package parser_test

import (
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

func TestLexer_Tokenization(t *testing.T) {
	input := "github.event['issue'].title == 'test' && contains(inputs.list, 123)"
	lexer := parser.NewLexer(input)

	var tokens []parser.Token
	for {
		tok, err := lexer.NextToken()
		if err != nil {
			t.Fatalf("Lexer error: %v", err)
		}
		if tok.Type == parser.TokenEOF {
			break
		}
		tokens = append(tokens, tok)
	}

	if len(tokens) == 0 {
		t.Fatalf("Expected tokens, got empty slice")
	}

	// Verify first token is identifier "github"
	if tokens[0].Type != parser.TokenIdent || tokens[0].Literal != "github" {
		t.Errorf("Expected token 0 to be ident 'github', got %+v", tokens[0])
	}
}

func TestExpressionParser_ASTConstruction(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "Member and Index Access",
			expr:     "github.event['pull_request']['head']['ref']",
			expected: "github.event['pull_request']['head']['ref']",
		},
		{
			name:     "Binary Equality with Literal",
			expr:     "github.actor == 'admin'",
			expected: "(github.actor == 'admin')",
		},
		{
			name:     "Function Call with Context",
			expr:     "contains(fromJSON(inputs.data), github.triggering_actor)",
			expected: "contains(fromJSON(inputs.data), github.triggering_actor)",
		},
		{
			name:     "Logical Precedence",
			expr:     "!github.event.issue.locked && github.actor == 'maintainer'",
			expected: "(!github.event.issue.locked && (github.actor == 'maintainer'))",
		},
		{
			name:     "Wildcard Object Collection Filter",
			expr:     "contains(github.event.pull_request.labels.*.name, 'safe-to-test')",
			expected: "contains(github.event.pull_request.labels.*.name, 'safe-to-test')",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node, err := parser.ParseExpression(tc.expr)
			if err != nil {
				t.Fatalf("Failed to parse expression %q: %v", tc.expr, err)
			}
			if node.String() != tc.expected {
				t.Errorf("Expected AST string %q, got %q", tc.expected, node.String())
			}
		})
	}
}

func TestResolveContextPath_CanonicalEquivalence(t *testing.T) {
	variants := []string{
		"github.event.issue.title",
		"github['event'].issue.title",
		"github['event']['issue']['title']",
		"GITHUB.EVENT.ISSUE.TITLE",
	}

	for _, v := range variants {
		node, err := parser.ParseExpression(v)
		if err != nil {
			t.Fatalf("Failed to parse %q: %v", v, err)
		}
		path, ok := parser.ResolveContextPath(node)
		if !ok || path != "github.event.issue.title" {
			t.Errorf("Expected canonical path 'github.event.issue.title', got %q (ok=%v) for input %q", path, ok, v)
		}
	}

	// Verify wildcard collection filter canonical path
	wildcardExpr := "github.event.pull_request.labels.*.name"
	node, err := parser.ParseExpression(wildcardExpr)
	if err != nil {
		t.Fatalf("Failed to parse wildcard filter %q: %v", wildcardExpr, err)
	}
	path, ok := parser.ResolveContextPath(node)
	if !ok || path != "github.event.pull_request.labels.*.name" {
		t.Errorf("Expected canonical path 'github.event.pull_request.labels.*.name', got %q (ok=%v)", path, ok)
	}
}

func TestContainsUntrustedContext_LiteralStringExclusion(t *testing.T) {
	// A shell step printing a literal string matching an untrusted context name
	// should NOT be flagged as an injection sink by the AST parser.
	safeLiteralRun := `echo "${{ 'github.event.issue.title' }}"`
	isUntrusted, _ := parser.ContainsUntrustedContext(safeLiteralRun)
	if isUntrusted {
		t.Errorf("String literal inside expression was incorrectly flagged as untrusted context")
	}

	// Real dynamic context access MUST be flagged
	realInjectionRun := `echo "${{ github.event.issue.title }}"`
	isUntrusted, untrustedVar := parser.ContainsUntrustedContext(realInjectionRun)
	if !isUntrusted || untrustedVar != "github.event.issue.title" {
		t.Errorf("Real dynamic context was not detected: got (%v, %s)", isUntrusted, untrustedVar)
	}

	// Bracket notation injection MUST be flagged
	bracketInjectionRun := `echo "${{ github['event']['pull_request']['head']['ref'] }}"`
	isUntrusted, _ = parser.ContainsUntrustedContext(bracketInjectionRun)
	if !isUntrusted {
		t.Errorf("Bracket notation untrusted context was not detected")
	}
}

func TestExtractExpressions_EscapedQuotesAndCurlyBraces(t *testing.T) {
	content := `
		run: |
			echo "${{ format('Hello {0}', github.event.issue.title) }}"
			echo "${{ 'embedded }} inside string' }}"
	`

	expressions := parser.ExtractExpressions(content)
	if len(expressions) != 2 {
		t.Fatalf("Expected 2 extracted expressions, got %d: %+v", len(expressions), expressions)
	}

	if expressions[1] != "'embedded }} inside string'" {
		t.Errorf("Extracted expression corrupted by internal closing braces: got %q", expressions[1])
	}
}
