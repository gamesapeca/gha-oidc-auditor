package parser_test

import (
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

func BenchmarkLexerAndASTParser(b *testing.B) {
	expr := "github.event['pull_request']['head']['ref'] == 'main' && contains(inputs.allowed, github.actor)"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		node, err := parser.ParseExpression(expr)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
		_ = node.String()
	}
}

func BenchmarkContainsUntrustedContext_AST(b *testing.B) {
	runBlock := `
		echo "Triggered by: ${{ github.event.issue.title }}"
		echo "Actor: ${{ github.actor }}"
		echo "Ref: ${{ github['event']['pull_request']['head']['ref'] }}"
	`
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = parser.ContainsUntrustedContext(runBlock)
	}
}
