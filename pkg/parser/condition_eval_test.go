package parser_test

import (
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/parser"
)

func TestEvaluateConditionGuards_AdvancedExpressions(t *testing.T) {
	tests := []struct {
		name          string
		condition     string
		expectedGuard bool
	}{
		{
			name:          "Direct Actor equality",
			condition:     "github.actor == 'trusted-maintainer'",
			expectedGuard: true,
		},
		{
			name:          "Triggering Actor equality",
			condition:     "github.triggering_actor == 'ci-bot'",
			expectedGuard: true,
		},
		{
			name:          "Functional Actor Membership with fromJson",
			condition:     "contains(fromJson('[\"alice\", \"bob\", \"core-team\"]'), github.actor)",
			expectedGuard: true,
		},
		{
			name:          "Prefix Actor Check with startsWith",
			condition:     "startsWith(github.actor, 'dependabot')",
			expectedGuard: true,
		},
		{
			name:          "Explicit PR Label Gate",
			condition:     "contains(github.event.pull_request.labels.*.name, 'safe-to-test')",
			expectedGuard: true,
		},
		{
			name:          "Fork isolation check",
			condition:     "github.event.pull_request.head.repo.fork == false",
			expectedGuard: true,
		},
		{
			name:          "Complex nested boolean expression with actor guard",
			condition:     "(github.repository == 'org/repo') && (github.event.pull_request.user.login == 'trusted-user' || startsWith(github.actor, 'bot-'))",
			expectedGuard: true,
		},
		{
			name:          "No guard (only event type or branch check)",
			condition:     "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main'",
			expectedGuard: false,
		},
		{
			name:          "Empty condition",
			condition:     "",
			expectedGuard: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasGuard, reason := parser.EvaluateConditionGuards(tt.condition)
			if hasGuard != tt.expectedGuard {
				t.Errorf("EvaluateConditionGuards(%q) = %v (reason: %q), want %v", tt.condition, hasGuard, reason, tt.expectedGuard)
			}
		})
	}
}
