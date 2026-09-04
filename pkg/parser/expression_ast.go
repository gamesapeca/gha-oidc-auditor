package parser

import (
	"fmt"
	"strings"
)

// Node represents an abstract syntax tree (AST) node for GitHub Actions expressions.
type Node interface {
	String() string
}

// IdentifierNode represents a named variable or context identifier (e.g. github, env, contains).
type IdentifierNode struct {
	Name string
}

func (n *IdentifierNode) String() string {
	return n.Name
}

// StringLiteralNode represents a single-quoted string literal.
type StringLiteralNode struct {
	Value string
}

func (n *StringLiteralNode) String() string {
	return fmt.Sprintf("'%s'", n.Value)
}

// NumberLiteralNode represents a numeric literal.
type NumberLiteralNode struct {
	Value float64
}

func (n *NumberLiteralNode) String() string {
	return fmt.Sprintf("%g", n.Value)
}

// BooleanLiteralNode represents a boolean literal (true / false).
type BooleanLiteralNode struct {
	Value bool
}

func (n *BooleanLiteralNode) String() string {
	if n.Value {
		return "true"
	}
	return "false"
}

// NilLiteralNode represents a null literal.
type NilLiteralNode struct{}

func (n *NilLiteralNode) String() string {
	return "null"
}

// MemberAccessNode represents a dot property access (e.g. github.event).
type MemberAccessNode struct {
	Target   Node
	Property string
}

func (n *MemberAccessNode) String() string {
	return fmt.Sprintf("%s.%s", n.Target.String(), n.Property)
}

// IndexAccessNode represents bracket access (e.g. github['event'] or matrix[0]).
type IndexAccessNode struct {
	Target Node
	Index  Node
}

func (n *IndexAccessNode) String() string {
	return fmt.Sprintf("%s[%s]", n.Target.String(), n.Index.String())
}

// FunctionCallNode represents a function call (e.g. contains(a, b) or fromJSON(c)).
type FunctionCallNode struct {
	Name string
	Args []Node
}

func (n *FunctionCallNode) String() string {
	args := make([]string, len(n.Args))
	for i, arg := range n.Args {
		args[i] = arg.String()
	}
	return fmt.Sprintf("%s(%s)", n.Name, strings.Join(args, ", "))
}

// UnaryNode represents an expression preceded by a unary operator (e.g. !condition).
type UnaryNode struct {
	Op      string
	Operand Node
}

func (n *UnaryNode) String() string {
	return fmt.Sprintf("%s%s", n.Op, n.Operand.String())
}

// BinaryNode represents a binary expression (e.g. left == right, a && b).
type BinaryNode struct {
	Left  Node
	Op    string
	Right Node
}

func (n *BinaryNode) String() string {
	return fmt.Sprintf("(%s %s %s)", n.Left.String(), n.Op, n.Right.String())
}

// ResolveContextPath traverses a chain of MemberAccess and IndexAccess nodes to produce
// a canonical dotted representation (e.g. github.event.issue.title), or returns false if
// the node contains dynamic, non-literal index expressions.
func ResolveContextPath(node Node) (string, bool) {
	switch n := node.(type) {
	case *IdentifierNode:
		return strings.ToLower(n.Name), true

	case *MemberAccessNode:
		parentPath, ok := ResolveContextPath(n.Target)
		if !ok {
			return "", false
		}
		return parentPath + "." + strings.ToLower(n.Property), true

	case *IndexAccessNode:
		parentPath, ok := ResolveContextPath(n.Target)
		if !ok {
			return "", false
		}
		switch idx := n.Index.(type) {
		case *StringLiteralNode:
			return parentPath + "." + strings.ToLower(idx.Value), true
		case *IdentifierNode:
			return parentPath + "." + strings.ToLower(idx.Name), true
		default:
			return "", false
		}

	default:
		return "", false
	}
}

// WalkAST traverses an AST depth-first and invokes the visitor on every encountered node.
func WalkAST(node Node, visitor func(n Node) bool) {
	if node == nil {
		return
	}
	if !visitor(node) {
		return
	}

	switch n := node.(type) {
	case *MemberAccessNode:
		WalkAST(n.Target, visitor)
	case *IndexAccessNode:
		WalkAST(n.Target, visitor)
		WalkAST(n.Index, visitor)
	case *FunctionCallNode:
		for _, arg := range n.Args {
			WalkAST(arg, visitor)
		}
	case *UnaryNode:
		WalkAST(n.Operand, visitor)
	case *BinaryNode:
		WalkAST(n.Left, visitor)
		WalkAST(n.Right, visitor)
	}
}
