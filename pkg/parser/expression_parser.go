package parser

import (
	"fmt"
	"strconv"
)

// ExpressionParser implements a Pratt / precedence climber AST parser for GitHub Actions expressions.
type ExpressionParser struct {
	lexer   *Lexer
	curTok  Token
	peekTok Token
}

// NewExpressionParser creates a new ExpressionParser instance for the given expression input.
func NewExpressionParser(input string) (*ExpressionParser, error) {
	l := NewLexer(input)
	p := &ExpressionParser{lexer: l}

	var err error
	p.curTok, err = p.lexer.NextToken()
	if err != nil {
		return nil, err
	}
	p.peekTok, err = p.lexer.NextToken()
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *ExpressionParser) nextToken() error {
	p.curTok = p.peekTok
	var err error
	p.peekTok, err = p.lexer.NextToken()
	return err
}

// Precedence levels for expression parsing
const (
	precLowest = iota
	precOr
	precAnd
	precComparison
	precPrefix
	precCall
	precIndex
)

func getPrecedence(tok Token) int {
	if tok.Type == TokenOp {
		switch tok.Literal {
		case "||":
			return precOr
		case "&&":
			return precAnd
		case "==", "!=", "<", "<=", ">", ">=":
			return precComparison
		}
	}
	if tok.Type == TokenLParen {
		return precCall
	}
	if tok.Type == TokenDot || tok.Type == TokenLBracket {
		return precIndex
	}
	return precLowest
}

// Parse parses the expression string into an AST Node.
func (p *ExpressionParser) Parse() (Node, error) {
	if p.curTok.Type == TokenEOF {
		return nil, nil
	}
	node, err := p.parseExpression(precLowest)
	if err != nil {
		return nil, err
	}
	return node, nil
}

func (p *ExpressionParser) parseExpression(precedence int) (Node, error) {
	left, err := p.parsePrefix()
	if err != nil {
		return nil, err
	}

	for p.curTok.Type != TokenEOF && precedence < getPrecedence(p.curTok) {
		switch {
		case p.curTok.Type == TokenDot:
			left, err = p.parseMemberAccess(left)
		case p.curTok.Type == TokenLBracket:
			left, err = p.parseIndexAccess(left)
		case p.curTok.Type == TokenLParen:
			left, err = p.parseFunctionCall(left)
		case p.curTok.Type == TokenOp:
			left, err = p.parseBinary(left)
		default:
			return left, nil
		}
		if err != nil {
			return nil, err
		}
	}

	return left, nil
}

func (p *ExpressionParser) parsePrefix() (Node, error) {
	tok := p.curTok
	switch tok.Type {
	case TokenIdent:
		_ = p.nextToken()
		return &IdentifierNode{Name: tok.Literal}, nil

	case TokenString:
		_ = p.nextToken()
		return &StringLiteralNode{Value: tok.Literal}, nil

	case TokenNumber:
		_ = p.nextToken()
		val, _ := strconv.ParseFloat(tok.Literal, 64)
		return &NumberLiteralNode{Value: val}, nil

	case TokenBool:
		_ = p.nextToken()
		return &BooleanLiteralNode{Value: tok.Literal == "true"}, nil

	case TokenNull:
		_ = p.nextToken()
		return &NilLiteralNode{}, nil

	case TokenOp:
		if tok.Literal == "!" {
			_ = p.nextToken()
			operand, err := p.parseExpression(precPrefix)
			if err != nil {
				return nil, err
			}
			return &UnaryNode{Op: "!", Operand: operand}, nil
		}
		return nil, fmt.Errorf("unexpected prefix operator %q at position %d", tok.Literal, tok.Pos)

	case TokenLParen:
		_ = p.nextToken()
		expr, err := p.parseExpression(precLowest)
		if err != nil {
			return nil, err
		}
		if p.curTok.Type != TokenRParen {
			return nil, fmt.Errorf("expected ')' at position %d, got %s", p.curTok.Pos, p.curTok.Literal)
		}
		_ = p.nextToken() // consume ')'
		return expr, nil

	default:
		return nil, fmt.Errorf("unexpected token %s (%q) at position %d", tokenTypeName(tok.Type), tok.Literal, tok.Pos)
	}
}

func (p *ExpressionParser) parseMemberAccess(target Node) (Node, error) {
	_ = p.nextToken() // consume '.'

	if p.curTok.Type != TokenIdent {
		return nil, fmt.Errorf("expected property identifier after '.' at position %d, got %s", p.curTok.Pos, p.curTok.Literal)
	}

	prop := p.curTok.Literal
	_ = p.nextToken()
	return &MemberAccessNode{Target: target, Property: prop}, nil
}

func (p *ExpressionParser) parseIndexAccess(target Node) (Node, error) {
	_ = p.nextToken() // consume '['

	indexExpr, err := p.parseExpression(precLowest)
	if err != nil {
		return nil, err
	}

	if p.curTok.Type != TokenRBracket {
		return nil, fmt.Errorf("expected ']' at position %d, got %s", p.curTok.Pos, p.curTok.Literal)
	}
	_ = p.nextToken() // consume ']'

	return &IndexAccessNode{Target: target, Index: indexExpr}, nil
}

func (p *ExpressionParser) parseFunctionCall(target Node) (Node, error) {
	ident, ok := target.(*IdentifierNode)
	if !ok {
		return nil, fmt.Errorf("invalid function call on non-identifier node %T", target)
	}

	_ = p.nextToken() // consume '('

	var args []Node
	if p.curTok.Type != TokenRParen {
		for {
			arg, err := p.parseExpression(precLowest)
			if err != nil {
				return nil, err
			}
			args = append(args, arg)

			if p.curTok.Type == TokenComma {
				_ = p.nextToken() // consume ','
				continue
			}
			break
		}
	}

	if p.curTok.Type != TokenRParen {
		return nil, fmt.Errorf("expected ')' at position %d, got %s", p.curTok.Pos, p.curTok.Literal)
	}
	_ = p.nextToken() // consume ')'

	return &FunctionCallNode{Name: ident.Name, Args: args}, nil
}

func (p *ExpressionParser) parseBinary(left Node) (Node, error) {
	opTok := p.curTok
	precedence := getPrecedence(opTok)
	_ = p.nextToken() // consume operator

	right, err := p.parseExpression(precedence)
	if err != nil {
		return nil, err
	}

	return &BinaryNode{Left: left, Op: opTok.Literal, Right: right}, nil
}

// ParseExpression is a convenient entrypoint that parses a raw expression string into an AST Node.
func ParseExpression(expr string) (Node, error) {
	p, err := NewExpressionParser(expr)
	if err != nil {
		return nil, err
	}
	return p.Parse()
}

func tokenTypeName(t TokenType) string {
	switch t {
	case TokenEOF:
		return "EOF"
	case TokenIdent:
		return "Identifier"
	case TokenString:
		return "String"
	case TokenNumber:
		return "Number"
	case TokenBool:
		return "Bool"
	case TokenNull:
		return "Null"
	case TokenDot:
		return "Dot"
	case TokenLBracket:
		return "LBracket"
	case TokenRBracket:
		return "RBracket"
	case TokenLParen:
		return "LParen"
	case TokenRParen:
		return "RParen"
	case TokenComma:
		return "Comma"
	case TokenOp:
		return "Operator"
	default:
		return "Unknown"
	}
}
