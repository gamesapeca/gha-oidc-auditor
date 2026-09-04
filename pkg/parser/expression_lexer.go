package parser

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType designates the lexical category of a token.
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenIdent
	TokenString
	TokenNumber
	TokenBool
	TokenNull
	TokenDot
	TokenLBracket
	TokenRBracket
	TokenLParen
	TokenRParen
	TokenComma
	TokenOp
)

// Token represents a lexical token with its position and raw string value.
type Token struct {
	Type    TokenType
	Literal string
	Pos     int
}

// Lexer implements a zero-regex, linear-time tokenizer for GitHub Actions expressions.
type Lexer struct {
	input string
	pos   int
	ch    byte
}

// NewLexer creates an initialized Lexer for the given expression.
func NewLexer(input string) *Lexer {
	l := &Lexer{input: input}
	l.readChar()
	return l
}

func (l *Lexer) readChar() {
	if l.pos >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.pos]
	}
	l.pos++
}

func (l *Lexer) peekChar() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	return l.input[l.pos]
}

func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\n' || l.ch == '\r' {
		l.readChar()
	}
}

// NextToken scans and returns the next lexical token.
func (l *Lexer) NextToken() (Token, error) {
	l.skipWhitespace()

	startPos := l.pos - 1
	if l.ch == 0 {
		return Token{Type: TokenEOF, Literal: "", Pos: startPos}, nil
	}

	switch l.ch {
	case '.':
		l.readChar()
		return Token{Type: TokenDot, Literal: ".", Pos: startPos}, nil
	case '[':
		l.readChar()
		return Token{Type: TokenLBracket, Literal: "[", Pos: startPos}, nil
	case ']':
		l.readChar()
		return Token{Type: TokenRBracket, Literal: "]", Pos: startPos}, nil
	case '(':
		l.readChar()
		return Token{Type: TokenLParen, Literal: "(", Pos: startPos}, nil
	case ')':
		l.readChar()
		return Token{Type: TokenRParen, Literal: ")", Pos: startPos}, nil
	case ',':
		l.readChar()
		return Token{Type: TokenComma, Literal: ",", Pos: startPos}, nil
	case '!':
		if l.peekChar() == '=' {
			l.readChar()
			l.readChar()
			return Token{Type: TokenOp, Literal: "!=", Pos: startPos}, nil
		}
		l.readChar()
		return Token{Type: TokenOp, Literal: "!", Pos: startPos}, nil
	case '=':
		if l.peekChar() == '=' {
			l.readChar()
			l.readChar()
			return Token{Type: TokenOp, Literal: "==", Pos: startPos}, nil
		}
		return Token{}, fmt.Errorf("unexpected token '=' at position %d (did you mean '=='?)", startPos)
	case '&':
		if l.peekChar() == '&' {
			l.readChar()
			l.readChar()
			return Token{Type: TokenOp, Literal: "&&", Pos: startPos}, nil
		}
		return Token{}, fmt.Errorf("unexpected character '&' at position %d", startPos)
	case '|':
		if l.peekChar() == '|' {
			l.readChar()
			l.readChar()
			return Token{Type: TokenOp, Literal: "||", Pos: startPos}, nil
		}
		return Token{}, fmt.Errorf("unexpected character '|' at position %d", startPos)
	case '<':
		if l.peekChar() == '=' {
			l.readChar()
			l.readChar()
			return Token{Type: TokenOp, Literal: "<=", Pos: startPos}, nil
		}
		l.readChar()
		return Token{Type: TokenOp, Literal: "<", Pos: startPos}, nil
	case '>':
		if l.peekChar() == '=' {
			l.readChar()
			l.readChar()
			return Token{Type: TokenOp, Literal: ">=", Pos: startPos}, nil
		}
		l.readChar()
		return Token{Type: TokenOp, Literal: ">", Pos: startPos}, nil
	case '\'':
		return l.readString(startPos)
	default:
		if isDigit(l.ch) {
			return l.readNumber(startPos)
		}
		if isIdentStart(l.ch) {
			return l.readIdentifier(startPos)
		}
		ch := l.ch
		l.readChar()
		return Token{}, fmt.Errorf("unknown character '%c' at position %d", ch, startPos)
	}
}

func (l *Lexer) readString(startPos int) (Token, error) {
	var sb strings.Builder
	l.readChar() // consume opening quote

	for {
		if l.ch == 0 {
			return Token{}, fmt.Errorf("unterminated string literal starting at position %d", startPos)
		}
		if l.ch == '\'' {
			if l.peekChar() == '\'' {
				// GitHub Actions escapes single quote via double single quote: ''
				sb.WriteByte('\'')
				l.readChar()
				l.readChar()
				continue
			}
			l.readChar() // consume closing quote
			break
		}
		if l.ch == '\\' && l.peekChar() == '\'' {
			// Support backslash escape as well
			sb.WriteByte('\'')
			l.readChar()
			l.readChar()
			continue
		}
		sb.WriteByte(l.ch)
		l.readChar()
	}

	return Token{Type: TokenString, Literal: sb.String(), Pos: startPos}, nil
}

func (l *Lexer) readNumber(startPos int) (Token, error) {
	var sb strings.Builder
	hasDot := false

	for isDigit(l.ch) || (l.ch == '.' && !hasDot && isDigit(l.peekChar())) {
		if l.ch == '.' {
			hasDot = true
		}
		sb.WriteByte(l.ch)
		l.readChar()
	}

	return Token{Type: TokenNumber, Literal: sb.String(), Pos: startPos}, nil
}

func (l *Lexer) readIdentifier(startPos int) (Token, error) {
	var sb strings.Builder
	for isIdentPart(l.ch) {
		sb.WriteByte(l.ch)
		l.readChar()
	}

	ident := sb.String()
	lower := strings.ToLower(ident)
	switch lower {
	case "true", "false":
		return Token{Type: TokenBool, Literal: lower, Pos: startPos}, nil
	case "null":
		return Token{Type: TokenNull, Literal: lower, Pos: startPos}, nil
	default:
		return Token{Type: TokenIdent, Literal: ident, Pos: startPos}, nil
	}
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isIdentStart(ch byte) bool {
	return unicode.IsLetter(rune(ch)) || ch == '_' || ch == '*'
}

func isIdentPart(ch byte) bool {
	return unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch)) || ch == '_' || ch == '-' || ch == '*'
}
