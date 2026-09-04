package parser

import (
	"strings"
)

// ExtractExpressions scans a block of text and extracts all interpolated ${{ ... }} expressions.
// Operates in linear O(N) time with a zero-regex state machine that respects string literal boundaries.
func ExtractExpressions(content string) []string {
	if content == "" {
		return nil
	}

	var results []string
	n := len(content)
	i := 0

	for i < n-2 {
		// Look for opening ${{
		if content[i] == '$' && content[i+1] == '{' && content[i+2] == '{' {
			start := i + 3
			j := start
			inString := false

			for j < n {
				if content[j] == '\'' {
					if inString && j+1 < n && content[j+1] == '\'' {
						j += 2 // skip escaped quote ''
						continue
					}
					inString = !inString
					j++
					continue
				}

				if !inString && j < n-1 && content[j] == '}' && content[j+1] == '}' {
					expr := strings.TrimSpace(content[start:j])
					if expr != "" {
						results = append(results, expr)
					}
					i = j + 2
					break
				}
				j++
			}

			if j >= n {
				// Unterminated ${{ block, advance past prefix
				i += 3
			}
		} else {
			i++
		}
	}

	return results
}
