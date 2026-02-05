package engine

import (
	"os"
	"regexp"
	"strings"
)

type FuncSummary struct {
	Name             string
	ReturnFromSource bool
	ReturnFromArgs   map[int]bool
}

var reFuncDef = regexp.MustCompile(`(?is)(^|[^\w$])function\s+&?\s*([a-zA-Z_\\][a-zA-Z0-9_\\]*)\s*\(`)

func buildFuncSummaries(files []string, rs Ruleset) map[string]FuncSummary {
	out := map[string]FuncSummary{}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		src := string(b)
		idxs := reFuncDef.FindAllStringSubmatchIndex(src, -1)
		for _, m := range idxs {
			if len(m) < 6 {
				continue
			}
			name := strings.ToLower(baseIdent(src[m[4]:m[5]]))
			openParen := strings.Index(src[m[0]:], "(")
			if openParen < 0 {
				continue
			}
			openParen = m[0] + openParen

			params, afterParen, ok := extractParenContent(src, openParen)
			if !ok {
				continue
			}

			i := afterParen
			for i < len(src) && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r') {
				i++
			}
			if i >= len(src) || src[i] != '{' {
				continue
			}
			body, _, ok := extractBraceContent(src, i)
			if !ok {
				continue
			}

			s := summarizeFunction(name, params, body, rs)
			if prev, ok := out[name]; ok {
				if s.ReturnFromSource {
					prev.ReturnFromSource = true
				}
				for k := range s.ReturnFromArgs {
					if prev.ReturnFromArgs == nil {
						prev.ReturnFromArgs = map[int]bool{}
					}
					prev.ReturnFromArgs[k] = true
				}
				out[name] = prev
			} else {
				out[name] = s
			}
		}
	}
	return out
}

func summarizeFunction(name string, paramList string, body string, rs Ruleset) FuncSummary {
	params := extractParamVars(paramList)
	paramIndex := map[string]int{}
	for i, p := range params {
		paramIndex[p] = i + 1
	}

	sum := FuncSummary{
		Name:           name,
		ReturnFromArgs: map[int]bool{},
	}

	for _, ret := range extractReturnExprs(body) {
		trim := strings.TrimSpace(ret)
		for _, src := range rs.Sources {
			if src.MatchString(trim) {
				sum.ReturnFromSource = true
				break
			}
		}
		for _, src := range rs.SourceFuncCalls {
			if src.MatchString(trim) {
				sum.ReturnFromSource = true
				break
			}
		}

		vars := reVarName.FindAllString(trim, -1)
		for _, v := range vars {
			if idx, ok := paramIndex[v]; ok {
				sum.ReturnFromArgs[idx] = true
			}
		}
	}

	if len(sum.ReturnFromArgs) == 0 {
		sum.ReturnFromArgs = nil
	}
	return sum
}

func extractParamVars(paramList string) []string {
	var vars []string
	seen := map[string]bool{}
	for _, v := range reVarName.FindAllString(paramList, -1) {
		if !seen[v] {
			seen[v] = true
			vars = append(vars, v)
		}
	}
	return vars
}

func extractReturnExprs(body string) []string {
	var out []string
	low := strings.ToLower(body)
	inStr := byte(0)
	escaped := false
	for i := 0; i < len(body); i++ {
		ch := body[i]
		if escaped {
			escaped = false
			continue
		}
		if inStr != 0 {
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inStr {
				inStr = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			inStr = ch
			continue
		}
		if !isIdentStart(ch) {
			continue
		}
		start := i
		for i < len(body) && isIdentChar(body[i]) {
			i++
		}
		word := low[start:i]
		if word != "return" {
			i = start
			continue
		}
		if !isWordBoundary(low, start, i) {
			i = start
			continue
		}
		expr, _ := extractUntilSemicolon(body, i)
		if strings.TrimSpace(expr) != "" {
			out = append(out, expr)
		}
	}
	return out
}

func extractUntilSemicolon(s string, from int) (string, int) {
	i := from
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	start := i
	inStr := byte(0)
	escaped := false
	paren := 0
	brack := 0
	curly := 0
	for i < len(s) {
		ch := s[i]
		if escaped {
			escaped = false
			i++
			continue
		}
		if inStr != 0 {
			if ch == '\\' {
				escaped = true
				i++
				continue
			}
			if ch == inStr {
				inStr = 0
			}
			i++
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			inStr = ch
			i++
			continue
		}
		switch ch {
		case '(':
			paren++
		case ')':
			if paren > 0 {
				paren--
			}
		case '[':
			brack++
		case ']':
			if brack > 0 {
				brack--
			}
		case '{':
			curly++
		case '}':
			if curly > 0 {
				curly--
			}
		case ';':
			if paren == 0 && brack == 0 && curly == 0 {
				return strings.TrimSpace(s[start:i]), i + 1
			}
		}
		i++
	}
	return strings.TrimSpace(s[start:]), i
}

func extractBraceContent(s string, openIdx int) (string, int, bool) {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != '{' {
		return "", openIdx, false
	}
	depth := 0
	inStr := byte(0)
	escaped := false
	for i := openIdx; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inStr != 0 {
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inStr {
				inStr = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			inStr = ch
			continue
		}
		if ch == '{' {
			depth++
			continue
		}
		if ch == '}' {
			depth--
			if depth == 0 {
				return s[openIdx+1 : i], i + 1, true
			}
		}
	}
	return "", openIdx, false
}
