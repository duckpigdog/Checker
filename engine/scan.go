package engine

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var phpExts = map[string]bool{
	".php":   true,
	".phtml": true,
	".inc":   true,
	".php5":  true,
	".php7":  true,
}

func ScanPath(ctx context.Context, target string, opt Options) (*Report, error) {
	if opt.MaxFileBytes <= 0 {
		opt.MaxFileBytes = 10 << 20
	}

	start := time.Now()
	target, _ = filepath.Abs(target)

	files, err := collectPHPFiles(target, opt.IncludeSubdirs)
	if err != nil {
		return nil, err
	}

	report := &Report{
		Target: target,
		Stats: Stats{
			StartedAt: start,
		},
	}

	rs := DefaultRuleset()
	rs.FuncSummaries = buildFuncSummaries(files, rs)
	applyTamper(&rs, target, files)
	root := target
	if st, err := os.Stat(target); err == nil && st.Mode().IsRegular() {
		root = filepath.Dir(target)
	}
	cfg := readCheckerConfig(root)
	for _, f := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		info, err := os.Stat(f)
		if err != nil {
			report.Stats.FilesSkipped++
			continue
		}
		if info.Size() > opt.MaxFileBytes {
			report.Stats.FilesSkipped++
			continue
		}

		findings, bytesRead, err := scanFile(ctx, f, rs, cfg)
		if err != nil {
			report.Stats.FilesSkipped++
			continue
		}
		report.Stats.FilesScanned++
		report.Stats.BytesRead += bytesRead
		report.Findings = append(report.Findings, findings...)
	}

	report.Findings = dedupeFindings(report.Findings)
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].File == report.Findings[j].File {
			return report.Findings[i].Line < report.Findings[j].Line
		}
		return report.Findings[i].File < report.Findings[j].File
	})

	report.Stats.FinishedAt = time.Now()
	return report, nil
}

func collectPHPFiles(target string, includeSubdirs bool) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	root := target
	if info.Mode().IsRegular() {
		ext := strings.ToLower(filepath.Ext(target))
		if phpExts[ext] {
			return []string{target}, nil
		}
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("target is not a file or directory")
	}

	ignore := readIgnorePatterns(target)

	var out []string
	walkFn := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if !includeSubdirs && path != target {
				return filepath.SkipDir
			}
			base := strings.ToLower(d.Name())
			if base == ".git" || base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			if shouldIgnorePath(root, path, ignore) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldIgnorePath(root, path, ignore) {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if phpExts[ext] {
			out = append(out, path)
		}
		return nil
	}

	if err := filepath.WalkDir(target, walkFn); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func readIgnorePatterns(root string) []string {
	var patterns []string
	tryFiles := []string{".checkerignore", ".kunlunmignore"}
	for _, name := range tryFiles {
		p := filepath.Join(root, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(strings.TrimRight(line, "\r"))
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "#") {
				continue
			}
			patterns = append(patterns, line)
		}
	}
	return patterns
}

func shouldIgnorePath(root, path string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	base := filepath.Base(path)
	for _, p := range patterns {
		pp := filepath.ToSlash(strings.TrimSpace(p))
		if pp == "" {
			continue
		}
		if ok, _ := filepath.Match(pp, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(pp, base); ok {
			return true
		}
		if strings.Contains(pp, "/") {
			if ok, _ := filepath.Match(pp, rel); ok {
				return true
			}
		} else {
			if ok, _ := filepath.Match(pp, base); ok {
				return true
			}
		}
	}
	return false
}

type varState struct {
	Tainted bool
	Source  Trace
}

var (
	reVarName = regexp.MustCompile(`\$\w+`)
	reVarLHS  = regexp.MustCompile(`(?i)^\s*(\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)\s*=\s*([\s\S]+)\s*$`)
)

func scanFile(ctx context.Context, filePath string, rs Ruleset, cfg CheckerConfig) ([]Finding, int64, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, 0, err
	}
	bytesRead := int64(len(b))
	lines := strings.Split(string(b), "\n")
	policy := mergePolicy(policyForPath(cfg, filePath), parseModeline(lines))
	if policy.Skip {
		return nil, bytesRead, nil
	}

	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	var (
		state          = map[string]varState{}
		findings       []Finding
		inBlockComment bool
		stmt           statementBuilder
	)

	lineNo := 0
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return nil, bytesRead, ctx.Err()
		default:
		}

		lineNo++
		line := sc.Text() + "\n"
		clean := stripComments(line, &inBlockComment)
		stmts := stmt.Feed(clean, lineNo)
		for _, s := range stmts {
			processStatement(ctx, filePath, s, rs, state, &findings, lines, policy)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, bytesRead, err
	}

	for _, s := range stmt.Flush() {
		processStatement(ctx, filePath, s, rs, state, &findings, lines, policy)
	}

	return findings, bytesRead, nil
}

func exprTaint(expr string, state map[string]varState, rs Ruleset) (bool, string) {
	return exprTaintDepth(expr, state, rs, 0)
}

func exprTaintDepth(expr string, state map[string]varState, rs Ruleset, depth int) (bool, string) {
	if depth > 5 {
		return false, ""
	}
	trim := strings.TrimSpace(expr)
	if trim == "" {
		return false, ""
	}

	for _, src := range rs.Sources {
		if src.MatchString(trim) {
			return true, src.String()
		}
	}

	for _, src := range rs.SourceFuncCalls {
		if src.MatchString(trim) {
			return true, src.String()
		}
	}

	if len(rs.FuncSummaries) > 0 {
		targets := map[string]struct{}{}
		for k := range rs.FuncSummaries {
			targets[k] = struct{}{}
		}
		for _, c := range findCalls(trim, targets, false) {
			sum, ok := rs.FuncSummaries[c.Name]
			if !ok {
				continue
			}
			if sum.ReturnFromSource {
				return true, c.Name + "()"
			}
			for pos := range sum.ReturnFromArgs {
				if pos <= 0 || pos > len(c.Args) {
					continue
				}
				if t, _ := exprTaintDepth(c.Args[pos-1], state, rs, depth+1); t {
					return true, c.Name + "()"
				}
			}
		}
	}

	vars := reVarName.FindAllString(trim, -1)
	for _, v := range vars {
		if st, ok := state[v]; ok && st.Tainted {
			return true, v
		}
	}

	return false, ""
}

type statement struct {
	Text      string
	StartLine int
}

type statementBuilder struct {
	buf          strings.Builder
	startLine    int
	inStr        byte
	escaped      bool
	parenDepth   int
	bracketDepth int
}

func (b *statementBuilder) Feed(line string, lineNo int) []statement {
	var out []statement
	if b.startLine == 0 && strings.TrimSpace(line) == "" {
		return nil
	}
	if b.startLine == 0 {
		b.startLine = lineNo
	}

	for i := 0; i < len(line); i++ {
		ch := line[i]
		b.buf.WriteByte(ch)

		if b.escaped {
			b.escaped = false
			continue
		}
		if b.inStr != 0 {
			if ch == '\\' {
				b.escaped = true
				continue
			}
			if ch == b.inStr {
				b.inStr = 0
			}
			continue
		}

		switch ch {
		case '\'', '"', '`':
			b.inStr = ch
		case '(':
			b.parenDepth++
		case ')':
			if b.parenDepth > 0 {
				b.parenDepth--
			}
		case '[':
			b.bracketDepth++
		case ']':
			if b.bracketDepth > 0 {
				b.bracketDepth--
			}
		case ';':
			if b.parenDepth == 0 && b.bracketDepth == 0 && b.inStr == 0 {
				text := b.buf.String()
				out = append(out, statement{Text: text, StartLine: b.startLine})
				b.reset()
				b.startLine = lineNo
			}
		}
	}
	return out
}

func (b *statementBuilder) Flush() []statement {
	if strings.TrimSpace(b.buf.String()) == "" {
		b.reset()
		return nil
	}
	s := statement{Text: b.buf.String(), StartLine: b.startLine}
	b.reset()
	return []statement{s}
}

func (b *statementBuilder) reset() {
	b.buf.Reset()
	b.startLine = 0
	b.inStr = 0
	b.escaped = false
	b.parenDepth = 0
	b.bracketDepth = 0
}

type sinkHit struct {
	Sink string
	Arg  string
	Pos  int
}

func processStatement(ctx context.Context, filePath string, s statement, rs Ruleset, state map[string]varState, findings *[]Finding, lines []string, policy filePolicy) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	stmtText := s.Text
	stmtScan := stripPHPTags(stmtText)
	stmtScan = stripStatementPreamble(stmtScan)
	if strings.TrimSpace(stmtScan) == "" {
		return
	}

	trimStmt := strings.TrimSpace(stmtScan)
	trimStmt = strings.TrimSuffix(trimStmt, ";")
	if strings.HasPrefix(strings.TrimSpace(trimStmt), "$") {
		if m := reVarLHS.FindStringSubmatch(trimStmt); len(m) == 3 {
			varName := strings.TrimSpace(m[1])
			rhs := strings.TrimSpace(m[2])
			tainted, src := exprTaint(rhs, state, rs)
			if tainted {
				state[varName] = varState{Tainted: true, Source: Trace{Kind: "source", File: filePath, Line: s.StartLine, Text: src}}
			} else {
				state[varName] = varState{Tainted: false}
			}
		}
	}

	low := strings.ToLower(stmtScan)
	for _, cat := range rs.Categories {
		for _, sink := range cat.Sinks {
			hits := findSinkHits(stmtScan, low, sink)
			for _, hit := range hits {
				arg := strings.TrimSpace(hit.Arg)
				if arg == "" {
					continue
				}

				tainted, src := exprTaint(arg, state, rs)
				if !tainted {
					continue
				}

				line := s.StartLine + strings.Count(stmtScan[:minInt(hit.Pos, len(stmtScan))], "\n")
				evidence := strings.TrimSpace(stmtScan)

				sev := cat.Severity
				fixedHint := ""
				if isSanitized(arg, cat.Sanitizers, rs.InverseSanitizers) {
					sev = SeverityLow
					fixedHint = "detected sanitizer wrapper; verify context correctness"
				}

				if shouldSkipFinding(lines, line, cat.Name, policy) {
					continue
				}

				id := stableID(filePath, line, cat.Name, sink.Name, evidence)
				trace := buildTrace(filePath, line, sink.Name, src, state, arg, rs)

				*findings = append(*findings, Finding{
					ID:        id,
					Category:  cat.Name,
					Severity:  sev,
					File:      filePath,
					Line:      line,
					Sink:      sink.Name,
					Evidence:  truncateOneLine(evidence, 240),
					Message:   fmt.Sprintf("tainted data reaches %s sink", sink.Name),
					Trace:     trace,
					FixedHint: fixedHint,
				})
			}
		}
	}
}

func findSinkHits(stmt string, low string, sink SinkRule) []sinkHit {
	switch sink.Kind {
	case SinkBackticks:
		return findBackticks(stmt)
	case SinkStatement:
		return findStatementHits(stmt, low, sink)
	case SinkFunction:
		return findCallHits(stmt, sink, false)
	case SinkMethod:
		return findCallHits(stmt, sink, true)
	default:
		return nil
	}
}

func findStatementHits(stmt string, low string, sink SinkRule) []sinkHit {
	var hits []sinkHit
	for _, kw := range sink.Targets {
		k := strings.ToLower(kw)
		for idx := 0; idx < len(low); {
			pos := strings.Index(low[idx:], k)
			if pos < 0 {
				break
			}
			pos += idx
			if !isWordBoundary(low, pos, pos+len(k)) {
				idx = pos + len(k)
				continue
			}

			expr, exprPos := extractKeywordExpr(stmt, pos+len(k))
			if expr != "" {
				parts := splitTopLevel(expr)
				for _, p := range parts {
					hits = append(hits, sinkHit{Sink: sink.Name, Arg: p, Pos: pos})
				}
			}
			if exprPos > pos {
				idx = exprPos
			} else {
				idx = pos + len(k)
			}
		}
	}
	return hits
}

func extractKeywordExpr(stmt string, from int) (string, int) {
	i := from
	for i < len(stmt) && (stmt[i] == ' ' || stmt[i] == '\t' || stmt[i] == '\n' || stmt[i] == '\r') {
		i++
	}
	if i >= len(stmt) {
		return "", i
	}
	if stmt[i] == '(' {
		content, end, ok := extractParenContent(stmt, i)
		if !ok {
			return "", i
		}
		return strings.TrimSpace(content), end
	}
	expr := strings.TrimSpace(strings.TrimSuffix(stmt[i:], ";"))
	return expr, len(stmt)
}

func findCallHits(stmt string, sink SinkRule, isMethod bool) []sinkHit {
	targetSet := map[string]struct{}{}
	for _, t := range sink.Targets {
		targetSet[strings.ToLower(t)] = struct{}{}
	}

	var hits []sinkHit
	calls := findCalls(stmt, targetSet, isMethod)
	for _, c := range calls {
		if sink.Predicate != nil && !sink.Predicate(c.Args) {
			continue
		}
		for _, pos := range sink.ParamPositions {
			if pos == 0 {
				for _, a := range c.Args {
					hits = append(hits, sinkHit{Sink: sink.Name, Arg: a, Pos: c.Pos})
				}
				continue
			}
			if pos-1 >= 0 && pos-1 < len(c.Args) {
				hits = append(hits, sinkHit{Sink: sink.Name, Arg: c.Args[pos-1], Pos: c.Pos})
			}
		}
	}
	return hits
}

type call struct {
	Name string
	Args []string
	Pos  int
}

func findCalls(s string, targets map[string]struct{}, isMethod bool) []call {
	var out []call
	inStr := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
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

		if isMethod {
			if i+2 >= len(s) {
				continue
			}
			if !(s[i] == '-' && s[i+1] == '>') && !(s[i] == ':' && s[i+1] == ':') {
				continue
			}
			opPos := i
			i += 2
			for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
				i++
			}
			nameStart := i
			for i < len(s) && (isIdentChar(s[i]) || s[i] == '\\') {
				i++
			}
			if nameStart == i {
				i = opPos
				continue
			}
			name := strings.ToLower(baseIdent(s[nameStart:i]))
			if _, ok := targets[name]; !ok {
				i = nameStart
				continue
			}
			j := i
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			if j >= len(s) || s[j] != '(' {
				i = nameStart
				continue
			}
			content, end, ok := extractParenContent(s, j)
			if !ok {
				i = nameStart
				continue
			}
			out = append(out, call{Name: name, Args: splitArgs(content), Pos: nameStart})
			i = end
			continue
		}

		if !isIdentStart(s[i]) && s[i] != '\\' {
			continue
		}
		nameStart := i
		for i < len(s) && (isIdentChar(s[i]) || s[i] == '\\') {
			i++
		}
		nameToken := s[nameStart:i]
		name := strings.ToLower(baseIdent(nameToken))
		if _, ok := targets[name]; !ok {
			i = nameStart
			continue
		}
		if isFunctionDefinition(s, nameStart) {
			i = nameStart
			continue
		}
		j := i
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
			j++
		}
		if j >= len(s) || s[j] != '(' {
			i = nameStart
			continue
		}
		content, end, ok := extractParenContent(s, j)
		if !ok {
			i = nameStart
			continue
		}
		out = append(out, call{Name: name, Args: splitArgs(content), Pos: nameStart})
		i = end
	}
	return out
}

func findBackticks(s string) []sinkHit {
	var hits []sinkHit
	inStr := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
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
		if ch == '\'' || ch == '"' {
			inStr = ch
			continue
		}
		if ch != '`' {
			continue
		}
		start := i
		i++
		var b strings.Builder
		for i < len(s) {
			cc := s[i]
			if cc == '\\' {
				if i+1 < len(s) {
					b.WriteByte(s[i])
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
			}
			if cc == '`' {
				break
			}
			b.WriteByte(cc)
			i++
		}
		if i < len(s) && s[i] == '`' {
			hits = append(hits, sinkHit{Sink: "backticks", Arg: b.String(), Pos: start})
		}
	}
	return hits
}

func extractParenContent(s string, openIdx int) (string, int, bool) {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != '(' {
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
		if ch == '(' {
			depth++
			continue
		}
		if ch == ')' {
			depth--
			if depth == 0 {
				return s[openIdx+1 : i], i + 1, true
			}
		}
	}
	return "", openIdx, false
}

func splitArgs(content string) []string {
	return splitTopLevel(content)
}

func splitTopLevel(s string) []string {
	var out []string
	inStr := byte(0)
	escaped := false
	paren := 0
	brack := 0
	curly := 0
	start := 0
	for i := 0; i < len(s); i++ {
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
		case ',':
			if paren == 0 && brack == 0 && curly == 0 {
				part := strings.TrimSpace(s[start:i])
				if part != "" {
					out = append(out, part)
				}
				start = i + 1
			}
		}
	}
	last := strings.TrimSpace(s[start:])
	if last != "" {
		out = append(out, last)
	}
	return out
}

func isIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isIdentChar(ch byte) bool {
	return isIdentStart(ch) || (ch >= '0' && ch <= '9')
}

func baseIdent(s string) string {
	if idx := strings.LastIndex(s, "\\"); idx >= 0 {
		return s[idx+1:]
	}
	return s
}

func isFunctionDefinition(s string, namePos int) bool {
	i := namePos - 1
	for i >= 0 && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i--
	}
	if i <= 0 {
		return false
	}
	end := i + 1
	for i >= 0 && isIdentChar(s[i]) {
		i--
	}
	word := strings.ToLower(s[i+1 : end])
	return word == "function"
}

func isWordBoundary(s string, start int, end int) bool {
	if start > 0 {
		p := s[start-1]
		if isIdentChar(p) || p == '$' {
			return false
		}
	}
	if end < len(s) {
		n := s[end]
		if isIdentChar(n) {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func stripPHPTags(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "<?php") {
		t = strings.TrimSpace(t[len("<?php"):])
	} else if strings.HasPrefix(t, "<?= ") {
		t = strings.TrimSpace(t[len("<?= "):])
	} else if strings.HasPrefix(t, "<?=") {
		t = strings.TrimSpace(t[len("<?="):])
	} else if strings.HasPrefix(t, "<?") {
		t = strings.TrimSpace(t[len("<?"):])
	}
	t = strings.ReplaceAll(t, "?>", "")
	return t
}

func stripStatementPreamble(s string) string {
	t := s
	for {
		prev := t
		t = strings.TrimSpace(t)
		if strings.HasPrefix(t, "}") {
			t = strings.TrimSpace(t[1:])
		}
		if strings.HasPrefix(t, "{") {
			t = strings.TrimSpace(t[1:])
		}
		if strings.HasPrefix(t, "?>") {
			t = strings.TrimSpace(t[2:])
		}
		if t == prev {
			break
		}
	}
	return t
}

func isSanitized(expr string, sanitizers []string, inverse []string) bool {
	low := strings.ToLower(expr)
	for _, inv := range inverse {
		if strings.Contains(low, strings.ToLower(inv)+"(") {
			return false
		}
	}
	for _, s := range sanitizers {
		if strings.Contains(low, strings.ToLower(s)+"(") {
			return true
		}
	}
	return false
}

func buildTrace(file string, line int, sink string, src string, state map[string]varState, arg string, rs Ruleset) []Trace {
	var out []Trace
	out = append(out, Trace{Kind: "sink", File: file, Line: line, Text: sink})

	for _, r := range rs.Sources {
		if r.MatchString(arg) {
			out = append(out, Trace{Kind: "source", File: file, Line: line, Text: r.String()})
			return reverseTrace(out)
		}
	}

	for _, r := range rs.SourceFuncCalls {
		if r.MatchString(arg) {
			out = append(out, Trace{Kind: "source", File: file, Line: line, Text: r.String()})
			return reverseTrace(out)
		}
	}

	vars := reVarName.FindAllString(arg, -1)
	for _, v := range vars {
		if st, ok := state[v]; ok && st.Tainted {
			out = append(out, Trace{Kind: "var", File: file, Line: line, Text: v})
			if st.Source.Text != "" {
				out = append(out, Trace{Kind: "source", File: st.Source.File, Line: st.Source.Line, Text: st.Source.Text})
			}
			return reverseTrace(out)
		}
	}

	if src != "" {
		out = append(out, Trace{Kind: "source", File: file, Line: line, Text: src})
	}
	return reverseTrace(out)
}

func reverseTrace(in []Trace) []Trace {
	for i, j := 0, len(in)-1; i < j; i, j = i+1, j-1 {
		in[i], in[j] = in[j], in[i]
	}
	return in
}

func stableID(file string, line int, cat, sink, evidence string) string {
	h := sha1.New()
	io.WriteString(h, file)
	io.WriteString(h, "|")
	io.WriteString(h, fmt.Sprintf("%d", line))
	io.WriteString(h, "|")
	io.WriteString(h, cat)
	io.WriteString(h, "|")
	io.WriteString(h, sink)
	io.WriteString(h, "|")
	io.WriteString(h, evidence)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func dedupeFindings(in []Finding) []Finding {
	seen := map[string]bool{}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		key := fmt.Sprintf("%s|%d|%s|%s|%s", f.File, f.Line, f.Category, f.Sink, f.Evidence)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func truncateOneLine(s string, max int) string {
	t := strings.ReplaceAll(s, "\r", " ")
	t = strings.ReplaceAll(t, "\n", " ")
	t = strings.Join(strings.Fields(t), " ")
	if len(t) <= max {
		return t
	}
	return t[:max-1] + "…"
}

func stripComments(line string, inBlock *bool) string {
	s := line
	if *inBlock {
		if end := strings.Index(s, "*/"); end >= 0 {
			s = s[end+2:]
			*inBlock = false
		} else {
			return ""
		}
	}

	for {
		start := strings.Index(s, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(s[start+2:], "*/")
		if end >= 0 {
			s = s[:start] + s[start+2+end+2:]
			continue
		}
		s = s[:start]
		*inBlock = true
		break
	}

	inStr := byte(0)
	escaped := false
	for i := 0; i < len(s)-1; i++ {
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
		if ch == '"' || ch == '\'' {
			inStr = ch
			continue
		}
		if ch == '/' && s[i+1] == '/' {
			return s[:i]
		}
		if ch == '#' {
			return s[:i]
		}
	}
	return s
}
