package engine

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type filePolicy struct {
	Ignore map[string]bool
	Select map[string]bool
	Skip   bool
}

type fileRule struct {
	Pattern string
	Policy  filePolicy
}

type CheckerConfig struct {
	Root    string
	Default filePolicy
	Rules   []fileRule
}

func readCheckerConfig(root string) CheckerConfig {
	cfg := CheckerConfig{Root: root, Default: filePolicy{Ignore: map[string]bool{}, Select: map[string]bool{}}}
	tryFiles := []string{"checker.ini", ".checker.ini"}
	var data []string
	for _, name := range tryFiles {
		p := filepath.Join(root, name)
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			data = append(data, sc.Text())
		}
		f.Close()
		break
	}
	if len(data) == 0 {
		return cfg
	}

	section := "checker"
	for _, raw := range data {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if name == "" {
				continue
			}
			section = strings.ToLower(name)
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		if section == "checker" || section == "default" {
			applyPolicyKV(&cfg.Default, key, val)
			continue
		}
		pat := section
		if strings.HasPrefix(pat, "pattern:") {
			pat = strings.TrimSpace(strings.TrimPrefix(pat, "pattern:"))
		} else if strings.HasPrefix(pat, "file:") {
			pat = strings.TrimSpace(strings.TrimPrefix(pat, "file:"))
		}
		if pat == "" {
			continue
		}
		r := getOrCreateRule(&cfg, pat)
		applyPolicyKV(&r.Policy, key, val)
	}

	return cfg
}

func getOrCreateRule(cfg *CheckerConfig, pat string) *fileRule {
	for i := range cfg.Rules {
		if cfg.Rules[i].Pattern == pat {
			return &cfg.Rules[i]
		}
	}
	r := fileRule{Pattern: pat, Policy: filePolicy{Ignore: map[string]bool{}, Select: map[string]bool{}}}
	cfg.Rules = append(cfg.Rules, r)
	return &cfg.Rules[len(cfg.Rules)-1]
}

func applyPolicyKV(p *filePolicy, key, val string) {
	switch key {
	case "ignore":
		for _, v := range splitList(val) {
			p.Ignore[strings.ToLower(v)] = true
		}
	case "select":
		p.Select = map[string]bool{}
		for _, v := range splitList(val) {
			p.Select[strings.ToLower(v)] = true
		}
	case "skip":
		p.Skip = parseBool(val)
	}
}

func splitList(s string) []string {
	raw := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
	var out []string
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func policyForPath(cfg CheckerConfig, path string) filePolicy {
	p := clonePolicy(cfg.Default)
	rel, err := filepath.Rel(cfg.Root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	base := filepath.Base(path)
	for _, r := range cfg.Rules {
		if matchPattern(rel, base, r.Pattern) {
			if r.Policy.Skip {
				p.Skip = true
			}
			if len(r.Policy.Select) > 0 {
				p.Select = cloneSet(r.Policy.Select)
			}
			for k := range r.Policy.Ignore {
				p.Ignore[k] = true
			}
		}
	}
	return p
}

func clonePolicy(p filePolicy) filePolicy {
	return filePolicy{
		Ignore: cloneSet(p.Ignore),
		Select: cloneSet(p.Select),
		Skip:   p.Skip,
	}
}

func cloneSet(m map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func matchPattern(rel, base, pattern string) bool {
	pat := filepath.ToSlash(strings.TrimSpace(pattern))
	if pat == "" {
		return false
	}
	if ok, _ := filepath.Match(pat, rel); ok {
		return true
	}
	if ok, _ := filepath.Match(pat, base); ok {
		return true
	}
	return false
}

func parseModeline(lines []string) filePolicy {
	p := filePolicy{Ignore: map[string]bool{}, Select: map[string]bool{}}
	for i := 0; i < len(lines) && i < 3; i++ {
		line := lines[i]
		lower := strings.ToLower(line)
		pos := strings.Index(lower, "checker:")
		if pos < 0 {
			continue
		}
		rest := line[pos+len("checker:"):]
		parts := strings.Split(rest, ":")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := strings.TrimSpace(kv[1])
			applyPolicyKV(&p, key, val)
		}
	}
	return p
}

func mergePolicy(base filePolicy, override filePolicy) filePolicy {
	out := clonePolicy(base)
	if override.Skip {
		out.Skip = true
	}
	if len(override.Select) > 0 {
		out.Select = cloneSet(override.Select)
	}
	for k := range override.Ignore {
		out.Ignore[k] = true
	}
	return out
}

func shouldIgnoreLine(line string, category string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "noqa") || strings.Contains(lower, "checker:skip") {
		return true
	}
	idx := strings.Index(lower, "checker:ignore")
	if idx < 0 {
		return false
	}
	rest := lower[idx+len("checker:ignore"):]
	if strings.Contains(rest, "all") {
		return true
	}
	for _, v := range splitList(rest) {
		if strings.Contains(v, category) {
			return true
		}
	}
	return false
}

func shouldSkipFinding(lines []string, line int, category string, policy filePolicy) bool {
	cat := strings.ToLower(category)
	if policy.Skip {
		return true
	}
	if len(policy.Select) > 0 && !policy.Select[cat] {
		return true
	}
	if policy.Ignore[cat] {
		return true
	}
	if line <= 0 || line > len(lines) {
		return false
	}
	if shouldIgnoreLine(lines[line-1], cat) {
		return true
	}
	return false
}
