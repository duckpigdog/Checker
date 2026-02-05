package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func applyTamper(rs *Ruleset, target string, files []string) {
	root := target
	if st, err := os.Stat(target); err == nil && st.Mode().IsRegular() {
		root = filepath.Dir(target)
	}

	lowerFiles := map[string]bool{}
	for _, f := range files {
		lowerFiles[strings.ToLower(filepath.Base(f))] = true
	}

	if lowerFiles["wp-config.php"] || hasDir(root, "wp-includes") {
		addSanitizers(rs, "xss", []string{"esc_url", "esc_js", "esc_html", "esc_attr", "esc_textarea", "tag_escape"})
		addSanitizers(rs, "sqli", []string{"esc_sql", "_real_escape"})
	}

	if hasDir(root, "program") && hasDir(root, "plugins") {
		addSourceFuncs(rs, []string{"get_input_value", "getprop", "login", "show"}...)
		addSourceFuncs(rs, []string{"rcube_utils::get_input_value"}...)
		addSanitizers(rs, "xss", []string{"Q"})
	}

	if hasDir(root, "thinkphp") || hasFilePrefix(lowerFiles, "thinkphp") {
		addSourceFuncs(rs, []string{"Input", "request", "I", "input"}...)
	}

	if hasFile(lowerFiles, "config.php") && hasDir(root, "includes") {
		addSourceRegex(rs, `(?i)\$request\b`)
	}
}

func addSanitizers(rs *Ruleset, category string, funcs []string) {
	for i := range rs.Categories {
		if rs.Categories[i].Name != category {
			continue
		}
		existing := map[string]bool{}
		for _, s := range rs.Categories[i].Sanitizers {
			existing[strings.ToLower(s)] = true
		}
		for _, f := range funcs {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			if !existing[strings.ToLower(f)] {
				rs.Categories[i].Sanitizers = append(rs.Categories[i].Sanitizers, f)
			}
		}
		return
	}
}

func addSourceFuncs(rs *Ruleset, funcs ...string) {
	var cleaned []string
	for _, f := range funcs {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		f = strings.ToLower(baseIdent(f))
		cleaned = append(cleaned, regexp.QuoteMeta(f))
	}
	if len(cleaned) == 0 {
		return
	}
	re := regexp.MustCompile(`(?i)\b(?:` + strings.Join(cleaned, "|") + `)\s*\(`)
	rs.SourceFuncCalls = append(rs.SourceFuncCalls, re)
}

func addSourceRegex(rs *Ruleset, pattern string) {
	rs.Sources = append(rs.Sources, regexp.MustCompile(pattern))
}

func hasDir(root, name string) bool {
	p := filepath.Join(root, name)
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func hasFile(files map[string]bool, name string) bool {
	return files[strings.ToLower(name)]
}

func hasFilePrefix(files map[string]bool, prefix string) bool {
	prefix = strings.ToLower(prefix)
	for k := range files {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}
