package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPath_FindsCommonIssues(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v.php")

	php := `<?php
$id = $_GET['id'];
$sql = "select * from users where id=" . $id;
mysqli_query($conn,
  $sql
);

$inc = $_REQUEST['p'];
if ($id) include $inc;

$c = $_POST['c'];
eval($c);

system($_GET["cmd"]);
unserialize($_POST['data']);
`

	if err := os.WriteFile(p, []byte(php), 0o644); err != nil {
		t.Fatalf("write php: %v", err)
	}

	report, err := ScanPath(context.Background(), p, Options{IncludeSubdirs: false})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatalf("expected findings, got 0")
	}

	got := map[string]bool{}
	for _, f := range report.Findings {
		got[f.Category] = true
	}

	wantCats := []string{"sqli", "file_include", "php_code_exec", "cmd_exec", "php_object_injection"}
	for _, c := range wantCats {
		if !got[c] {
			t.Fatalf("expected category %q, got categories: %+v, findings: %+v", c, got, report.Findings)
		}
	}
}

func TestFindCalls_MysqliQuery(t *testing.T) {
	stmt := "mysqli_query($conn,\n  $sql\n);\n"
	targets := map[string]struct{}{"mysqli_query": {}}
	calls := findCalls(stmt, targets, false)
	if len(calls) == 0 {
		t.Fatalf("expected calls, got 0")
	}
	if len(calls[0].Args) != 2 {
		t.Fatalf("expected 2 args, got %d: %#v", len(calls[0].Args), calls[0].Args)
	}
}

func TestStatementBuilder_EmitsMysqliQueryStatement(t *testing.T) {
	php := `<?php
$id = $_GET['id'];
$sql = "select * from users where id=" . $id;
mysqli_query($conn,
  $sql
);
`
	var (
		sb             statementBuilder
		inBlockComment bool
		lineNo         int
		found          bool
	)
	for _, line := range strings.SplitAfter(php, "\n") {
		lineNo++
		clean := stripComments(line, &inBlockComment)
		for _, st := range sb.Feed(clean, lineNo) {
			if strings.Contains(st.Text, "mysqli_query") {
				found = true
			}
		}
	}
	for _, st := range sb.Flush() {
		if strings.Contains(st.Text, "mysqli_query") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected mysqli_query statement to be emitted")
	}
}

func TestFuncSummary_PropagatesReturnTaint(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.php")
	php := `<?php
function getId() {
  return $_GET['id'];
}
$id = getId();
mysqli_query($conn, $id);
`
	if err := os.WriteFile(p, []byte(php), 0o644); err != nil {
		t.Fatalf("write php: %v", err)
	}
	report, err := ScanPath(context.Background(), p, Options{IncludeSubdirs: false})
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	got := map[string]bool{}
	for _, f := range report.Findings {
		got[f.Category] = true
	}
	if !got["sqli"] {
		t.Fatalf("expected sqli, got categories: %+v, findings: %+v", got, report.Findings)
	}
}
