package engine

import (
	"regexp"
	"strings"
)

type RuleCategory struct {
	Name       string
	Severity   Severity
	Sinks      []SinkRule
	Sanitizers []string
}

type SinkKind string

const (
	SinkFunction  SinkKind = "function"
	SinkMethod    SinkKind = "method"
	SinkStatement SinkKind = "statement"
	SinkBackticks SinkKind = "backticks"
)

type ArgPredicate func(args []string) bool

type SinkRule struct {
	Name           string
	Kind           SinkKind
	Targets        []string
	ParamPositions []int
	Predicate      ArgPredicate
}

type Ruleset struct {
	Categories        []RuleCategory
	Sources           []*regexp.Regexp
	SourceFuncCalls   []*regexp.Regexp
	InverseSanitizers []string
	FuncSummaries     map[string]FuncSummary
}

func DefaultRuleset() Ruleset {
	must := func(p string) *regexp.Regexp { return regexp.MustCompile(p) }

	sources := []*regexp.Regexp{
		must(`(?i)\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b`),
		must(`(?i)\$(argc|argv)\b`),
		must(`(?i)\$(HTTP_GET_VARS|HTTP_POST_VARS|HTTP_COOKIE_VARS|HTTP_REQUEST_VARS|HTTP_POST_FILES|HTTP_SERVER_VARS|HTTP_RAW_POST_DATA)\b`),
	}

	sourceFuncs := []string{
		"get_headers",
		"getallheaders",
		"get_browser",
		"getenv",
		"gethostbyaddr",
		"import_request_variables",
		"fgets",
		"fgetss",
		"fread",
		"file",
		"file_get_contents",
		"glob",
		"scandir",
		"readdir",
		"mysql_fetch_array",
		"mysql_fetch_assoc",
		"mysql_fetch_field",
		"mysql_fetch_object",
		"mysql_fetch_row",
		"pg_fetch_all",
		"pg_fetch_array",
		"pg_fetch_assoc",
		"pg_fetch_object",
		"pg_fetch_result",
		"pg_fetch_row",
		"sqlite_fetch_all",
		"sqlite_fetch_array",
		"sqlite_fetch_object",
		"sqlite_fetch_single",
		"sqlite_fetch_string",
	}
	sourceFuncCalls := []*regexp.Regexp{
		must(`(?i)\b(?:` + strings.Join(sourceFuncs, "|") + `)\s*\(`),
	}

	stringSan := []string{
		"intval",
		"floatval",
		"doubleval",
		"filter_input",
		"urlencode",
		"rawurlencode",
		"strlen",
		"strpos",
		"strrpos",
		"md5",
		"sha1",
		"hash",
		"base64_encode",
		"count",
		"abs",
		"max",
		"min",
	}

	xssSan := []string{"htmlentities", "htmlspecialchars", "highlight_string"}
	sqlSan := []string{
		"addslashes",
		"dbx_escape_string",
		"db2_escape_string",
		"ingres_escape_string",
		"maxdb_escape_string",
		"maxdb_real_escape_string",
		"mysql_escape_string",
		"mysql_real_escape_string",
		"mysqli_escape_string",
		"mysqli_real_escape_string",
		"pg_escape_string",
		"pg_escape_bytea",
		"sqlite_escape_string",
		"sqlite_udf_encode_binary",
		"cubrid_real_escape_string",
	}
	pregSan := []string{"preg_quote"}
	cmdSan := []string{"escapeshellarg", "escapeshellcmd"}
	pathSan := []string{"basename", "dirname", "pathinfo", "realpath"}

	categories := []RuleCategory{
		{
			Name:       "xss",
			Severity:   SeverityHigh,
			Sanitizers: append(append([]string{}, xssSan...), stringSan...),
			Sinks: []SinkRule{
				{Name: "xss_output", Kind: SinkStatement, Targets: []string{"echo", "print", "print_r", "printf", "vprintf", "exit", "die", "trigger_error", "user_error"}, ParamPositions: []int{1}},
			},
		},
		{
			Name:       "sqli",
			Severity:   SeverityHigh,
			Sanitizers: append(append(append([]string{}, sqlSan...), stringSan...), "sprintf"),
			Sinks: []SinkRule{
				{
					Name:           "sql_exec_arg2",
					Kind:           SinkFunction,
					Targets:        []string{"dbx_query", "odbc_do", "odbc_exec", "odbc_execute", "db2_exec", "db2_execute", "fbsql_db_query", "ibase_query", "ingres_query", "ingres_execute", "ingres_unbuffered_query", "msql_db_query", "msql_query", "mssql_query", "mssql_execute", "mysql_db_query", "mysqli_query", "mysqli_master_query", "pg_query", "pg_send_query", "pg_send_query_params", "pg_send_prepare", "pg_prepare", "sqlite_query", "sqlite_exec", "sqlite_unbuffered_query", "sqlite_array_query"},
					ParamPositions: []int{2},
				},
				{
					Name:           "sql_exec_arg1",
					Kind:           SinkFunction,
					Targets:        []string{"dba_open", "dba_popen", "dba_insert", "dba_fetch", "dba_delete", "fbsql_query", "ifx_query", "ifx_do", "mysql_query", "mysql_unbuffered_query", "sqlite_query", "sqlite_exec"},
					ParamPositions: []int{1},
				},
				{
					Name:           "sql_prepare_like",
					Kind:           SinkFunction,
					Targets:        []string{"oci_parse"},
					ParamPositions: []int{2},
				},
				{
					Name:           "db_method_query",
					Kind:           SinkMethod,
					Targets:        []string{"query", "exec"},
					ParamPositions: []int{1},
				},
			},
		},
		{
			Name:       "cmd_exec",
			Severity:   SeverityHigh,
			Sanitizers: append(append([]string{}, cmdSan...), stringSan...),
			Sinks: []SinkRule{
				{
					Name:           "os_exec",
					Kind:           SinkFunction,
					Targets:        []string{"exec", "expect_popen", "passthru", "pcntl_exec", "popen", "proc_open", "shell_exec", "system"},
					ParamPositions: []int{1},
				},
				{Name: "backticks", Kind: SinkBackticks},
			},
		},
		{
			Name:       "file_include",
			Severity:   SeverityHigh,
			Sanitizers: append(append([]string{}, pathSan...), stringSan...),
			Sinks: []SinkRule{
				{Name: "include", Kind: SinkStatement, Targets: []string{"include", "include_once", "require", "require_once"}, ParamPositions: []int{1}},
				{Name: "set_include_path", Kind: SinkFunction, Targets: []string{"set_include_path", "runkit_import", "virtual"}, ParamPositions: []int{1}},
			},
		},
		{
			Name:       "file_access",
			Severity:   SeverityMedium,
			Sanitizers: append(append([]string{}, pathSan...), stringSan...),
			Sinks: []SinkRule{
				{Name: "file_read", Kind: SinkFunction, Targets: []string{"file", "file_get_contents", "readfile", "readgzfile", "show_source", "highlight_file", "parse_ini_file", "simplexml_load_file", "zip_open", "opendir", "scandir"}, ParamPositions: []int{1}},
				{Name: "file_write", Kind: SinkFunction, Targets: []string{"file_put_contents", "fwrite", "fputs", "fprintf", "rename", "unlink", "copy", "mkdir", "rmdir", "touch", "move_uploaded_file"}, ParamPositions: []int{1, 2}},
			},
		},
		{
			Name:       "php_code_exec",
			Severity:   SeverityHigh,
			Sanitizers: append(append(append([]string{}, pregSan...), stringSan...), cmdSan...),
			Sinks: []SinkRule{
				{Name: "eval_like", Kind: SinkFunction, Targets: []string{"eval", "assert", "create_function"}, ParamPositions: []int{1, 2}},
				{
					Name:           "preg_replace_e",
					Kind:           SinkFunction,
					Targets:        []string{"preg_replace", "preg_filter", "mb_ereg_replace", "mb_eregi_replace"},
					ParamPositions: []int{2},
					Predicate: func(args []string) bool {
						if len(args) == 0 {
							return false
						}
						return strings.Contains(strings.ToLower(args[0]), "e")
					},
				},
			},
		},
		{
			Name:       "php_object_injection",
			Severity:   SeverityHigh,
			Sanitizers: append([]string{}, stringSan...),
			Sinks: []SinkRule{
				{Name: "unserialize", Kind: SinkFunction, Targets: []string{"unserialize", "yaml_parse"}, ParamPositions: []int{1}},
			},
		},
	}

	return Ruleset{
		Categories:        categories,
		Sources:           sources,
		SourceFuncCalls:   sourceFuncCalls,
		InverseSanitizers: []string{"urldecode", "rawurldecode", "htmlspecialchars_decode", "html_entity_decode", "base64_decode"},
	}
}
