package ui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"checker/engine"
)

type server struct {
	mu   sync.Mutex
	jobs map[string]*job
}

func Run() {
	s := &server{
		jobs: map[string]*job{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/job/", s.handleJob)
	mux.HandleFunc("/api/context", s.handleContext)
	mux.HandleFunc("/api/export", s.handleExport)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := "http://" + ln.Addr().String() + "/"

	go func() {
		_ = http.Serve(ln, mux)
	}()

	fmt.Println("Checker UI:", addr)
	_ = openBrowser(addr)
	select {}
}

type jobStatus string

const (
	jobQueued   jobStatus = "queued"
	jobRunning  jobStatus = "running"
	jobDone     jobStatus = "done"
	jobError    jobStatus = "error"
	jobCanceled jobStatus = "canceled"
)

type job struct {
	ID       string
	Target   string
	Subdirs  bool
	Status   jobStatus
	Error    string
	Started  time.Time
	Finished time.Time
	Report   *engine.Report
	cancel   context.CancelFunc
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path    string `json:"path"`
		Subdirs bool   `json:"subdirs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	req.Path = strings.TrimSpace(req.Path)
	if req.Path == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}

	id := newID()
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{
		ID:      id,
		Target:  req.Path,
		Subdirs: req.Subdirs,
		Status:  jobQueued,
		cancel:  cancel,
	}

	s.mu.Lock()
	s.jobs[id] = j
	s.mu.Unlock()

	go func() {
		s.updateJob(id, func(j *job) {
			j.Status = jobRunning
			j.Started = time.Now()
		})

		report, err := engine.ScanPath(ctx, req.Path, engine.Options{IncludeSubdirs: req.Subdirs})
		if err != nil {
			if errorsIsCanceled(err) {
				s.updateJob(id, func(j *job) {
					j.Status = jobCanceled
					j.Finished = time.Now()
				})
				return
			}
			s.updateJob(id, func(j *job) {
				j.Status = jobError
				j.Error = err.Error()
				j.Finished = time.Now()
			})
			return
		}

		s.updateJob(id, func(j *job) {
			j.Status = jobDone
			j.Report = report
			j.Finished = time.Now()
		})
	}()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"jobId": id})
}

func (s *server) handleJob(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/job/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "job id required", http.StatusBadRequest)
		return
	}
	id := parts[0]

	if len(parts) == 2 && parts[1] == "cancel" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.mu.Lock()
		j := s.jobs[id]
		s.mu.Unlock()
		if j == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if j.cancel != nil {
			j.cancel()
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	j := s.jobs[id]
	s.mu.Unlock()
	if j == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	type resp struct {
		ID       string         `json:"id"`
		Target   string         `json:"target"`
		Status   jobStatus      `json:"status"`
		Error    string         `json:"error,omitempty"`
		Started  time.Time      `json:"started,omitempty"`
		Finished time.Time      `json:"finished,omitempty"`
		Summary  *summary       `json:"summary,omitempty"`
		Report   *engine.Report `json:"report,omitempty"`
	}
	out := resp{
		ID:       j.ID,
		Target:   j.Target,
		Status:   j.Status,
		Error:    j.Error,
		Started:  j.Started,
		Finished: j.Finished,
	}
	if j.Report != nil {
		out.Summary = summarize(j.Report)
		out.Report = j.Report
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

type summary struct {
	Findings int `json:"findings"`
	Files    int `json:"files"`
	Skipped  int `json:"skipped"`
}

func summarize(r *engine.Report) *summary {
	if r == nil {
		return nil
	}
	return &summary{
		Findings: len(r.Findings),
		Files:    r.Stats.FilesScanned,
		Skipped:  r.Stats.FilesSkipped,
	}
}

func (s *server) handleContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	file := q.Get("file")
	line, _ := strconv.Atoi(q.Get("line"))
	radius, _ := strconv.Atoi(q.Get("radius"))
	if radius <= 0 || radius > 50 {
		radius = 6
	}
	if file == "" || line <= 0 {
		http.Error(w, "file and line required", http.StatusBadRequest)
		return
	}

	ctxText, err := loadContextLines(file, line, radius)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"context": ctxText})
}

func (s *server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	jobID := q.Get("jobId")
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "json"
	}
	if jobID == "" {
		http.Error(w, "jobId required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	j := s.jobs[jobID]
	s.mu.Unlock()
	if j == nil || j.Report == nil {
		http.Error(w, "report not ready", http.StatusBadRequest)
		return
	}

	name := sanitizeFilename("checker-report-" + jobID)
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".csv"))
		_ = engine.WriteCSV(w, j.Report)
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".json"))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(buildExportJSON(j.Report))
	default:
		http.Error(w, "unsupported format", http.StatusBadRequest)
	}
}

type exportReport struct {
	Schema      string          `json:"schema"`
	GeneratedAt time.Time       `json:"generatedAt"`
	Target      string          `json:"target"`
	Stats       engine.Stats    `json:"stats"`
	Summary     *summary        `json:"summary,omitempty"`
	Findings    []exportFinding `json:"findings"`
}

type exportFinding struct {
	ID            string         `json:"id"`
	Category      string         `json:"category"`
	CategoryLabel string         `json:"categoryLabel"`
	Severity      string         `json:"severity"`
	SeverityLabel string         `json:"severityLabel"`
	File          string         `json:"file"`
	FileBase      string         `json:"fileBase"`
	Line          int            `json:"line"`
	Location      string         `json:"location"`
	Sink          string         `json:"sink"`
	Evidence      string         `json:"evidence"`
	Message       string         `json:"message"`
	Description   string         `json:"description"`
	FixedHint     string         `json:"fixedHint,omitempty"`
	Trace         []engine.Trace `json:"trace,omitempty"`
}

func buildExportJSON(report *engine.Report) exportReport {
	out := exportReport{
		Schema:      "checker.report.v2",
		GeneratedAt: time.Now(),
		Target:      report.Target,
		Stats:       report.Stats,
	}
	sum := summarize(report)
	if sum != nil {
		out.Summary = sum
	}
	out.Findings = make([]exportFinding, 0, len(report.Findings))
	for _, f := range report.Findings {
		label := categoryLabelGo(f.Category)
		sevLabel := severityLabelGo(f.Severity)
		base := fileBaseGo(f.File)
		loc := base
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", base, f.Line)
		}
		out.Findings = append(out.Findings, exportFinding{
			ID:            f.ID,
			Category:      f.Category,
			CategoryLabel: label,
			Severity:      string(f.Severity),
			SeverityLabel: sevLabel,
			File:          f.File,
			FileBase:      base,
			Line:          f.Line,
			Location:      loc,
			Sink:          f.Sink,
			Evidence:      f.Evidence,
			Message:       f.Message,
			Description:   simpleDescGo(f),
			FixedHint:     f.FixedHint,
			Trace:         f.Trace,
		})
	}
	return out
}

func categoryLabelGo(cat string) string {
	switch strings.ToLower(cat) {
	case "xss":
		return "XSS 跨站脚本"
	case "sqli":
		return "SQL 注入"
	case "file_include":
		return "文件包含"
	case "file_access":
		return "文件读写"
	case "cmd_exec":
		return "命令执行"
	case "php_code_exec":
		return "PHP 代码执行"
	case "php_object_injection":
		return "反序列化"
	default:
		return cat
	}
}

func severityLabelGo(sev engine.Severity) string {
	switch strings.ToLower(string(sev)) {
	case "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	case "info":
		return "提示"
	default:
		return string(sev)
	}
}

func fileBaseGo(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

func simpleDescGo(f engine.Finding) string {
	sev := severityLabelGo(f.Severity)
	cat := strings.ToLower(f.Category)
	sink := f.Sink
	var base string
	switch cat {
	case "xss":
		base = "可能存在 XSS（输出未过滤）"
	case "sqli":
		base = "可能存在 SQL 注入（输入进入数据库查询）"
	case "file_include":
		base = "可能存在 文件包含（路径可控）"
	case "file_access":
		base = "可能存在 文件读写风险（路径可控）"
	case "cmd_exec":
		base = "可能存在 命令执行（参数可控）"
	case "php_code_exec":
		base = "可能存在 PHP 代码执行（eval/assert 等）"
	case "php_object_injection":
		base = "可能存在 反序列化风险（对象注入）"
	default:
		base = categoryLabelGo(f.Category)
	}
	if sink != "" {
		return "风险：" + sev + " · " + base + " · 位置点：" + sink
	}
	return "风险：" + sev + " · " + base
}

func (s *server) updateJob(id string, fn func(*job)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[id]
	if j == nil {
		return
	}
	fn(j)
}

func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "checker-report"
	}
	invalid := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, ch := range invalid {
		s = strings.ReplaceAll(s, ch, "_")
	}
	return s
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:8])
}

func errorsIsCanceled(err error) bool {
	if err == nil {
		return false
	}
	return err == context.Canceled || strings.Contains(strings.ToLower(err.Error()), "canceled")
}

func loadContextLines(path string, line int, radius int) (string, error) {
	b, err := osReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(b), "\n")
	start := line - radius
	if start < 1 {
		start = 1
	}
	end := line + radius
	if end > len(lines) {
		end = len(lines)
	}

	var out strings.Builder
	for i := start; i <= end; i++ {
		prefix := "   "
		if i == line {
			prefix = " > "
		}
		out.WriteString(fmt.Sprintf("%s%5d | %s\n", prefix, i, strings.TrimRight(lines[i-1], "\r")))
	}
	return out.String(), nil
}

func osReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	case "darwin":
		return exec.Command("open", rawURL).Start()
	default:
		return exec.Command("xdg-open", rawURL).Start()
	}
}

const indexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Checker - PHP 代码审计</title>
  <style>
    :root{
      --background-deep:#020203;
      --background-base:#050506;
      --background-elevated:#0a0a0c;
      --surface:rgba(255,255,255,0.05);
      --surface-hover:rgba(255,255,255,0.08);
      --foreground:#EDEDEF;
      --foreground-muted:#8A8F98;
      --foreground-subtle:rgba(255,255,255,0.60);
      --accent:#5E6AD2;
      --accent-bright:#6872D9;
      --accent-glow:rgba(94,106,210,0.30);
      --border-default:rgba(255,255,255,0.06);
      --border-hover:rgba(255,255,255,0.10);
      --border-accent:rgba(94,106,210,0.30);
      --shadow-card:0 0 0 1px rgba(255,255,255,0.06),0 2px 20px rgba(0,0,0,0.45),0 0 60px rgba(0,0,0,0.18);
      --shadow-card-hover:0 0 0 1px rgba(255,255,255,0.10),0 10px 50px rgba(0,0,0,0.55),0 0 120px rgba(94,106,210,0.10);
      --shadow-cta:0 0 0 1px rgba(94,106,210,0.55),0 10px 30px rgba(94,106,210,0.25),inset 0 1px 0 0 rgba(255,255,255,0.22);
      --ease-expo:cubic-bezier(0.16, 1, 0.3, 1);
    }

    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0;
      color:var(--foreground);
      font-family:Inter,"Geist Sans",system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
      background:
        radial-gradient(ellipse at top, #0a0a0f 0%, var(--background-base) 50%, var(--background-deep) 100%);
      overflow-x:hidden;
    }

    body::before{
      content:"";
      position:fixed;
      inset:0;
      pointer-events:none;
      opacity:0.015;
      background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='220' height='220'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='220' height='220' filter='url(%23n)' opacity='.55'/%3E%3C/svg%3E");
      background-size:220px 220px;
      mix-blend-mode:overlay;
    }

    body::after{
      content:"";
      position:fixed;
      inset:0;
      pointer-events:none;
      opacity:0.02;
      background-image:
        linear-gradient(to right, rgba(255,255,255,0.08) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255,255,255,0.08) 1px, transparent 1px);
      background-size:64px 64px;
      mask-image:radial-gradient(ellipse at top, rgba(0,0,0,0.95), transparent 70%);
    }

    .bg{
      position:fixed;
      inset:-120px -120px -120px -120px;
      pointer-events:none;
      z-index:-1;
    }

    .blob{
      position:absolute;
      filter:blur(140px);
      transform:translate3d(0,0,0);
      opacity:0.9;
      animation:float 9s ease-in-out infinite;
    }

    .blob.b1{
      width:980px;height:1400px;
      left:50%; top:-260px;
      transform:translateX(-52%);
      background:radial-gradient(circle at 35% 25%, rgba(94,106,210,0.28), transparent 60%);
      animation-duration:9.5s;
    }
    .blob.b2{
      width:680px;height:860px;
      left:-220px; top:120px;
      background:radial-gradient(circle at 40% 40%, rgba(168,85,247,0.14), transparent 62%),
                 radial-gradient(circle at 65% 55%, rgba(94,106,210,0.12), transparent 60%);
      animation-duration:10.5s;
      animation-direction:reverse;
    }
    .blob.b3{
      width:560px;height:780px;
      right:-240px; top:240px;
      background:radial-gradient(circle at 40% 40%, rgba(56,189,248,0.10), transparent 60%),
                 radial-gradient(circle at 70% 60%, rgba(94,106,210,0.12), transparent 62%);
      animation-duration:8.8s;
    }
    .blob.b4{
      width:900px;height:520px;
      left:40%; bottom:-260px;
      background:radial-gradient(circle at 50% 50%, rgba(94,106,210,0.10), transparent 70%);
      animation-duration:11.2s;
    }

    @keyframes float{
      0%,100%{transform:translateY(0) rotate(0deg)}
      50%{transform:translateY(-18px) rotate(0.8deg)}
    }

    @media (prefers-reduced-motion: reduce){
      *{animation:none !important; transition:none !important; scroll-behavior:auto !important}
    }

    .wrap{max-width:1200px;margin:0 auto;padding:26px 22px 34px}
    .top{
      display:flex;
      gap:16px;
      align-items:flex-start;
      justify-content:space-between;
      padding:14px 16px;
      border:1px solid var(--border-default);
      border-radius:18px;
      background:linear-gradient(to bottom, rgba(255,255,255,0.07), rgba(255,255,255,0.03));
      box-shadow:var(--shadow-card);
      position:relative;
      overflow:hidden;
    }

    .top::before{
      content:"";
      position:absolute;
      inset:0;
      opacity:0;
      transition:opacity 240ms var(--ease-expo);
      background:radial-gradient(300px circle at var(--mx, 50%) var(--my, 20%), rgba(94,106,210,0.15), transparent 60%);
    }

    .top:hover::before{opacity:1}

    .brand{display:flex;gap:14px;align-items:center}
    .logo{
      width:42px;height:42px;border-radius:14px;
      background:
        radial-gradient(circle at 30% 30%, rgba(255,255,255,0.45), rgba(255,255,255,0.05) 55%),
        linear-gradient(180deg, rgba(94,106,210,0.9), rgba(94,106,210,0.35));
      box-shadow:0 0 0 1px rgba(94,106,210,0.40),0 12px 40px rgba(94,106,210,0.18);
    }

    .title{
      font-weight:600;
      font-size:18px;
      letter-spacing:-0.01em;
      line-height:1.1;
      background:linear-gradient(to bottom, rgba(255,255,255,1), rgba(255,255,255,0.75));
      -webkit-background-clip:text;
      background-clip:text;
      color:transparent;
    }

    .subtitle{
      margin-top:4px;
      color:var(--foreground-muted);
      font-size:12px;
      letter-spacing:0.02em;
    }

    .row{display:flex;gap:10px;align-items:center}
    .metaRow{display:flex;gap:10px;align-items:center;justify-content:flex-end;flex-wrap:wrap}

    .pill{
      display:inline-flex;
      align-items:center;
      gap:8px;
      padding:7px 10px;
      border-radius:999px;
      border:1px solid var(--border-default);
      background:rgba(255,255,255,0.03);
      color:var(--foreground-muted);
      font-size:12px;
      box-shadow:inset 0 1px 0 0 rgba(255,255,255,0.08);
    }

    .btn{
      appearance:none;
      border:0;
      border-radius:10px;
      padding:10px 12px;
      cursor:pointer;
      color:var(--foreground);
      background:rgba(255,255,255,0.05);
      box-shadow:inset 0 1px 0 0 rgba(255,255,255,0.10);
      transition:transform 220ms var(--ease-expo), background 220ms var(--ease-expo), box-shadow 220ms var(--ease-expo);
      font-weight:600;
      letter-spacing:-0.01em;
    }

    .btn:hover{background:rgba(255,255,255,0.08); transform:translateY(-1px)}
    .btn:active{transform:scale(0.98)}
    .btn:disabled{opacity:.55; cursor:not-allowed; transform:none}

    .btn.pri{
      background:linear-gradient(180deg, var(--accent), rgba(94,106,210,0.72));
      box-shadow:var(--shadow-cta);
    }
    .btn.pri:hover{background:linear-gradient(180deg, var(--accent-bright), rgba(104,114,217,0.78)); box-shadow:0 0 0 1px rgba(94,106,210,0.65),0 16px 40px rgba(94,106,210,0.25),inset 0 1px 0 0 rgba(255,255,255,0.25)}

    .btn.ghost{
      background:transparent;
      color:var(--foreground-muted);
    }
    .btn.ghost:hover{background:rgba(255,255,255,0.05); color:var(--foreground)}

    input[type=text]{
      width:100%;
      padding:12px 12px;
      border-radius:12px;
      border:1px solid rgba(255,255,255,0.10);
      background:#0F0F12;
      color:var(--foreground);
      outline:none;
      transition:border 220ms var(--ease-expo), box-shadow 220ms var(--ease-expo), background 220ms var(--ease-expo);
    }
    input[type=text]::placeholder{color:var(--foreground-subtle)}
    input[type=text]:focus{
      border-color:rgba(94,106,210,0.55);
      box-shadow:0 0 0 4px rgba(94,106,210,0.20);
      background:rgba(15,15,18,0.92);
    }

    .chk{display:flex;gap:10px;align-items:center;color:var(--foreground-muted);font-size:13px}
    .chk input{accent-color:var(--accent)}

    .stack{display:flex; flex-direction:column; gap:16px; margin-top:16px}

    .card{
      position:relative;
      border-radius:18px;
      border:1px solid var(--border-default);
      background:linear-gradient(to bottom, rgba(255,255,255,0.08), rgba(255,255,255,0.02));
      box-shadow:var(--shadow-card);
      overflow:hidden;
      transform:translate3d(0,0,0);
      transition:transform 260ms var(--ease-expo), box-shadow 260ms var(--ease-expo), border-color 260ms var(--ease-expo);
    }

    .card::before{
      content:"";
      position:absolute;
      inset:0;
      opacity:0;
      transition:opacity 240ms var(--ease-expo);
      background:radial-gradient(300px circle at var(--mx, 50%) var(--my, 20%), rgba(94,106,210,0.15), transparent 60%);
      pointer-events:none;
    }

    .card::after{
      content:"";
      position:absolute;
      left:0; right:0; top:0;
      height:1px;
      background:linear-gradient(to right, transparent, rgba(255,255,255,0.18), transparent);
      opacity:0.45;
      pointer-events:none;
    }

    .card:hover{
      border-color:var(--border-hover);
      box-shadow:var(--shadow-card-hover);
      transform:translateY(-3px);
    }
    .card:hover::before{opacity:1}

    .hd{
      padding:14px 16px 10px;
      border-bottom:1px solid rgba(255,255,255,0.06);
      display:flex;
      align-items:flex-end;
      justify-content:space-between;
      gap:12px;
    }
    .hdTitle{font-weight:600; letter-spacing:-0.01em; white-space:nowrap}
    .status{color:var(--foreground-muted); font-size:12px}
    .bd{padding:16px}

    .label{
      font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
      font-size:11px;
      letter-spacing:0.12em;
      color:var(--foreground-muted);
      text-transform:uppercase;
    }

    .footer{margin-top:14px;color:var(--foreground-muted); font-size:12px; line-height:1.6}

    .tableWrap{
      max-height:520px;
      overflow:auto;
      border-top:1px solid rgba(255,255,255,0.06);
      outline:none;
    }

    table{width:100%; border-collapse:separate; border-spacing:0}
    th,td{padding:11px 12px; border-bottom:1px solid rgba(255,255,255,0.06); font-size:13px}
    th{
      position:sticky; top:0; z-index:2;
      background:rgba(10,10,12,0.72);
      backdrop-filter:blur(10px);
      text-align:left;
      color:rgba(255,255,255,0.82);
      font-weight:600;
      letter-spacing:-0.01em;
    }

    tbody tr{cursor:pointer; transition:background 200ms var(--ease-expo)}
    tbody tr:hover{background:rgba(255,255,255,0.03)}
    tbody tr:hover td{border-bottom-color:rgba(255,255,255,0.08)}

    .badge{
      padding:3px 9px;
      border-radius:999px;
      font-size:12px;
      font-weight:700;
      display:inline-block;
      letter-spacing:0.02em;
    }
    .sev-high{background:rgba(255,93,93,.10); color:#ff8080; border:1px solid rgba(255,93,93,.22)}
    .sev-medium{background:rgba(255,209,102,.10); color:#ffd166; border:1px solid rgba(255,209,102,.22)}
    .sev-low{background:rgba(61,220,151,.10); color:#3ddc97; border:1px solid rgba(61,220,151,.20)}
    .sev-info{background:rgba(93,214,255,.10); color:#5dd6ff; border:1px solid rgba(93,214,255,.20)}

    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
    .detail{
      white-space:pre-wrap;
      line-height:1.55;
      font-size:12px;
      color:rgba(255,255,255,0.82);
    }
    .muted{color:var(--foreground-muted)}

    .detailArea{
      padding:2px 0;
    }

    .metaChips{display:flex; align-items:center; gap:8px; flex-wrap:wrap; justify-content:flex-end}
    .chip{
      appearance:none;
      border:1px solid rgba(255,255,255,0.10);
      background:rgba(255,255,255,0.03);
      color:rgba(255,255,255,0.80);
      border-radius:999px;
      padding:6px 10px;
      cursor:pointer;
      font-size:12px;
      box-shadow:inset 0 1px 0 0 rgba(255,255,255,0.08);
      transition:transform 220ms var(--ease-expo), border-color 220ms var(--ease-expo), background 220ms var(--ease-expo);
    }
    .chip:hover{background:rgba(255,255,255,0.06); border-color:rgba(255,255,255,0.14); transform:translateY(-1px)}
    .chip:active{transform:scale(0.98)}

    .kbrd{
      display:inline-flex;
      align-items:center;
      padding:2px 8px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,0.10);
      background:rgba(255,255,255,0.03);
      color:rgba(255,255,255,0.70);
      font-size:12px;
      font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
    }

    .sepLine{
      height:1px;
      background:linear-gradient(to right, transparent, rgba(255,255,255,0.10), transparent);
      margin:14px 0;
    }

    [v-cloak]{display:none}

    tbody tr.rowSelected{background:rgba(94,106,210,0.12)}
    tbody tr.rowSelected td{border-bottom-color:rgba(94,106,210,0.25)}

    .resultBar{display:flex; align-items:center; justify-content:space-between; gap:12px; width:100%}
    .resultHd{align-items:center}
    .pager{display:flex; align-items:center; gap:10px; flex-wrap:wrap; justify-content:flex-end}
    .pagerInfo{display:flex; align-items:center; gap:8px; color:var(--foreground-muted); font-size:12px}
    .pagerBtn{
      appearance:none;
      border:1px solid rgba(255,255,255,0.10);
      background:rgba(255,255,255,0.03);
      color:rgba(255,255,255,0.80);
      border-radius:10px;
      padding:8px 10px;
      cursor:pointer;
      box-shadow:inset 0 1px 0 0 rgba(255,255,255,0.08);
      transition:transform 220ms var(--ease-expo), border-color 220ms var(--ease-expo), background 220ms var(--ease-expo);
    }
    .pagerBtn:hover{background:rgba(255,255,255,0.06); border-color:rgba(255,255,255,0.14); transform:translateY(-1px)}
    .pagerBtn:active{transform:scale(0.98)}
    .pagerBtn:disabled{opacity:.55; cursor:not-allowed; transform:none}
    .pagerBtn.pri{border-color:rgba(94,106,210,0.35); background:rgba(94,106,210,0.12)}

    .empty{
      padding:22px 16px;
      color:var(--foreground-muted);
      text-align:center;
      font-size:13px;
    }

    .detailSummary{
      color:rgba(255,255,255,0.70);
      font-size:12px;
      line-height:1.6;
      margin-bottom:10px;
    }
    .pathWrap{display:flex; flex-direction:column; gap:4px}
    .pathMain{display:flex; align-items:center; gap:8px; flex-wrap:wrap}
    .pathBtn{
      appearance:none;
      border:1px solid rgba(255,255,255,0.10);
      background:rgba(255,255,255,0.03);
      color:rgba(255,255,255,0.80);
      border-radius:999px;
      padding:5px 10px;
      cursor:pointer;
      font-size:12px;
      box-shadow:inset 0 1px 0 0 rgba(255,255,255,0.08);
      transition:transform 220ms var(--ease-expo), border-color 220ms var(--ease-expo), background 220ms var(--ease-expo);
    }
    .pathBtn:hover{background:rgba(255,255,255,0.06); border-color:rgba(255,255,255,0.14); transform:translateY(-1px)}
    .pathBtn:active{transform:scale(0.98)}
    .pathFull{
      color:rgba(255,255,255,0.70);
      font-size:12px;
      word-break:break-all;
    }

    .codePanel{
      border-radius:14px;
      border:1px solid rgba(255,255,255,0.10);
      background:rgba(0,0,0,0.35);
      box-shadow:inset 0 1px 0 0 rgba(255,255,255,0.06), 0 8px 30px rgba(0,0,0,0.35);
      overflow:auto;
      max-height:320px;
      scrollbar-width:thin;
      scrollbar-color:rgba(255,255,255,0.28) rgba(0,0,0,0.18);
    }
    .codePanel::-webkit-scrollbar{width:10px; height:10px}
    .codePanel::-webkit-scrollbar-track{background:rgba(0,0,0,0.18); border-radius:999px}
    .codePanel::-webkit-scrollbar-thumb{
      background:rgba(255,255,255,0.18);
      border:2px solid rgba(0,0,0,0.18);
      border-radius:999px;
    }
    .codePanel::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.26)}

    .codeRow{
      display:flex;
      gap:12px;
      padding:7px 12px;
      border-bottom:1px solid rgba(255,255,255,0.06);
    }
    .codeRow:last-child{border-bottom:0}
    .codeRow.sel{
      background:linear-gradient(to right, rgba(94,106,210,0.20), rgba(94,106,210,0.06));
      box-shadow:inset 3px 0 0 0 rgba(94,106,210,0.75);
    }
    .codeNo{
      width:72px;
      flex:0 0 72px;
      color:rgba(255,255,255,0.55);
      text-align:right;
    }
    .codeText{
      flex:1 1 auto;
      color:rgba(255,255,255,0.86);
      white-space:pre-wrap;
      word-break:break-word;
    }

    .hlSrc{
      color:#5dd6ff;
      background:rgba(93,214,255,0.12);
      border:1px solid rgba(93,214,255,0.22);
      padding:1px 6px;
      border-radius:999px;
    }
    .hlSink{
      color:#ffd166;
      background:rgba(255,209,102,0.18);
      border:1px solid rgba(255,209,102,0.36);
      padding:1px 6px;
      border-radius:999px;
      box-shadow:0 0 0 1px rgba(0,0,0,0.35), 0 0 24px rgba(255,209,102,0.10);
    }
    .hlVar{
      color:#EDEDEF;
      background:rgba(255,255,255,0.06);
      border:1px solid rgba(255,255,255,0.10);
      padding:1px 6px;
      border-radius:999px;
    }
    .hlVarStrong{
      color:#EDEDEF;
      background:rgba(94,106,210,0.12);
      border:1px solid rgba(94,106,210,0.26);
      padding:1px 6px;
      border-radius:999px;
    }

    .thBtn{
      appearance:none;
      border:0;
      background:transparent;
      color:inherit;
      padding:0;
      cursor:pointer;
      font:inherit;
      display:inline-flex;
      align-items:center;
      gap:6px;
    }
    .thBtn:hover{color:rgba(255,255,255,0.92)}
    .sortInd{color:rgba(94,106,210,0.9); font-size:12px}

    @media (max-width: 980px){
      .metaRow{justify-content:flex-start}
      .wrap{padding:18px 14px 28px}
    }
  </style>
</head>
<body>
  <div id="app" v-cloak>
    <div class="bg">
      <div class="blob b1"></div>
      <div class="blob b2"></div>
      <div class="blob b3"></div>
      <div class="blob b4"></div>
    </div>

    <div class="wrap">
      <div class="top" @pointermove="spotlightMove">
        <div class="brand">
          <div class="logo"></div>
          <div>
            <div class="title">Checker</div>
          </div>
        </div>
        <div class="metaRow">
          <span class="pill">{{ summaryText }}</span>
          <button class="btn" :disabled="!jobId || exporting" @click="exportReport('json')">导出 JSON</button>
        </div>
      </div>

      <div class="stack">
        <div class="card" @pointermove="spotlightMove">
          <div class="hd">
            <div>
              <div class="hdTitle">扫描目标</div>
            </div>
            <div class="status">{{ statusText }}</div>
          </div>
          <div class="bd">
            <div class="row" style="margin-bottom:12px">
              <input type="text" v-model.trim="path" @keydown.enter="startScan" placeholder="输入项目目录或 PHP 文件路径（例如 D:\www\project 或 /var/www/app）"/>
            </div>
            <div class="row" style="justify-content:space-between; flex-wrap:wrap">
              <label class="chk"><input type="checkbox" v-model="includeSubdirs"/> 扫描子目录</label>
              <div class="row">
                <button class="btn ghost" :disabled="!jobId || !running" @click="stopScan">停止</button>
                <button class="btn pri" :disabled="running" @click="startScan">开始扫描</button>
              </div>
            </div>
          </div>
        </div>
 
        <div class="card tableCard" @pointermove="spotlightMove">
        <div class="hd resultHd">
          <div>
            <div class="hdTitle">结果</div>
          </div>
          <div class="resultBar">
            <div class="row">
              <input type="text" v-model.trim="filter" placeholder="过滤：类型 / 文件 / 说明" style="width:340px"/>
            </div>
            <div class="pager">
              <button class="pagerBtn" :disabled="totalPages <= 1 || page <= 1" @click="prevPage">上一页</button>
              <div class="pagerInfo">
                <span>第 {{ page }} / {{ totalPages }} 页</span>
                <span>·</span>
                <span>{{ totalFindings }} 条</span>
                <span>·</span>
                <span>每页 5 条</span>
              </div>
              <button class="pagerBtn" :disabled="totalPages <= 1 || page >= totalPages" @click="nextPage">下一页</button>
            </div>
          </div>
        </div>
        <div class="tableWrap" tabindex="0" @keydown="onTableKeydown">
          <table>
            <thead>
              <tr>
                <th style="width:120px">
                  <button class="thBtn" @click="toggleSort('severity')">
                    风险
                    <span class="sortInd" v-if="sortKey === 'severity'">{{ sortDir === 'asc' ? '▲' : '▼' }}</span>
                  </button>
                </th>
                <th style="width:120px">
                  <button class="thBtn" @click="toggleSort('category')">
                    类型
                    <span class="sortInd" v-if="sortKey === 'category'">{{ sortDir === 'asc' ? '▲' : '▼' }}</span>
                  </button>
                </th>
                <th style="width:260px">位置</th>
                <th>说明</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="pagedFindings.length === 0">
                <td colspan="4" class="empty">暂无结果</td>
              </tr>
              <tr v-for="f in pagedFindings" :key="f.id" :class="{rowSelected: f.id === selectedId}" @click="selectFinding(f)">
                <td><span class="badge" :class="sevClass(f.severity)">{{ (f.severity || '').toUpperCase() }}</span></td>
                <td>{{ categoryLabel(f.category) }}</td>
                <td class="mono">
                  <div class="pathWrap">
                    <div class="pathMain">
                      <span>{{ fileBase(f.file) }}:{{ f.line }}</span>
                      <button class="pathBtn" @click.stop="copyText(f.file || '')">复制路径</button>
                      <button class="pathBtn" @click.stop="copyText((f.file || '') + ':' + String(f.line || ''))">复制行</button>
                    </div>
                    <div class="pathFull">{{ toRelative(f.file) }}</div>
                  </div>
                </td>
                <td :title="f.evidence">{{ simpleDesc(f) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

        <div class="card" @pointermove="spotlightMove">
          <div class="hd">
            <div>
              <div class="hdTitle">详情</div>
            </div>
            <div v-if="selectedFinding" class="metaChips">
              <button class="chip mono" :title="selectedFinding.file" @click="copyText((selectedFinding.file || '') + ':' + String(selectedFinding.line || ''))">{{ selectedFileBase }}</button>
              <button class="chip" @click="copyText(String(selectedFinding.line || ''))">L{{ selectedFinding.line }}</button>
              <button class="chip" @click="copyText(selectedFinding.category || '')">{{ selectedFinding.category }}</button>
              <span class="badge" :class="sevClass(selectedFinding.severity)">{{ (selectedFinding.severity || '').toUpperCase() }}</span>
            </div>
            <div v-else class="muted">未选择</div>
          </div>
          <div class="bd">
            <div v-if="selectedFinding" class="detailSummary">{{ simpleDesc(selectedFinding) }}</div>
            <div class="detail mono detailArea">{{ detailTrace }}</div>
            <div class="sepLine"></div>
            <div class="codePanel mono" v-if="contextLines.length">
              <div class="codeRow" :class="{sel: l.sel}" v-for="(l, idx) in contextLines" :key="idx">
                <div class="codeNo">{{ l.no }}</div>
                <div class="codeText" v-html="l.html"></div>
              </div>
            </div>
            <div v-else class="detail mono detailArea">{{ detailContext }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script src="https://unpkg.com/vue@3.4.38/dist/vue.global.prod.js"></script>
  <script>
    (function(){
      if(!window.Vue){
        const root = document.getElementById('app');
        if(root){
          root.innerHTML = '<div class="wrap"><div class="card"><div class="bd"><div class="hdTitle">Vue 资源加载失败</div><div class="footer">当前 UI 版本使用 Vue 运行时（CDN）。如果你的环境无法联网，请告诉我，我会把 Vue 运行时内置进 exe。</div></div></div></div>';
        }
        return;
      }

      const { createApp, ref, computed, watch } = Vue;

      createApp({
        setup(){
          const pageSize = 5;
          const path = ref('');
          const includeSubdirs = ref(true);
          const filter = ref('');
          const statusText = ref('就绪');
          const summaryText = ref('未扫描');
          const jobId = ref('');
          const report = ref(null);
          const running = ref(false);
          const exporting = ref(false);
          const selectedId = ref('');
          const selectedFinding = ref(null);
          const detailTrace = ref('');
          const detailContext = ref('');
          const page = ref(1);
          const sortKey = ref('');
          const sortDir = ref('asc');
          let pollTimer = 0;
          let ctxReqSeq = 0;

          const allFindings = computed(() => (report.value && report.value.findings) ? report.value.findings : []);
          const filteredFindings = computed(() => {
            const q = (filter.value || '').trim().toLowerCase();
            if(!q){ return allFindings.value; }
            return allFindings.value.filter(f => {
              const hay = [f.severity,f.category,f.file,f.sink,f.evidence,f.message].join(' ').toLowerCase();
              return hay.includes(q);
            });
          });

          const sortedFindings = computed(() => {
            const key = sortKey.value;
            const dir = sortDir.value;
            const arr = filteredFindings.value.slice();
            if(!key){ return arr; }
            const sRank = (sev) => {
              const v = String(sev || '').toLowerCase();
              if(v === 'high'){ return 3; }
              if(v === 'medium'){ return 2; }
              if(v === 'low'){ return 1; }
              if(v === 'info'){ return 0; }
              return -1;
            };
            arr.sort((a, b) => {
              if(key === 'severity'){
                const da = sRank(a.severity);
                const db = sRank(b.severity);
                if(da !== db){ return da - db; }
              } else if(key === 'category'){
                const ca = String(a.category || '').toLowerCase();
                const cb = String(b.category || '').toLowerCase();
                if(ca !== cb){ return ca < cb ? -1 : 1; }
              }
              const fa = String(a.file || '');
              const fb = String(b.file || '');
              if(fa !== fb){ return fa < fb ? -1 : 1; }
              return Number(a.line || 0) - Number(b.line || 0);
            });
            if(dir === 'desc'){ arr.reverse(); }
            return arr;
          });

          const totalFindings = computed(() => sortedFindings.value.length);
          const totalPages = computed(() => {
            const n = Math.ceil(totalFindings.value / pageSize);
            return n <= 0 ? 1 : n;
          });

          const pagedFindings = computed(() => {
            const p = page.value;
            const start = (p - 1) * pageSize;
            return sortedFindings.value.slice(start, start + pageSize);
          });

          function clampPage(){
            if(page.value < 1){ page.value = 1; return; }
            if(page.value > totalPages.value){ page.value = totalPages.value; }
          }

          function sevClass(sev){
            const s = (sev || '').toLowerCase();
            return s === 'high' ? 'sev-high' : s === 'medium' ? 'sev-medium' : s === 'low' ? 'sev-low' : 'sev-info';
          }

          function categoryLabel(cat){
            const c = String(cat || '').toLowerCase();
            if(c === 'xss'){ return 'XSS 跨站脚本'; }
            if(c === 'sqli'){ return 'SQL 注入'; }
            if(c === 'file_include'){ return '文件包含'; }
            if(c === 'file_access'){ return '文件读写'; }
            if(c === 'cmd_exec'){ return '命令执行'; }
            if(c === 'php_code_exec'){ return 'PHP 代码执行'; }
            if(c === 'php_object_injection'){ return '反序列化'; }
            return String(cat || '');
          }

          function fileBase(p){
            const parts = String(p || '').split(/[\\\\/]/);
            return parts[parts.length - 1] || String(p || '');
          }

          function toRelative(p){
            const root = (report.value && report.value.target) ? String(report.value.target) : '';
            if(!root || !p){ return String(p || ''); }
            const normRoot = root.replace(/[\\\/]+/g, '\\');
            const normPath = String(p).replace(/[\\\/]+/g, '\\');
            if(normPath.toLowerCase().startsWith(normRoot.toLowerCase())){
              let rel = normPath.slice(normRoot.length);
              rel = rel.replace(/^[\\\/]+/, '');
              return rel || fileBase(p);
            }
            return String(p);
          }

          function severityZh(sev){
            const s = String(sev || '').toLowerCase();
            if(s === 'high'){ return '高'; }
            if(s === 'medium'){ return '中'; }
            if(s === 'low'){ return '低'; }
            if(s === 'info'){ return '提示'; }
            return String(sev || '');
          }

          function simpleDesc(f){
            if(!f){ return ''; }
            const cat = String(f.category || '').toLowerCase();
            const sink = f.sink ? String(f.sink) : '';
            const sev = severityZh(f.severity);
            if(cat === 'xss'){ return '风险：' + sev + ' · 可能存在 XSS（输出未过滤）' + (sink ? ' · 位置点：' + sink : ''); }
            if(cat === 'sqli'){ return '风险：' + sev + ' · 可能存在 SQL 注入（输入进入数据库查询）' + (sink ? ' · 位置点：' + sink : ''); }
            if(cat === 'file_include'){ return '风险：' + sev + ' · 可能存在 文件包含（路径可控）' + (sink ? ' · 位置点：' + sink : ''); }
            if(cat === 'file_access'){ return '风险：' + sev + ' · 可能存在 文件读写风险（路径可控）' + (sink ? ' · 位置点：' + sink : ''); }
            if(cat === 'cmd_exec'){ return '风险：' + sev + ' · 可能存在 命令执行（参数可控）' + (sink ? ' · 位置点：' + sink : ''); }
            if(cat === 'php_code_exec'){ return '风险：' + sev + ' · 可能存在 PHP 代码执行（eval/assert 等）' + (sink ? ' · 位置点：' + sink : ''); }
            if(cat === 'php_object_injection'){ return '风险：' + sev + ' · 可能存在 反序列化风险（对象注入）' + (sink ? ' · 位置点：' + sink : ''); }
            return '风险：' + sev + ' · ' + categoryLabel(f.category) + (sink ? ' · 位置点：' + sink : '');
          }

          function spotlightMove(e){
            const c = e.currentTarget;
            if(!c){ return; }
            const r = c.getBoundingClientRect();
            const x = e.clientX - r.left;
            const y = e.clientY - r.top;
            c.style.setProperty('--mx', x + 'px');
            c.style.setProperty('--my', y + 'px');
          }

          function clearDetail(){
            selectedId.value = '';
            selectedFinding.value = null;
            detailTrace.value = '';
            detailContext.value = '';
          }

          const selectedFileBase = computed(() => {
            const f = selectedFinding.value;
            if(!f || !f.file){ return ''; }
            const parts = String(f.file).split(/[\\\/]/);
            return parts[parts.length - 1] || String(f.file);
          });

          const contextLines = computed(() => {
            const raw = String(detailContext.value || '');
            const lines = raw.split('\n').filter(x => x !== '');
            const out = [];
            const re = /^( > | {3})(\s*\d+)\s\|\s(.*)$/;
            const f = selectedFinding.value;

            function escapeHtml(s){
              return String(s || '')
                .replaceAll('&', '&amp;')
                .replaceAll('<', '&lt;')
                .replaceAll('>', '&gt;')
                .replaceAll('"', '&quot;')
                .replaceAll("'", '&#39;');
            }

            function escapeRegExp(s){
              return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            }

            function wrapRegex(html, rex, cls){
              return html.replace(rex, function(m){
                return '<span class="' + cls + '">' + m + '</span>';
              });
            }

            function buildKeyVars(ff){
              const ev = String((ff && ff.evidence) || '');
              const m = ev.match(/\$[A-Za-z_][A-Za-z0-9_]*/g) || [];
              const uniq = {};
              const vars = [];
              for(const v of m){
                if(!uniq[v]){
                  uniq[v] = true;
                  vars.push(v);
                }
              }
              return vars.slice(0, 6);
            }

            const keyVars = buildKeyVars(f);
            const sinkName = (f && f.sink) ? String(f.sink) : '';

            function highlightLine(text, isSel){
              let html = escapeHtml(text);
              html = wrapRegex(html, /(\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV))\b/gi, 'hlSrc');
              if(sinkName){
                const sinkRe = new RegExp(escapeRegExp(sinkName), 'gi');
                html = wrapRegex(html, sinkRe, 'hlSink');
              }
              for(const v of keyVars){
                const vr = new RegExp(escapeRegExp(v), 'g');
                html = wrapRegex(html, vr, isSel ? 'hlVarStrong' : 'hlVar');
              }
              return html;
            }

            for(const ln of lines){
              const m = re.exec(ln);
              if(m){
                const sel = m[1].trim() === '>';
                const no = String(m[2]).trim();
                const text = m[3];
                out.push({ sel, no, text, html: highlightLine(text, sel) });
              }else{
                out.push({ sel: false, no: '', text: ln, html: highlightLine(ln, false) });
              }
            }
            return out;
          });

          async function copyText(text){
            const t = String(text || '');
            if(!t){ return; }
            try{
              if(navigator && navigator.clipboard && navigator.clipboard.writeText){
                await navigator.clipboard.writeText(t);
                return;
              }
            }catch(e){}
            try{
              const ta = document.createElement('textarea');
              ta.value = t;
              ta.style.position = 'fixed';
              ta.style.left = '-9999px';
              ta.style.top = '0';
              document.body.appendChild(ta);
              ta.focus();
              ta.select();
              document.execCommand('copy');
              document.body.removeChild(ta);
            }catch(e){}
          }

          async function loadContext(f){
            if(!f){ return; }
            const seq = ++ctxReqSeq;
            detailContext.value = '加载上下文…';
            try{
              const u = new URL('/api/context', location.href);
              u.searchParams.set('file', f.file);
              u.searchParams.set('line', String(f.line));
              u.searchParams.set('radius', '6');
              const resp = await fetch(u);
              if(seq !== ctxReqSeq){ return; }
              if(!resp.ok){ detailContext.value = '无法读取上下文'; return; }
              const data = await resp.json();
              detailContext.value = data.context || '';
            }catch(e){
              if(seq !== ctxReqSeq){ return; }
              detailContext.value = '无法读取上下文';
            }
          }

          function formatTrace(f){
            return (f.trace || []).map(t => {
              const loc = (t.file && t.line) ? ('(' + String(t.file).split(/[\\\\/]/).pop() + ':' + t.line + ')') : '';
              const text = t.text ? (': ' + t.text) : '';
              return t.kind + loc + text;
            }).join('  ->  ') + (f.fixedHint ? ('\nHint: ' + f.fixedHint) : '');
          }

          function selectFinding(f){
            if(!f){ return; }
            selectedId.value = f.id || '';
            selectedFinding.value = f;
            detailTrace.value = formatTrace(f);
            loadContext(f);
          }

          function selectByIndex(i){
            const list = pagedFindings.value;
            if(!list || list.length === 0){ return; }
            if(i < 0){ i = 0; }
            if(i >= list.length){ i = list.length - 1; }
            selectFinding(list[i]);
          }

          function onTableKeydown(e){
            const list = pagedFindings.value;
            if(!list || list.length === 0){ return; }
            const cur = list.findIndex(x => x.id === selectedId.value);
            if(e.key === 'ArrowDown'){
              e.preventDefault();
              if(cur >= 0 && cur === list.length - 1){
                if(page.value < totalPages.value){
                  page.value = page.value + 1;
                  window.setTimeout(() => selectByIndex(0), 0);
                  return;
                }
              }
              selectByIndex(cur < 0 ? 0 : cur + 1);
              return;
            }
            if(e.key === 'ArrowUp'){
              e.preventDefault();
              if(cur >= 0 && cur === 0){
                if(page.value > 1){
                  page.value = page.value - 1;
                  window.setTimeout(() => selectByIndex(pageSize - 1), 0);
                  return;
                }
              }
              selectByIndex(cur < 0 ? 0 : cur - 1);
              return;
            }
            if(e.key === 'Enter'){
              e.preventDefault();
              if(cur >= 0){ selectByIndex(cur); }
              return;
            }
          }

          function prevPage(){
            page.value = page.value - 1;
            clampPage();
            if(pagedFindings.value.length > 0){
              selectByIndex(0);
            }else{
              clearDetail();
            }
          }

          function nextPage(){
            page.value = page.value + 1;
            clampPage();
            if(pagedFindings.value.length > 0){
              selectByIndex(0);
            }else{
              clearDetail();
            }
          }

          async function startScan(){
            const p = (path.value || '').trim();
            if(!p){ statusText.value = '请先输入路径'; return; }
            statusText.value = '已提交任务…';
            summaryText.value = '扫描中…';
            report.value = null;
            clearDetail();
            page.value = 1;
            running.value = true;
            try{
              const resp = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({path: p, subdirs: includeSubdirs.value})});
              if(!resp.ok){
                statusText.value = '提交失败';
                running.value = false;
                return;
              }
              const data = await resp.json();
              jobId.value = data.jobId || '';
              pollJob();
            }catch(e){
              statusText.value = '提交失败';
              running.value = false;
            }
          }

          async function pollJob(){
            if(!jobId.value){ running.value = false; return; }
            try{
              const resp = await fetch('/api/job/' + encodeURIComponent(jobId.value));
              if(!resp.ok){ statusText.value = '任务状态获取失败'; running.value = false; return; }
              const j = await resp.json();
              if(j.status === 'running' || j.status === 'queued'){
                statusText.value = '扫描中…';
                running.value = true;
                pollTimer = window.setTimeout(pollJob, 600);
                return;
              }
              if(j.status === 'canceled'){
                statusText.value = '已停止';
                summaryText.value = '已停止';
                running.value = false;
                return;
              }
              if(j.status === 'error'){
                statusText.value = '失败: ' + (j.error || 'unknown');
                summaryText.value = '失败';
                running.value = false;
                return;
              }
              report.value = j.report || null;
              const sum = j.summary ? ('发现 ' + j.summary.findings + ' 项 | 扫描 ' + j.summary.files + ' 文件 | 跳过 ' + j.summary.skipped) : '完成';
              summaryText.value = sum;
              statusText.value = '完成';
              running.value = false;
              page.value = 1;
              clampPage();
              if(pagedFindings.value.length > 0){ selectByIndex(0); }
            }catch(e){
              statusText.value = '任务状态获取失败';
              running.value = false;
            }
          }

          async function stopScan(){
            if(!jobId.value){ return; }
            try{
              window.clearTimeout(pollTimer);
              await fetch('/api/job/' + encodeURIComponent(jobId.value) + '/cancel', {method:'POST'});
            }catch(e){}
          }

          function exportReport(format){
            if(!jobId.value){ return; }
            exporting.value = true;
            const url = '/api/export?format=' + encodeURIComponent(format) + '&jobId=' + encodeURIComponent(jobId.value);
            location.href = url;
            window.setTimeout(() => { exporting.value = false; }, 800);
          }

          watch(filter, () => {
            page.value = 1;
            clampPage();
            if(pagedFindings.value.length > 0){
              selectByIndex(0);
            }else{
              clearDetail();
            }
          });

          watch(totalPages, () => {
            clampPage();
            const list = pagedFindings.value;
            if(!selectedId.value){
              if(list.length > 0){ selectByIndex(0); }
              return;
            }
            const ok = list.some(x => x.id === selectedId.value);
            if(!ok){
              if(list.length > 0){
                selectByIndex(0);
              }else{
                clearDetail();
              }
            }
          });

          function toggleSort(key){
            if(sortKey.value === key){
              sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc';
            }else{
              sortKey.value = key;
              sortDir.value = key === 'severity' ? 'desc' : 'asc';
            }
            page.value = 1;
            clampPage();
            if(pagedFindings.value.length > 0){
              selectByIndex(0);
            }else{
              clearDetail();
            }
          }

          return {
            path,
            includeSubdirs,
            filter,
            statusText,
            summaryText,
            jobId,
            running,
            exporting,
            page,
            totalPages,
            totalFindings,
            pagedFindings,
            selectedId,
            selectedFinding,
            selectedFileBase,
            contextLines,
            detailTrace,
            detailContext,
            sevClass,
            categoryLabel,
            fileBase,
            toRelative,
            simpleDesc,
            spotlightMove,
            startScan,
            stopScan,
            exportReport,
            selectFinding,
            onTableKeydown,
            prevPage,
            nextPage,
            copyText,
            sortKey,
            sortDir,
            toggleSort,
          };
        }
      }).mount('#app');
    })();
  </script>
</body>
</html>`
