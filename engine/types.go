package engine

import "time"

type Options struct {
	IncludeSubdirs bool
	MaxFileBytes   int64
}

type Stats struct {
	StartedAt    time.Time `json:"startedAt"`
	FinishedAt   time.Time `json:"finishedAt"`
	FilesScanned int       `json:"filesScanned"`
	FilesSkipped int       `json:"filesSkipped"`
	BytesRead    int64     `json:"bytesRead"`
}

type Report struct {
	Target   string    `json:"target"`
	Stats    Stats     `json:"stats"`
	Findings []Finding `json:"findings"`
}

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

type Finding struct {
	ID        string   `json:"id"`
	Category  string   `json:"category"`
	Severity  Severity `json:"severity"`
	File      string   `json:"file"`
	Line      int      `json:"line"`
	Sink      string   `json:"sink"`
	Evidence  string   `json:"evidence"`
	Message   string   `json:"message"`
	Trace     []Trace  `json:"trace,omitempty"`
	FixedHint string   `json:"fixedHint,omitempty"`
}

type Trace struct {
	Kind string `json:"kind"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Text string `json:"text,omitempty"`
}

type Progress struct {
	CurrentFile string
	Scanned     int
	Total       int
}
