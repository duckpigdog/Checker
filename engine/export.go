package engine

import (
	"encoding/csv"
	"io"
	"strconv"
)

func WriteCSV(w io.Writer, report *Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"id", "category", "severity", "file", "line", "sink", "evidence", "message"}); err != nil {
		return err
	}
	for _, f := range report.Findings {
		if err := cw.Write([]string{
			f.ID,
			f.Category,
			string(f.Severity),
			f.File,
			strconv.Itoa(f.Line),
			f.Sink,
			f.Evidence,
			f.Message,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
