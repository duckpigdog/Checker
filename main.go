package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"checker/engine"
	"checker/ui"
)

func main() {
	var (
		targetPath = flag.String("path", "", "target file or directory")
		outPath    = flag.String("out", "", "output file path")
		format     = flag.String("format", "json", "output format: json|csv")
		noGUI      = flag.Bool("cli", false, "run in CLI mode")
		subdirs    = flag.Bool("subdirs", true, "scan subdirectories")
	)
	flag.Parse()

	if *noGUI || strings.TrimSpace(*targetPath) != "" {
		if err := runCLI(*targetPath, *outPath, *format, *subdirs); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		return
	}

	ui.Run()
}

func runCLI(targetPath, outPath, format string, subdirs bool) error {
	if strings.TrimSpace(targetPath) == "" {
		return fmt.Errorf("missing -path")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	report, err := engine.ScanPath(ctx, targetPath, engine.Options{
		IncludeSubdirs: subdirs,
	})
	if err != nil {
		return err
	}

	if outPath == "" {
		switch strings.ToLower(format) {
		case "csv":
			return engine.WriteCSV(os.Stdout, report)
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		default:
			return fmt.Errorf("unsupported -format: %s", format)
		}
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	switch strings.ToLower(format) {
	case "csv":
		if err := engine.WriteCSV(f, report); err != nil {
			return err
		}
	case "json":
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported -format: %s", format)
	}

	fmt.Fprintf(os.Stdout, "done: %d findings, %d files, %s\n", len(report.Findings), report.Stats.FilesScanned, time.Since(start).Truncate(time.Millisecond))
	return nil
}
