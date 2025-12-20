package report

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cavoq/PCL/internal/linter"
)

type ColorScheme struct {
	Reset   string
	Error   string
	Success string
	Warning string
	Info    string
	Muted   string
	Bold    string
}

var DefaultColors = ColorScheme{
	Reset:   "\033[0m",
	Error:   "\033[31m",
	Success: "\033[32m",
	Warning: "\033[33m",
	Info:    "\033[36m",
	Muted:   "\033[90m",
	Bold:    "\033[1m",
}

var colors = DefaultColors

type CliReporter struct{}

func (c CliReporter) Report(run *linter.LintRun) (string, error) {
	if run == nil {
		return colors.Error + "ERROR: no lint run" + colors.Reset, nil
	}
	return FormatLintRun(run), nil
}

func colorize(s, color string) string {
	return color + s + colors.Reset
}

func FormatLintRun(run *linter.LintRun) string {
	sb := strings.Builder{}

	// Header with meta information
	sb.WriteString(colorize("══════════════════════════════════════════════════════════════════════════════\n", colors.Info))
	sb.WriteString(colorize("  PCL - Policy-based Certificate Linter\n", colors.Bold+colors.Info))
	sb.WriteString(colorize("══════════════════════════════════════════════════════════════════════════════\n", colors.Info))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Certificates:", colors.Muted), run.CertPath))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Policy:      ", colors.Muted), run.PolicyPath))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Started:     ", colors.Muted), run.StartedAt.Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(colorize("──────────────────────────────────────────────────────────────────────────────\n", colors.Muted))
	sb.WriteString("\n")

	// Individual results
	for i, r := range run.Results {
		sb.WriteString(formatResult(r, i+1))
		sb.WriteString("\n")
	}

	// Summary
	passed, failed, warnings := run.Summary()
	sb.WriteString(colorize("══════════════════════════════════════════════════════════════════════════════\n", colors.Info))
	sb.WriteString(colorize("  Summary\n", colors.Bold+colors.Info))
	sb.WriteString(colorize("──────────────────────────────────────────────────────────────────────────────\n", colors.Muted))

	total := passed + failed
	sb.WriteString(fmt.Sprintf("  %s %d\n", colorize("Total certificates:", colors.Muted), total))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Passed:            ", colors.Muted), colorize(fmt.Sprintf("%d", passed), colors.Success)))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Failed:            ", colors.Muted), colorize(fmt.Sprintf("%d", failed), colors.Error)))
	if warnings > 0 {
		sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Warnings:          ", colors.Muted), colorize(fmt.Sprintf("%d", warnings), colors.Warning)))
	}
	sb.WriteString(colorize("══════════════════════════════════════════════════════════════════════════════\n", colors.Info))

	return sb.String()
}

func formatResult(r *linter.LintResult, index int) string {
	if r == nil {
		return colorize("ERROR: no result", colors.Error)
	}

	sb := strings.Builder{}

	// Certificate header
	status := "PASS"
	statusColor := colors.Success
	if !r.Valid {
		status = "FAIL"
		statusColor = colors.Error
	}

	fileName := filepath.Base(r.FilePath)
	sb.WriteString(fmt.Sprintf("%s [%s]\n", colorize(fmt.Sprintf("Certificate #%d", index), colors.Bold), colorize(status, statusColor)))
	sb.WriteString(colorize("────────────────────────────────────────\n", colors.Muted))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("File:  ", colors.Muted), fileName))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Path:  ", colors.Muted), r.FilePath))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Policy:", colors.Muted), r.PolicyName))
	sb.WriteString(fmt.Sprintf("  %s %s\n", colorize("Hash:  ", colors.Muted), r.Hash[:16]+"..."))
	sb.WriteString("\n")

	if len(r.Findings) == 0 {
		sb.WriteString(colorize("  No findings.\n", colors.Muted))
		return sb.String()
	}

	// Findings
	sb.WriteString(colorize("  Findings:\n", colors.Muted))
	for _, f := range r.Findings {
		var statusColor string
		switch f.Status {
		case linter.StatusPass:
			statusColor = colors.Success
		case linter.StatusFail:
			statusColor = colors.Error
		case linter.StatusWarn:
			statusColor = colors.Warning
		case linter.StatusInfo:
			statusColor = colors.Info
		}

		sb.WriteString(fmt.Sprintf("    %s %-6s %s\n",
			colorize(fmt.Sprintf("[%s]", f.ID), colors.Muted),
			colorize(string(f.Status), statusColor),
			f.Message,
		))
	}

	return sb.String()
}
