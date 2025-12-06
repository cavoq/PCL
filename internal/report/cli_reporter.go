package report

import (
	"fmt"
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
}

var DefaultColors = ColorScheme{
	Reset:   "\033[0m",
	Error:   "\033[31m",
	Success: "\033[32m",
	Warning: "\033[33m",
	Info:    "\033[36m",
	Muted:   "\033[90m",
}

var colors = DefaultColors

type CliReporter struct{}

func (c CliReporter) Report(r *linter.LintResult) (string, error) {
	if r == nil {
		return colors.Error + "ERROR: no result" + colors.Reset, nil
	}
	return FormatResult(r), nil
}

func colorize(s, color string) string {
	return color + s + colors.Reset
}

func FormatResult(r *linter.LintResult) string {
	if r == nil {
		return colorize("ERROR: no result", colors.Error)
	}

	sb := strings.Builder{}

	sb.WriteString(colorize("┌─ File: ", colors.Info) + r.CertFile + "\n")
	sb.WriteString(colorize("│  Checked: ", colors.Info) + r.CheckedAt.Format("2006-01-02 15:04:05 MST") + "\n")

	status := "PASS"
	statusColor := colors.Success
	if !r.Valid {
		status = "FAIL"
		statusColor = colors.Error
	}
	sb.WriteString(colorize("└─ Status: ", colors.Info) + colorize(status, statusColor) + "\n")

	if len(r.Findings) == 0 {
		sb.WriteString(colorize("   No findings.\n", colors.Muted))
		return sb.String()
	}

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

		sb.WriteString(fmt.Sprintf("   [%s] %s %s\n",
			f.ID,
			colorize(fmt.Sprintf("%-6s", f.Status), statusColor),
			f.Message,
		))
	}

	return sb.String()
}
