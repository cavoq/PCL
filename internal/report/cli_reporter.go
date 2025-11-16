package report

import (
	"fmt"
	"strings"

	"github.com/cavoq/RCV/internal/linter"
)

const (
	reset  = "\033[0m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
)

func colorize(s, color string) string {
	return color + s + reset
}

func FormatResult(r *linter.Result) string {
	if r == nil {
		return colorize("ERROR: no result", red)
	}

	sb := strings.Builder{}

	sb.WriteString(colorize("┌─ File: ", cyan) + r.CertFile + "\n")
	sb.WriteString(colorize("│  Checked: ", cyan) + r.CheckedAt.Format("2006-01-02 15:04:05 MST") + "\n")

	status := "PASS"
	statusColor := green
	if !r.Valid {
		status = "FAIL"
		statusColor = red
	}
	sb.WriteString(colorize("└─ Status: ", cyan) + colorize(status, statusColor) + "\n")

	if len(r.Findings) == 0 {
		sb.WriteString(colorize("   No findings.\n", gray))
		return sb.String()
	}

	for _, f := range r.Findings {
		var statusColor string
		switch f.Status {
		case linter.StatusPass:
			statusColor = green
		case linter.StatusFail:
			statusColor = red
		case linter.StatusWarn:
			statusColor = yellow
		case linter.StatusInfo:
			statusColor = cyan
		}

		sb.WriteString(fmt.Sprintf("   [%s] %s %s\n",
			f.ID,
			colorize(fmt.Sprintf("%-6s", f.Status), statusColor),
			f.Message,
		))
	}

	return sb.String()
}
