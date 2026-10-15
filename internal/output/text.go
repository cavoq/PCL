package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/cavoq/PCL/internal/rule"
)

type TextFormatter struct {
	Options Options
}

func NewTextFormatter(opts Options) *TextFormatter {
	return &TextFormatter{Options: opts}
}

func (f *TextFormatter) Format(w io.Writer, out LintOutput) error {
	colors := palette(f.Options.Color)
	if f.Options.ShowMeta {
		warnTotal := 0
		for _, pr := range out.Results {
			warnTotal += countRules(pr.Results).warned
		}
		if _, err := fmt.Fprintf(
			w,
			"[Summary] Checked: %s | Certs: %d | Rules: %d | %s: %d, %s: %d, %s: %d, %s: %d\n",
			out.Meta.CheckedAt.Format("2006-01-02 15:04:05"),
			out.Meta.TotalCerts,
			out.Meta.TotalRules,
			colors.verdict(rule.VerdictPass),
			out.Meta.PassedRules,
			colors.verdict(rule.VerdictFail),
			out.Meta.FailedRules,
			colors.verdict(rule.VerdictSkip),
			out.Meta.SkippedRules,
			colors.severity(rule.SeverityWarning),
			warnTotal,
		); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}

	for i, pr := range out.Results {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, strings.Repeat("=", 72)); err != nil {
			return err
		}
		certPath := pr.CertPath
		if certPath == "" {
			certPath = "-"
		}
		// Display source info if available and not local file
		sourceInfo := ""
		if pr.Source != "" && pr.Source != "local" {
			sourceInfo = fmt.Sprintf(" (%s)", pr.Source)
		}
		counts := countRules(pr.Results)
		if _, err := fmt.Fprintf(
			w,
			"[File] Policy: %s | Cert: %s | File: %s%s | Verdict: %s | %s: %d, %s: %d, %s: %d, %s: %d\n",
			pr.PolicyID,
			pr.CertType,
			certPath,
			sourceInfo,
			colors.verdict(pr.Verdict),
			colors.verdict(rule.VerdictPass),
			counts.passed,
			colors.verdict(rule.VerdictFail),
			counts.failed,
			colors.verdict(rule.VerdictSkip),
			counts.skipped,
			colors.severity(rule.SeverityWarning),
			counts.warned,
		); err != nil {
			return err
		}
		if err := writeRulesTable(w, colors, visibleRules(pr.Results, f.Options), len(pr.Results)); err != nil {
			return err
		}
	}
	return nil
}

func verdictLabel(verdict string) string {
	return strings.ToUpper(verdict)
}

// palette colors labels with ANSI escape codes when enabled and returns
// them unchanged otherwise.
type palette bool

func (p palette) paint(s string, color string) string {
	if !p {
		return s
	}
	return color + s + ansiReset
}

func (p palette) verdict(verdict string) string {
	label := verdictLabel(verdict)
	switch verdict {
	case rule.VerdictPass:
		return p.paint(label, ansiGreen)
	case rule.VerdictFail:
		return p.paint(label, ansiRed)
	case rule.VerdictSkip:
		return p.paint(label, ansiCyan)
	default:
		return label
	}
}

// verdictCell is the padded VERDICT cell of a rule, colored by its severity
// when it failed.
func (p palette) verdictCell(verdict string, severity string, width int) string {
	padded := fmt.Sprintf("%-*s", width, verdictLabel(verdict))
	switch verdict {
	case rule.VerdictPass:
		return p.paint(padded, ansiGreen)
	case rule.VerdictFail:
		// INFO level failures use white (informational), more visible than blue
		if severity == rule.SeverityInfo {
			return p.paint(padded, ansiWhite)
		}
		if severity == rule.SeverityWarning {
			return p.paint(padded, ansiYellow)
		}
		return p.paint(padded, ansiRed)
	case rule.VerdictSkip:
		return p.paint(padded, ansiCyan)
	default:
		return padded
	}
}

func (p palette) severity(severity string) string {
	label := severityLabel(severity)
	if severity == rule.SeverityWarning {
		return p.paint(label, ansiYellow)
	}
	if severity == rule.SeverityInfo {
		return p.paint(label, ansiBlue)
	}
	return label
}

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiWhite  = "\033[37m"
)

// verdictWidth is the padded width of the always-present VERDICT column.
const verdictWidth = 7

// tableColumn is an optional rules-table column after VERDICT.
type tableColumn struct {
	header string
	width  int
	value  func(rule.Result) string
}

// writeRulesTable lists the visible results of a policy that evaluated
// total rules.
func writeRulesTable(w io.Writer, colors palette, results []rule.Result, total int) error {
	if _, err := fmt.Fprintln(w, strings.Repeat("-", 72)); err != nil {
		return err
	}
	if len(results) == 0 {
		if total > 0 {
			_, err := fmt.Fprintln(w, "  (no rules to display with current verbosity)")
			return err
		}
		_, err := fmt.Fprintln(w, "  (no rules to display)")
		return err
	}

	columns := rulesTableColumns(results)
	header := []string{fmt.Sprintf("%-*s", verdictWidth, "VERDICT")}
	separator := []string{strings.Repeat("-", verdictWidth)}
	for _, column := range columns {
		header = append(header, fmt.Sprintf("%-*s", column.width, column.header))
		separator = append(separator, strings.Repeat("-", column.width))
	}
	if err := writeTableLine(w, header); err != nil {
		return err
	}
	if err := writeTableLine(w, separator); err != nil {
		return err
	}

	for _, rr := range results {
		cells := []string{colors.verdictCell(rr.Verdict, rr.Severity, verdictWidth)}
		for _, column := range columns {
			cells = append(cells, fmt.Sprintf("%-*s", column.width, column.value(rr)))
		}
		if err := writeTableLine(w, cells); err != nil {
			return err
		}
		if rr.Message != "" {
			if _, err := fmt.Fprintf(w, "          -> %s\n", rr.Message); err != nil {
				return err
			}
		}
	}

	return nil
}

// rulesTableColumns returns the SEVERITY, RULE and REFERENCE columns, omitting
// SEVERITY and REFERENCE when no result has a value for them.
func rulesTableColumns(results []rule.Result) []tableColumn {
	severity := tableColumn{header: "SEVERITY", value: func(rr rule.Result) string { return severityLabel(rr.Severity) }}
	ruleID := tableColumn{header: "RULE", value: func(rr rule.Result) string { return rr.RuleID }}
	reference := tableColumn{header: "REFERENCE", value: func(rr rule.Result) string { return rr.Reference }}

	showSeverity := false
	showReference := false
	ruleID.width = len(ruleID.header)
	reference.width = len(reference.header)
	for _, rr := range results {
		showSeverity = showSeverity || rr.Severity != ""
		showReference = showReference || rr.Reference != ""
		ruleID.width = max(ruleID.width, len(rr.RuleID))
		reference.width = max(reference.width, len(rr.Reference))
	}
	severity.width = len(severity.header)

	columns := make([]tableColumn, 0, 3)
	if showSeverity {
		columns = append(columns, severity)
	}
	columns = append(columns, ruleID)
	if showReference {
		columns = append(columns, reference)
	}
	return columns
}

func writeTableLine(w io.Writer, cells []string) error {
	_, err := fmt.Fprintf(w, "  %s\n", strings.Join(cells, "  "))
	return err
}

func severityLabel(severity string) string {
	if severity == rule.SeverityWarning {
		return "WARN"
	}
	if severity == "" {
		return ""
	}
	return strings.ToUpper(severity)
}
