package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

type TextFormatter struct {
	ShowMeta bool
}

func NewTextFormatter(opts Options) *TextFormatter {
	return &TextFormatter{ShowMeta: opts.ShowMeta}
}

func (f *TextFormatter) Format(w io.Writer, out LintOutput) error {
	if f.ShowMeta {
		warnTotal := countWarnings(out.Results)
		if _, err := fmt.Fprintf(
			w,
			"[Summary] Checked: %s | Certs: %d | Rules: %d | %s: %d, %s: %d, %s: %d, %s: %d\n",
			out.Meta.CheckedAt.Format("2006-01-02 15:04:05"),
			out.Meta.TotalCerts,
			out.Meta.TotalRules,
			verdictLabelColored(rule.VerdictPass),
			out.Meta.PassedRules,
			verdictLabelColored(rule.VerdictFail),
			out.Meta.FailedRules,
			verdictLabelColored(rule.VerdictSkip),
			out.Meta.SkippedRules,
			severityLabelColored(rule.SeverityWarning),
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
		passCount, failCount, skipCount, warnCount := countsFromResult(pr)
		if _, err := fmt.Fprintf(
			w,
			"[File] Policy: %s | Cert: %s | File: %s%s | Verdict: %s | %s: %d, %s: %d, %s: %d, %s: %d\n",
			pr.PolicyID,
			pr.CertType,
			certPath,
			sourceInfo,
			verdictLabelColored(pr.Verdict),
			verdictLabelColored(rule.VerdictPass),
			passCount,
			verdictLabelColored(rule.VerdictFail),
			failCount,
			verdictLabelColored(rule.VerdictSkip),
			skipCount,
			severityLabelColored(rule.SeverityWarning),
			warnCount,
		); err != nil {
			return err
		}
		if err := writeRulesTable(w, pr.Results, passCount, failCount, skipCount); err != nil {
			return err
		}
	}
	return nil
}

func verdictLabel(verdict string) string {
	return strings.ToUpper(verdict)
}

func verdictLabelColored(verdict string) string {
	label := verdictLabel(verdict)
	switch verdict {
	case rule.VerdictPass:
		return colorize(label, ansiGreen)
	case rule.VerdictFail:
		return colorize(label, ansiRed)
	case rule.VerdictSkip:
		return colorize(label, ansiCyan)
	default:
		return label
	}
}

func verdictLabelColoredPadded(verdict string, width int) string {
	label := verdictLabel(verdict)
	padded := fmt.Sprintf("%-*s", width, label)
	switch verdict {
	case rule.VerdictPass:
		return colorize(padded, ansiGreen)
	case rule.VerdictFail:
		return colorize(padded, ansiRed)
	case rule.VerdictSkip:
		return colorize(padded, ansiCyan)
	default:
		return padded
	}
}

func verdictLabelColoredPaddedWithSeverity(verdict string, severity string, width int) string {
	label := verdictLabel(verdict)
	padded := fmt.Sprintf("%-*s", width, label)
	switch verdict {
	case rule.VerdictPass:
		return colorize(padded, ansiGreen)
	case rule.VerdictFail:
		// INFO level failures use white (informational), more visible than blue
		if severity == rule.SeverityInfo {
			return colorize(padded, ansiWhite)
		}
		if severity == rule.SeverityWarning {
			return colorize(padded, ansiYellow)
		}
		return colorize(padded, ansiRed)
	case rule.VerdictSkip:
		return colorize(padded, ansiCyan)
	default:
		return padded
	}
}

func colorize(s string, color string) string {
	return color + s + ansiReset
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

func writeRulesTable(w io.Writer, results []rule.Result, passCount, failCount, skipCount int) error {
	if _, err := fmt.Fprintln(w, strings.Repeat("-", 72)); err != nil {
		return err
	}
	if len(results) == 0 {
		if passCount+failCount+skipCount > 0 {
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
		cells := []string{verdictLabelColoredPaddedWithSeverity(rr.Verdict, rr.Severity, verdictWidth)}
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

func countResults(results []rule.Result) (int, int, int, int) {
	passed, failed, skipped, warned := 0, 0, 0, 0
	for _, rr := range results {
		switch rr.Verdict {
		case rule.VerdictPass:
			passed++
		case rule.VerdictFail:
			failed++
			if rr.Severity == rule.SeverityWarning {
				warned++
			}
		case rule.VerdictSkip:
			skipped++
		}
	}
	return passed, failed, skipped, warned
}

func countWarnings(results []policy.Result) int {
	total := 0
	for _, pr := range results {
		if pr.Counts.Warned == 0 && len(pr.Results) > 0 {
			_, _, _, warned := countResults(pr.Results)
			total += warned
			continue
		}
		total += pr.Counts.Warned
	}
	return total
}

func countsFromResult(pr policy.Result) (int, int, int, int) {
	if pr.Counts.Passed+pr.Counts.Failed+pr.Counts.Skipped+pr.Counts.Warned > 0 {
		return pr.Counts.Passed, pr.Counts.Failed, pr.Counts.Skipped, pr.Counts.Warned
	}
	return countResults(pr.Results)
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

func severityLabelColored(severity string) string {
	label := severityLabel(severity)
	if severity == rule.SeverityWarning {
		return colorize(label, ansiYellow)
	}
	if severity == rule.SeverityInfo {
		return colorize(label, ansiBlue)
	}
	return label
}
