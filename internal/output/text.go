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
			severityLabelColored("warning"),
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
		passCount, failCount, skipCount, warnCount := countsFromResult(pr)
		if _, err := fmt.Fprintf(
			w,
			"[File] Policy: %s | Cert: %s | File: %s | Verdict: %s | %s: %d, %s: %d, %s: %d, %s: %d\n",
			pr.PolicyID,
			pr.CertType,
			certPath,
			verdictLabelColored(pr.Verdict),
			verdictLabelColored(rule.VerdictPass),
			passCount,
			verdictLabelColored(rule.VerdictFail),
			failCount,
			verdictLabelColored(rule.VerdictSkip),
			skipCount,
			severityLabelColored("warning"),
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

func colorize(s string, color string) string {
	return color + s + ansiReset
}

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

func writeRulesTable(w io.Writer, results []rule.Result, passCount, failCount, skipCount int) error {
	if len(results) == 0 {
		if _, err := fmt.Fprintln(w, strings.Repeat("-", 72)); err != nil {
			return err
		}
		if passCount+failCount+skipCount > 0 {
			_, err := fmt.Fprintln(w, "  (no rules to display with current verbosity)")
			return err
		}
		_, err := fmt.Fprintln(w, "  (no rules to display)")
		return err
	}
	showReference := false
	showSeverity := false
	for _, rr := range results {
		if rr.Reference != "" {
			showReference = true
		}
		if rr.Severity == "warning" {
			showSeverity = true
		}
	}

	ruleWidth := len("RULE")
	refWidth := len("REFERENCE")
	levelWidth := len("SEVERITY")
	for _, rr := range results {
		if len(rr.RuleID) > ruleWidth {
			ruleWidth = len(rr.RuleID)
		}
		if showReference && len(rr.Reference) > refWidth {
			refWidth = len(rr.Reference)
		}
	}

	if _, err := fmt.Fprintln(w, strings.Repeat("-", 72)); err != nil {
		return err
	}
	if showReference && showSeverity {
		if _, err := fmt.Fprintf(w, "  %-7s  %-*s  %-*s  %-*s\n", "VERDICT", levelWidth, "SEVERITY", ruleWidth, "RULE", refWidth, "REFERENCE"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %-7s  %-*s  %-*s  %-*s\n", strings.Repeat("-", 7), levelWidth, strings.Repeat("-", levelWidth), ruleWidth, strings.Repeat("-", ruleWidth), refWidth, strings.Repeat("-", refWidth)); err != nil {
			return err
		}
	} else if showReference {
		if _, err := fmt.Fprintf(w, "  %-7s  %-*s  %-*s\n", "VERDICT", ruleWidth, "RULE", refWidth, "REFERENCE"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %-7s  %-*s  %-*s\n", strings.Repeat("-", 7), ruleWidth, strings.Repeat("-", ruleWidth), refWidth, strings.Repeat("-", refWidth)); err != nil {
			return err
		}
	} else if showSeverity {
		if _, err := fmt.Fprintf(w, "  %-7s  %-*s  %-*s\n", "VERDICT", levelWidth, "SEVERITY", ruleWidth, "RULE"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %-7s  %-*s  %-*s\n", strings.Repeat("-", 7), levelWidth, strings.Repeat("-", levelWidth), ruleWidth, strings.Repeat("-", ruleWidth)); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "  %-7s  %-*s\n", "VERDICT", ruleWidth, "RULE"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %-7s  %-*s\n", strings.Repeat("-", 7), ruleWidth, strings.Repeat("-", ruleWidth)); err != nil {
			return err
		}
	}

	for _, rr := range results {
		verdict := verdictLabelColoredPadded(rr.Verdict, 7)
		level := severityLabel(rr.Severity)
		if showReference && showSeverity {
			if _, err := fmt.Fprintf(w, "  %s  %-*s  %-*s  %-*s\n", verdict, levelWidth, level, ruleWidth, rr.RuleID, refWidth, rr.Reference); err != nil {
				return err
			}
		} else if showReference {
			if _, err := fmt.Fprintf(w, "  %s  %-*s  %-*s\n", verdict, ruleWidth, rr.RuleID, refWidth, rr.Reference); err != nil {
				return err
			}
		} else if showSeverity {
			if _, err := fmt.Fprintf(w, "  %s  %-*s  %-*s\n", verdict, levelWidth, level, ruleWidth, rr.RuleID); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "  %s  %-*s\n", verdict, ruleWidth, rr.RuleID); err != nil {
				return err
			}
		}
		if rr.Message != "" {
			if _, err := fmt.Fprintf(w, "          -> %s\n", rr.Message); err != nil {
				return err
			}
		}
	}

	return nil
}

func countResults(results []rule.Result) (int, int, int, int) {
	passed, failed, skipped, warned := 0, 0, 0, 0
	for _, rr := range results {
		switch rr.Verdict {
		case rule.VerdictPass:
			passed++
		case rule.VerdictFail:
			failed++
			if rr.Severity == "warning" {
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
	if severity == "warning" {
		return "WARN"
	}
	if severity == "" {
		return ""
	}
	return strings.ToUpper(severity)
}

func severityLabelColored(severity string) string {
	label := severityLabel(severity)
	if severity == "warning" {
		return colorize(label, ansiYellow)
	}
	return label
}
