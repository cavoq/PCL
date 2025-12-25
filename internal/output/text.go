package output

import (
	"fmt"
	"io"
	"strings"
)

type TextFormatter struct {
	ShowMeta bool
}

func NewTextFormatter(opts Options) *TextFormatter {
	return &TextFormatter{ShowMeta: opts.ShowMeta}
}

func (f *TextFormatter) Format(w io.Writer, out LintOutput) error {
	if f.ShowMeta {
		if _, err := fmt.Fprintf(w, "Checked: %s | Certs: %d | Rules: %d (pass: %d, fail: %d, skip: %d)\n\n",
			out.Meta.CheckedAt.Format("2006-01-02 15:04:05"),
			out.Meta.TotalCerts,
			out.Meta.TotalRules,
			out.Meta.PassedRules,
			out.Meta.FailedRules,
			out.Meta.SkippedRules,
		); err != nil {
			return err
		}
	}

	for _, pr := range out.Results {
		if _, err := fmt.Fprintf(w, "Policy: %s | Cert: %s | Verdict: %s\n", pr.PolicyID, pr.CertType, pr.Verdict); err != nil {
			return err
		}
		for _, rr := range pr.Results {
			if _, err := fmt.Fprintf(w, "  [%s] %s\n", verdictLabel(rr.Verdict), rr.RuleID); err != nil {
				return err
			}
			if rr.Message != "" {
				if _, err := fmt.Fprintf(w, "        %s\n", rr.Message); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func verdictLabel(verdict string) string {
	return strings.ToUpper(verdict)
}
