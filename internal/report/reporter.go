package report

import (
	"fmt"

	"github.com/cavoq/PCL/internal/linter"
)

type Reporter interface {
	Report(run *linter.LintRun) (string, error)
}

func SelectReporter(format string) Reporter {
	switch format {
	case "json":
		return JsonReporter{}
	default:
		return CliReporter{}
	}
}

func ReportLintRun(r Reporter, run *linter.LintRun) error {
	output, err := r.Report(run)
	if err != nil {
		return fmt.Errorf("failed to format lint run: %w", err)
	}
	fmt.Println(output)
	return nil
}
