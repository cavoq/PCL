package report

import (
	"fmt"

	"github.com/cavoq/PCL/internal/linter"
)

type Reporter interface {
	Report(r *linter.LintResult) (string, error)
}

func SelectReporter(fmt string) Reporter {
	switch fmt {
	case "json":
		return JsonReporter{}
	default:
		return CliReporter{}
	}
}

func ReportAll(r Reporter, jobs []*linter.LintJob) error {
	for _, job := range jobs {
		output, err := r.Report(job.Result)
		if err != nil {
			return fmt.Errorf("failed to format result for cert %v: %w", job.Result.CertFile, err)
		}
		fmt.Println(output)
	}
	return nil
}
