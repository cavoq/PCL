package report

import (
	"github.com/cavoq/RCV/internal/linter"
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
