package report

import (
	"github.com/cavoq/RCV/internal/linter"
)

type Reporter interface {
	FormatResult(r *linter.Result) string
}
