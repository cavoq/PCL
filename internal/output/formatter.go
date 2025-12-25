package output

import "io"

type Options struct {
	ShowPassed  bool
	ShowFailed  bool
	ShowSkipped bool
	ShowMeta    bool
}

type Formatter interface {
	Format(w io.Writer, output LintOutput) error
}

func GetFormatter(format string, opts Options) Formatter {
	switch format {
	case "json":
		return NewJSONFormatter(opts)
	case "yaml":
		return NewYAMLFormatter(opts)
	default:
		return NewTextFormatter(opts)
	}
}
