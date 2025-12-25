package output

import "io"

type Options struct {
	ShowPassed  bool
	ShowFailed  bool
	ShowSkipped bool
	ShowMeta    bool
}

func DefaultOptions() Options {
	return Options{
		ShowPassed:  true,
		ShowFailed:  true,
		ShowSkipped: true,
		ShowMeta:    true,
	}
}

func FailedOnlyOptions() Options {
	return Options{
		ShowPassed:  false,
		ShowFailed:  true,
		ShowSkipped: false,
		ShowMeta:    true,
	}
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
