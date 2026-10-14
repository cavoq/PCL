package output

import "io"

// Output formats accepted by GetFormatter. Unknown formats render as text.
const (
	FormatText = "text"
	FormatJSON = "json"
	FormatYAML = "yaml"
)

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
	case FormatJSON:
		return NewJSONFormatter(opts)
	case FormatYAML:
		return NewYAMLFormatter(opts)
	default:
		return NewTextFormatter(opts)
	}
}
