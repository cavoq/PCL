package output

import (
	"fmt"
	"io"
)

// Output formats accepted by GetFormatter. Unknown formats render as text;
// CheckFormat rejects them before any output is produced.
const (
	FormatText = "text"
	FormatJSON = "json"
	FormatYAML = "yaml"
)

// CheckFormat reports an output format that is not text, json or yaml.
func CheckFormat(format string) error {
	switch format {
	case FormatText, FormatJSON, FormatYAML:
		return nil
	default:
		return fmt.Errorf("unknown output format %q: use text, json or yaml", format)
	}
}

type Options struct {
	ShowPassed  bool
	ShowFailed  bool
	ShowSkipped bool
	ShowMeta    bool
	// Color marks text output with ANSI colors.
	Color bool
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
