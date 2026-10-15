package output

import (
	"encoding/json"
	"io"
)

type JSONFormatter struct {
	Options Options
}

func NewJSONFormatter(opts Options) *JSONFormatter {
	return &JSONFormatter{Options: opts}
}

func (f *JSONFormatter) Format(w io.Writer, out LintOutput) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	out = filterRules(out, f.Options)
	if f.Options.ShowMeta {
		return enc.Encode(out)
	}
	return enc.Encode(out.Results)
}
