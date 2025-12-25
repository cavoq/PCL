package output

import (
	"encoding/json"
	"io"
)

type JSONFormatter struct {
	ShowMeta bool
}

func NewJSONFormatter(opts Options) *JSONFormatter {
	return &JSONFormatter{ShowMeta: opts.ShowMeta}
}

func (f *JSONFormatter) Format(w io.Writer, out LintOutput) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if f.ShowMeta {
		return enc.Encode(out)
	}
	return enc.Encode(out.Results)
}
