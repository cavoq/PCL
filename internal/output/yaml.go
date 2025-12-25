package output

import (
	"io"

	"gopkg.in/yaml.v3"
)

type YAMLFormatter struct {
	ShowMeta bool
}

func NewYAMLFormatter(opts Options) *YAMLFormatter {
	return &YAMLFormatter{ShowMeta: opts.ShowMeta}
}

func (f *YAMLFormatter) Format(w io.Writer, out LintOutput) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)

	if f.ShowMeta {
		return enc.Encode(out)
	}
	return enc.Encode(out.Results)
}
