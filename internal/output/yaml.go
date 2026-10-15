package output

import (
	"io"

	"gopkg.in/yaml.v3"
)

type YAMLFormatter struct {
	Options Options
}

func NewYAMLFormatter(opts Options) *YAMLFormatter {
	return &YAMLFormatter{Options: opts}
}

func (f *YAMLFormatter) Format(w io.Writer, out LintOutput) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)

	out = filterRules(out, f.Options)
	if f.Options.ShowMeta {
		return enc.Encode(out)
	}
	return enc.Encode(out.Results)
}
