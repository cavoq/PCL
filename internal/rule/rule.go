package rule

type Rule struct {
	ID       string `yaml:"id"`
	Target   string `yaml:"target"`
	Operator string `yaml:"operator"`
	Operands []any  `yaml:"operands"`
	Severity string `yaml:"severity"`
}
