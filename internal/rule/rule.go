package rule

type Condition struct {
	Target   string `yaml:"target"`
	Operator string `yaml:"operator"`
	Operands []any  `yaml:"operands"`
}

type Rule struct {
	ID        string     `yaml:"id"`
	Reference string     `yaml:"reference,omitempty"`
	Target    string     `yaml:"target"`
	Operator  string     `yaml:"operator"`
	Operands  []any      `yaml:"operands"`
	Severity  string     `yaml:"severity"`
	AppliesTo []string   `yaml:"appliesTo,omitempty"`
	When      *Condition `yaml:"when,omitempty"`
}
