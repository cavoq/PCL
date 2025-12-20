package rule

type Rule struct {
	ID       string
	Target   string
	Operator string
	Operands []any
	Severity string
}
