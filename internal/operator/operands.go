package operator

import "fmt"

// NormalizeOperands converts the YAML-facing operand representation to the
// slice consumed by operators. A map is one structured operand, while scalar
// values are one positional operand.
func NormalizeOperands(operands any) []any {
	if operands == nil {
		return nil
	}

	switch value := operands.(type) {
	case []any:
		return value
	case map[string]any:
		return []any{value}
	default:
		return []any{value}
	}
}

// parseIntegerOperand accepts the numeric representations produced by YAML
// and programmatic callers while rejecting fractions and lossy conversions.
func parseIntegerOperand(value any) (int, error) {
	rational, ok := numericValue(value)
	if !ok || !rational.IsInt() {
		return 0, fmt.Errorf("must be an integer")
	}
	numerator := rational.Num()
	if !numerator.IsInt64() {
		return 0, fmt.Errorf("integer is out of range")
	}
	integer := int(numerator.Int64())
	if int64(integer) != numerator.Int64() {
		return 0, fmt.Errorf("integer is out of range")
	}
	return integer, nil
}
