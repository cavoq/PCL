package operator

import (
	"fmt"
	"math"
)

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
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int8:
		return int(typed), nil
	case int16:
		return int(typed), nil
	case int32:
		return int(typed), nil
	case int64:
		integer := int(typed)
		if int64(integer) != typed {
			return 0, fmt.Errorf("integer is out of range")
		}
		return integer, nil
	case uint:
		integer := int(typed)
		if integer < 0 || uint(integer) != typed {
			return 0, fmt.Errorf("integer is out of range")
		}
		return integer, nil
	case uint8:
		return int(typed), nil
	case uint16:
		return int(typed), nil
	case uint32:
		integer := int(typed)
		if integer < 0 || uint32(integer) != typed {
			return 0, fmt.Errorf("integer is out of range")
		}
		return integer, nil
	case uint64:
		integer := int(typed)
		if integer < 0 || uint64(integer) != typed {
			return 0, fmt.Errorf("integer is out of range")
		}
		return integer, nil
	case float32:
		return parseFloatInteger(float64(typed))
	case float64:
		return parseFloatInteger(typed)
	default:
		return 0, fmt.Errorf("must be an integer")
	}
}

func parseFloatInteger(value float64) (int, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value {
		return 0, fmt.Errorf("must be an integer")
	}
	integer := int(value)
	if float64(integer) != value {
		return 0, fmt.Errorf("integer is out of range")
	}
	return integer, nil
}
