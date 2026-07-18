package operator

import "math/big"

// compareNumericValues compares all numeric representations supported by the
// operator package without converting integers through float64. The boolean
// result is false for non-numeric and non-finite values.
func compareNumericValues(a, b any) (int, bool) {
	aValue, ok := numericValue(a)
	if !ok {
		return 0, false
	}
	bValue, ok := numericValue(b)
	if !ok {
		return 0, false
	}
	return aValue.Cmp(bValue), true
}

func numericValue(value any) (*big.Rat, bool) {
	result := new(big.Rat)
	switch number := value.(type) {
	case int:
		return result.SetInt64(int64(number)), true
	case int8:
		return result.SetInt64(int64(number)), true
	case int16:
		return result.SetInt64(int64(number)), true
	case int32:
		return result.SetInt64(int64(number)), true
	case int64:
		return result.SetInt64(number), true
	case uint:
		return result.SetUint64(uint64(number)), true
	case uint8:
		return result.SetUint64(uint64(number)), true
	case uint16:
		return result.SetUint64(uint64(number)), true
	case uint32:
		return result.SetUint64(uint64(number)), true
	case uint64:
		return result.SetUint64(number), true
	case float32:
		converted := result.SetFloat64(float64(number))
		return converted, converted != nil
	case float64:
		converted := result.SetFloat64(number)
		return converted, converted != nil
	default:
		return nil, false
	}
}
