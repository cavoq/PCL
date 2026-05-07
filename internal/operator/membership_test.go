package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestInOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operands []any
		expected bool
	}{
		{"string in set", "SHA256WithRSA", []any{"SHA256WithRSA", "SHA384WithRSA"}, true},
		{"string not in set", "MD5WithRSA", []any{"SHA256WithRSA", "SHA384WithRSA"}, false},
		{"int in set", 2048, []any{2048, 4096}, true},
		{"int not in set", 1024, []any{2048, 4096}, false},
		{"single operand match", "RSA", []any{"RSA"}, true},
		{"numeric type coercion", 2048, []any{2048.0}, true},
	}

	op := In{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, nil, tt.operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInOperatorNilNode(t *testing.T) {
	op := In{}
	got, _ := op.Evaluate(nil, nil, []any{"a"})
	if got != false {
		t.Error("nil node should return false")
	}
}

func TestInOperatorNoOperands(t *testing.T) {
	op := In{}
	n := node.New("test", "value")
	_, err := op.Evaluate(n, nil, []any{})
	if err == nil {
		t.Error("should error with no operands")
	}
}

func TestNotInOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operands []any
		expected bool
	}{
		{"string not in set", "MD5WithRSA", []any{"SHA256WithRSA", "SHA384WithRSA"}, true},
		{"string in set", "SHA256WithRSA", []any{"SHA256WithRSA", "SHA384WithRSA"}, false},
		{"int not in set", 1024, []any{2048, 4096}, true},
	}

	op := NotIn{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, nil, tt.operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestContainsOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operand  any
		expected bool
	}{
		{"slice contains string", []string{"digitalSignature", "keyEncipherment"}, "digitalSignature", true},
		{"slice does not contain", []string{"digitalSignature", "keyEncipherment"}, "cRLSign", false},
		{"slice contains int", []int{1, 2, 3}, 2, true},
		{"string contains substring", "SHA256WithRSA", "SHA256", true},
		{"string does not contain", "SHA256WithRSA", "MD5", false},
	}

	op := Contains{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, nil, []any{tt.operand})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestContainsWithChildren(t *testing.T) {
	parent := node.New("keyUsage", nil)
	parent.Children["0"] = node.New("0", "digitalSignature")
	parent.Children["1"] = node.New("1", "keyEncipherment")

	op := Contains{}

	got, err := op.Evaluate(parent, nil, []any{"digitalSignature"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("should find digitalSignature in children")
	}

	got, err = op.Evaluate(parent, nil, []any{"cRLSign"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("should not find cRLSign in children")
	}
}

func TestContainsNilNode(t *testing.T) {
	op := Contains{}
	got, _ := op.Evaluate(nil, nil, []any{"a"})
	if got != false {
		t.Error("nil node should return false")
	}
}

func TestContainsWrongOperands(t *testing.T) {
	op := Contains{}
	n := node.New("test", []string{"a"})

	_, err := op.Evaluate(n, nil, []any{})
	if err == nil {
		t.Error("should error with no operands")
	}

	// Multiple operands now allowed (any match semantics)
	result, err := op.Evaluate(n, nil, []any{"a", "b"})
	if err != nil {
		t.Error("multiple operands should now be allowed")
	}
	if !result {
		t.Error("should match 'a' in slice")
	}

	// Test multiple operands with no match
	result, err = op.Evaluate(n, nil, []any{"x", "y"})
	if err != nil {
		t.Error("multiple operands should be allowed")
	}
	if result {
		t.Error("should not match 'x' or 'y' in slice")
	}
}

func TestDEREqualsHex(t *testing.T) {
	// RSA AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
	// DER encoding: 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00
	rsaDER := []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00}

	// ECDSA with secp256r1: SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 }
	// DER encoding: 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07
	ecdsaDER := []byte{0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

	tests := []struct {
		name     string
		value    any
		operands []any
		expected bool
	}{
		{"exact match RSA", rsaDER, []any{"300d06092a864886f70d0101010500"}, true},
		{"exact match ECDSA", ecdsaDER, []any{"301306072a8648ce3d020106082a8648ce3d030107"}, true},
		{"no match", rsaDER, []any{"301306072a8648ce3d0201"}, false},
		{"multiple operands - one matches", rsaDER, []any{"301306072a8648ce3d0201", "300d06092a864886f70d0101010500"}, true},
		{"multiple operands - none match", rsaDER, []any{"301306072a8648ce3d0201", "deadbeef"}, false},
		{"invalid hex operand skipped", rsaDER, []any{"not-valid-hex", "300d06092a864886f70d0101010500"}, true},
		{"non-string operand skipped", rsaDER, []any{123, "300d06092a864886f70d0101010500"}, true},
		{"wrong type value", "not bytes", []any{"300d06092a864886f70d0101010500"}, false},
	}

	op := DEREqualsHex{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, nil, tt.operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDEREqualsHexNilNode(t *testing.T) {
	op := DEREqualsHex{}
	got, _ := op.Evaluate(nil, nil, []any{"300d06092a864886f70d0101010500"})
	if got != false {
		t.Error("nil node should return false")
	}
}

func TestDEREqualsHexNoOperands(t *testing.T) {
	op := DEREqualsHex{}
	n := node.New("test", []byte{0x30, 0x0d})
	_, err := op.Evaluate(n, nil, []any{})
	if err == nil {
		t.Error("should error with no operands")
	}
}
