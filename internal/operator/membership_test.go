package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestMembershipOperators(t *testing.T) {
	is := func(name string, op Operator, value any, operands []any, want bool) evaluationCase {
		return evaluationCase{name: name, op: op, node: node.New("test", value), operands: operands, want: want}
	}
	algorithms := []any{"SHA256WithRSA", "SHA384WithRSA"}
	usages := []string{"digitalSignature", "keyEncipherment"}
	keyUsage := collection("keyUsage", "digitalSignature", "keyEncipherment")
	structured := func() map[string]any { return map[string]any{"key": []any{1, "two"}} }

	// RSA AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
	const rsaHex = "300d06092a864886f70d0101010500"
	rsaDER := []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00}
	// ECDSA with secp256r1: SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 }
	ecdsaDER := []byte{0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

	checkEvaluations(t, nil, []evaluationCase{
		is("in: string in set", In{}, "SHA256WithRSA", algorithms, true),
		is("in: string not in set", In{}, "MD5WithRSA", algorithms, false),
		is("in: int in set", In{}, 2048, []any{2048, 4096}, true),
		is("in: int not in set", In{}, 1024, []any{2048, 4096}, false),
		is("in: single operand match", In{}, "RSA", []any{"RSA"}, true),
		is("in: numeric type coercion", In{}, 2048, []any{2048.0}, true),
		is("in: structured operand match", In{}, structured(), []any{structured()}, true),
		is("in: large integer does not equal rounded float", In{}, int64(9_007_199_254_740_993),
			[]any{float64(9_007_199_254_740_992)}, false),
		{name: "in: nil node", op: In{}, operands: []any{"a"}},
		{name: "in: no operands", op: In{}, node: node.New("test", "value"), operands: []any{}, wantErr: true},

		is("notIn: string not in set", NotIn{}, "MD5WithRSA", algorithms, true),
		is("notIn: string in set", NotIn{}, "SHA256WithRSA", algorithms, false),
		is("notIn: int not in set", NotIn{}, 1024, []any{2048, 4096}, true),
		{name: "notIn: nil node is not a member", op: NotIn{}, operands: []any{"a"}, want: true},

		is("contains: slice contains string", Contains{}, usages, []any{"digitalSignature"}, true),
		is("contains: slice does not contain", Contains{}, usages, []any{"cRLSign"}, false),
		is("contains: slice contains int", Contains{}, []int{1, 2, 3}, []any{2}, true),
		is("contains: string contains substring", Contains{}, "SHA256WithRSA", []any{"SHA256"}, true),
		is("contains: string does not contain", Contains{}, "SHA256WithRSA", []any{"MD5"}, false),
		is("contains: equal structured value", Contains{},
			[]any{map[string]any{"other": true}, map[string]any{"nested": []any{1, "two"}}},
			[]any{map[string]any{"nested": []any{1, "two"}}}, true),
		{name: "contains: children hold the value", op: Contains{}, node: keyUsage, operands: []any{"digitalSignature"}, want: true},
		{name: "contains: children lack the value", op: Contains{}, node: keyUsage, operands: []any{"cRLSign"}},
		{name: "contains: nil node", op: Contains{}, operands: []any{"a"}},
		{name: "contains: no operands", op: Contains{}, node: node.New("test", []string{"a"}), operands: []any{}, wantErr: true},
		is("contains: any of several operands matches", Contains{}, []string{"a"}, []any{"a", "b"}, true),
		is("contains: none of several operands matches", Contains{}, []string{"a"}, []any{"x", "y"}, false),

		is("derEqualsHex: exact match RSA", DEREqualsHex{}, rsaDER, []any{rsaHex}, true),
		is("derEqualsHex: exact match ECDSA", DEREqualsHex{}, ecdsaDER, []any{"301306072a8648ce3d020106082a8648ce3d030107"}, true),
		is("derEqualsHex: no match", DEREqualsHex{}, rsaDER, []any{"301306072a8648ce3d0201"}, false),
		is("derEqualsHex: multiple operands - one matches", DEREqualsHex{}, rsaDER, []any{"301306072a8648ce3d0201", rsaHex}, true),
		is("derEqualsHex: multiple operands - none match", DEREqualsHex{}, rsaDER, []any{"301306072a8648ce3d0201", "deadbeef"}, false),
		is("derEqualsHex: invalid hex operand skipped", DEREqualsHex{}, rsaDER, []any{"not-valid-hex", rsaHex}, true),
		is("derEqualsHex: non-string operand skipped", DEREqualsHex{}, rsaDER, []any{123, rsaHex}, true),
		is("derEqualsHex: wrong type value", DEREqualsHex{}, "not bytes", []any{rsaHex}, false),
		{name: "derEqualsHex: nil node", op: DEREqualsHex{}, operands: []any{rsaHex}},
		{name: "derEqualsHex: no operands", op: DEREqualsHex{}, node: node.New("test", []byte{0x30, 0x0d}), operands: []any{}, wantErr: true},
	})
}

func TestEqualIsStrictAcrossKinds(t *testing.T) {
	tests := []struct {
		name string
		a, b any
		want bool
	}{
		{name: "same string", a: "1.2.3", b: "1.2.3", want: true},
		{name: "numeric kinds", a: uint16(5), b: 5, want: true},
		{name: "number against numeric string", a: 1, b: "1", want: false},
		{name: "bool against string", a: true, b: "true", want: false},
		{name: "nil against nil string form", a: nil, b: "<nil>", want: false},
		{name: "bytes against string", a: []byte("ab"), b: "[97 98]", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := equal(test.a, test.b); got != test.want {
				t.Fatalf("equal(%#v, %#v) = %v, want %v", test.a, test.b, got, test.want)
			}
		})
	}
}
