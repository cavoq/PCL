package zcrypto

import (
	"math/big"
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestStrictExtensionCountersRetainValuesLargerThanNativeInt(t *testing.T) {
	content := []byte{0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	decimal := new(big.Int).SetBytes(content).String()

	decoded, err := decodeNonNegativeIntegerContent(content)
	if err != nil {
		t.Fatalf("decodeNonNegativeIntegerContent() error = %v", err)
	}
	if decoded.FitsInt || decoded.Decimal != decimal {
		t.Fatalf("decoded counter = %#v, want exact overflow value %s", decoded, decimal)
	}

	t.Run("Basic Constraints", func(t *testing.T) {
		var builder cryptobyte.Builder
		builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
			sequence.AddASN1(cryptobyte_asn1.INTEGER, func(integer *cryptobyte.Builder) {
				integer.AddBytes(content)
			})
		})
		n, err := ParseBasicConstraintsStrict(builder.BytesOrPanic())
		if err != nil {
			t.Fatalf("ParseBasicConstraintsStrict() error = %v", err)
		}
		assertLargeIntegerNode(t, n.Children["pathLenConstraint"], decimal)
	})

	t.Run("Name Constraints", func(t *testing.T) {
		var builder cryptobyte.Builder
		builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
			sequence.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(subtrees *cryptobyte.Builder) {
				subtrees.AddASN1(cryptobyte_asn1.SEQUENCE, func(subtree *cryptobyte.Builder) {
					subtree.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(name *cryptobyte.Builder) {
						name.AddBytes([]byte("example.test"))
					})
					subtree.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific(), func(minimum *cryptobyte.Builder) {
						minimum.AddBytes(content)
					})
				})
			})
		})
		der := builder.BytesOrPanic()
		n, err := ParseNameConstraintsStrict(der)
		if err != nil {
			t.Fatalf("ParseNameConstraintsStrict() error = %v", err)
		}
		assertLargeIntegerNode(t, n.Children["permittedSubtrees"].Children["0"].Children["minimum"], decimal)
		facts, err := DecodeNameConstraintsStrict(der)
		if err != nil {
			t.Fatalf("DecodeNameConstraintsStrict() error = %v", err)
		}
		minimum := facts.PermittedSubtrees[0]
		if minimum.MinimumFitsInt || minimum.MinimumDecimal != decimal {
			t.Fatalf("minimum facts = %#v, want exact overflow value %s", minimum, decimal)
		}
	})

	t.Run("Policy Constraints", func(t *testing.T) {
		var builder cryptobyte.Builder
		builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
			sequence.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific(), func(counter *cryptobyte.Builder) {
				counter.AddBytes(content)
			})
		})
		der := builder.BytesOrPanic()
		n, err := ParsePolicyConstraintsStrict(der)
		if err != nil {
			t.Fatalf("ParsePolicyConstraintsStrict() error = %v", err)
		}
		assertLargeIntegerNode(t, n.Children["requireExplicitPolicy"], decimal)
		facts, err := DecodePolicyConstraintsStrict(der)
		if err != nil {
			t.Fatalf("DecodePolicyConstraintsStrict() error = %v", err)
		}
		if facts.RequireExplicitPolicyFitsInt || facts.RequireExplicitPolicyDecimal != decimal {
			t.Fatalf("policy facts = %#v, want exact overflow value %s", facts, decimal)
		}
	})

	t.Run("Inhibit anyPolicy", func(t *testing.T) {
		var builder cryptobyte.Builder
		builder.AddASN1(cryptobyte_asn1.INTEGER, func(integer *cryptobyte.Builder) {
			integer.AddBytes(content)
		})
		der := builder.BytesOrPanic()
		n, err := ParseInhibitAnyPolicyStrict(der)
		if err != nil {
			t.Fatalf("ParseInhibitAnyPolicyStrict() error = %v", err)
		}
		assertLargeIntegerNode(t, n.Children["skipCerts"], decimal)
		facts, err := DecodeInhibitAnyPolicyStrict(der)
		if err != nil {
			t.Fatalf("DecodeInhibitAnyPolicyStrict() error = %v", err)
		}
		if facts.FitsInt || facts.Decimal != decimal {
			t.Fatalf("inhibit facts = %#v, want exact overflow value %s", facts, decimal)
		}
	})
}

func assertLargeIntegerNode(t *testing.T, n *node.Node, decimal string) {
	t.Helper()
	if n == nil {
		t.Fatal("large INTEGER node is missing")
	}
	if n.Value != decimal {
		t.Fatalf("large INTEGER value = %#v, want decimal %q", n.Value, decimal)
	}
	if fits := n.Children["fitsInt"]; fits == nil || fits.Value != false {
		t.Fatalf("fitsInt = %#v, want false", fits)
	}
	if exact := n.Children["decimal"]; exact == nil || exact.Value != decimal {
		t.Fatalf("decimal = %#v, want %q", exact, decimal)
	}
}
