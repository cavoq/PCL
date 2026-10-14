package x509node_test

import (
	"encoding/hex"
	"testing"

	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
)

func TestBuildReasonFlagsProjectsEveryFlag(t *testing.T) {
	// keyCompromise (bit 1) and superseded (bit 4): 0x48 with 3 unused bits.
	reasons, err := x509ext.DecodeReasonFlagsContents([]byte{0x03, 0x48})
	if err != nil {
		t.Fatalf("DecodeReasonFlagsContents: %v", err)
	}

	n := x509node.BuildReasonFlags("reasons", &reasons)
	if n.Value != uint16(reasons.Mask) {
		t.Fatalf("value = %#v, want mask %#v", n.Value, uint16(reasons.Mask))
	}
	if n.Children["present"].Value != true {
		t.Fatal("present must be true")
	}
	for _, descriptor := range x509ext.ReasonFlagDescriptors() {
		want := descriptor.CanonicalName == "keyCompromise" || descriptor.CanonicalName == "superseded"
		flag := n.Children[descriptor.CanonicalName]
		if flag == nil || flag.Value != want {
			t.Errorf("%s = %v, want %v", descriptor.CanonicalName, flag, want)
		}
	}

	raw, ok := n.Children["raw"].Value.([]byte)
	if !ok {
		t.Fatalf("raw has type %T, want []byte", n.Children["raw"].Value)
	}
	matched, err := operator.DEREqualsHex{}.Evaluate(n.Children["raw"], nil, []any{hex.EncodeToString(raw)})
	if err != nil || !matched {
		t.Fatalf("derEqualsHex on reasons.raw = %v, %v", matched, err)
	}
}
