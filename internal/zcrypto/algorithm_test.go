package zcrypto

import (
	"testing"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
)

func TestBuildAlgorithmIdentifier(t *testing.T) {
	n := BuildAlgorithmIdentifier("signatureAlgorithm", "SHA256-RSA", internalasn1.ParamsState{
		OID:    "1.2.840.113549.1.1.11",
		IsNull: true,
		RawDER: []byte{0x30, 0x0d},
	})

	tests := map[string]any{
		"signatureAlgorithm.algorithm":       "SHA256-RSA",
		"signatureAlgorithm.oid":             "1.2.840.113549.1.1.11",
		"signatureAlgorithm.parameters.null": true,
	}
	for path, want := range tests {
		got, ok := n.Resolve(path)
		if !ok || got.Value != want {
			t.Fatalf("%s = %v, want %v", path, got, want)
		}
	}
	if raw, ok := n.Resolve("signatureAlgorithm.rawDER"); !ok || len(raw.Value.([]byte)) == 0 {
		t.Fatal("raw AlgorithmIdentifier DER missing")
	}

	absent := BuildAlgorithmIdentifier("algorithm", "", internalasn1.ParamsState{
		OID:      "1.3.101.112",
		IsAbsent: true,
	})
	if _, ok := absent.Resolve("algorithm.parameters"); ok {
		t.Fatal("absent parameters must not create a parameters node")
	}
}

func TestBuildAlgorithmIdentifier_PreservesNestedMGF1Identity(t *testing.T) {
	n := BuildAlgorithmIdentifier("signatureAlgorithm", "RSASSA-PSS", internalasn1.ParamsState{
		OID: "1.2.840.113549.1.1.10",
		PSS: &internalasn1.PSSParams{
			MaskGenAlgorithm: internalasn1.AlgorithmIdentifier{
				OID: "1.2.840.113549.1.1.8",
				Params: internalasn1.ParamsState{
					OID:    "2.16.840.1.101.3.4.2.1",
					IsNull: true,
					RawDER: []byte{0x30, 0x0d},
				},
			},
		},
	})

	tests := map[string]any{
		"signatureAlgorithm.parameters.pss.maskGenAlgorithm.oid":            "1.2.840.113549.1.1.8",
		"signatureAlgorithm.parameters.pss.maskGenAlgorithm.parameters.oid": "2.16.840.1.101.3.4.2.1",
	}
	for path, want := range tests {
		got, ok := n.Resolve(path)
		if !ok || got.Value != want {
			t.Fatalf("%s = %v, want %v", path, got, want)
		}
	}
	raw, ok := n.Resolve("signatureAlgorithm.parameters.pss.maskGenAlgorithm.parameters.rawDER")
	if !ok || len(raw.Value.([]byte)) == 0 {
		t.Fatal("nested hash AlgorithmIdentifier DER missing")
	}
}

func TestBuildAlgorithmIdentifier_ProjectsMalformedState(t *testing.T) {
	n := BuildAlgorithmIdentifier("signatureAlgorithm", "", internalasn1.ParamsState{
		Malformed: true,
		RawDER:    []byte{0x30, 0x00},
	})
	malformed, ok := n.Resolve("signatureAlgorithm.malformed")
	if !ok || malformed.Value != true {
		t.Fatalf("malformed state not projected: %v", malformed)
	}
	if _, ok := n.Resolve("signatureAlgorithm.parameters"); ok {
		t.Fatal("malformed parameters must not be projected as a valid parameters node")
	}
}
