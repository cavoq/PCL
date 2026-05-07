package asn1

import "testing"

func TestParamsStateZeroValue(t *testing.T) {
	var state ParamsState
	if state.IsNull || state.IsAbsent || state.OID != "" || state.PSS != nil || state.OAEP != nil {
		t.Fatalf("unexpected zero value: %+v", state)
	}
}

func TestAlgorithmIdentifierCarriesNestedParams(t *testing.T) {
	algo := AlgorithmIdentifier{
		OID: oidMGF1,
		Params: ParamsState{
			OID: oidSHA1,
		},
	}

	if algo.OID != oidMGF1 {
		t.Fatalf("expected MGF1 OID, got %q", algo.OID)
	}
	if algo.Params.OID != oidSHA1 {
		t.Fatalf("expected SHA1 nested OID, got %q", algo.Params.OID)
	}
}
