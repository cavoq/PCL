package x509ext

import (
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestDecodeDistributionPointsUnusualForms(t *testing.T) {
	issuerOnly := buildBoundaryDistributionPoints(func(point *cryptobyte.Builder) {
		point.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(issuer *cryptobyte.Builder) {
			addBoundaryGeneralName(issuer, boundaryGeneralName{tag: 2, content: []byte("crl-issuer.example.test")})
		})
	})
	points, err := DecodeDistributionPoints(issuerOnly)
	if err != nil {
		t.Fatalf("cRLIssuer-only DecodeDistributionPoints() error = %v", err)
	}
	if len(points) != 1 || points[0].Name != nil || points[0].Reasons != nil ||
		len(points[0].CRLIssuer) != 1 || points[0].CRLIssuer[0].Tag != 2 {
		t.Fatalf("cRLIssuer-only point = %#v", points)
	}
	facts, err := DecodeCRLDistributionPointsStrict(issuerOnly)
	if err != nil || len(facts.DistributionPoints) != 1 ||
		facts.DistributionPoints[0].DistributionPointPresent ||
		!slices.Equal(facts.DistributionPoints[0].CRLIssuerGeneralNameTags, []int{2}) {
		t.Fatalf("cRLIssuer-only facts = %#v, %v", facts, err)
	}

	full := buildBoundaryDistributionPoints(func(point *cryptobyte.Builder) {
		point.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(distributionPoint *cryptobyte.Builder) {
			distributionPoint.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(names *cryptobyte.Builder) {
				addBoundaryGeneralName(names, boundaryGeneralName{tag: 6, content: []byte("https://crl.example.test/root.crl")})
				addBoundaryGeneralName(names, boundaryGeneralName{tag: 2, content: []byte("mirror.example.test")})
				addBoundaryGeneralName(names, boundaryGeneralName{tag: 6, content: []byte("https://crl.example.test/root.crl")})
			})
		})
		point.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(reasons *cryptobyte.Builder) {
			reasons.AddBytes([]byte{0x06, 0x40})
		})
		point.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(issuer *cryptobyte.Builder) {
			addBoundaryGeneralName(issuer, boundaryGeneralName{
				tag: 4, constructed: true, content: boundaryDirectoryNameDER("CRL Issuer"),
			})
		})
	})
	points, err = DecodeDistributionPoints(full)
	if err != nil {
		t.Fatalf("full DecodeDistributionPoints() error = %v", err)
	}
	uris := DistributionPointURIs(points)
	if !slices.Equal(uris, []string{"https://crl.example.test/root.crl"}) {
		t.Fatalf("DistributionPointURIs() = %q", uris)
	}
	facts, err = DecodeCRLDistributionPointsStrict(full)
	if err != nil {
		t.Fatalf("DecodeCRLDistributionPointsStrict() error = %v", err)
	}
	pointFacts := facts.DistributionPoints[0]
	if pointFacts.DistributionPointNameKind != CRLDistributionPointNameFullName ||
		!pointFacts.ReasonsPresent || pointFacts.ReasonMask != ReasonKeyCompromise ||
		!slices.Equal(pointFacts.FullNameGeneralNameTags, []int{6, 2, 6}) ||
		!slices.Equal(pointFacts.CRLIssuerGeneralNameTags, []int{4}) {
		t.Fatalf("full distribution point facts = %#v", pointFacts)
	}
}

func TestDistributionPointExpansionFailuresAndIntersection(t *testing.T) {
	if _, err := ExpandDistributionPointName(nil, nil); err == nil {
		t.Fatal("ExpandDistributionPointName(nil) succeeded")
	}
	invalid := &DistributionPointName{Kind: DistributionPointNameRelative}
	if _, err := ExpandDistributionPointName(invalid, nil); err == nil {
		t.Fatal("empty relative distribution point name succeeded")
	}
	invalid.RelativeRDN = []byte{0x02, 0x01, 0x00}
	if _, err := ExpandDistributionPointName(invalid, []byte{0x01, 0x01, 0xff}); err == nil {
		t.Fatal("invalid base Name succeeded")
	}
	left := &DistributionPointName{
		Kind:     DistributionPointNameFullName,
		FullName: []GeneralName{{Tag: 6, RawDER: []byte{0x86, 0x01, 'a'}, RawValue: []byte("a")}},
	}
	right := &DistributionPointName{
		Kind:     DistributionPointNameFullName,
		FullName: []GeneralName{{Tag: 6, RawDER: []byte{0x86, 0x01, 'b'}, RawValue: []byte("b")}},
	}
	if DistributionPointNamesIntersect(left, right, nil, nil) {
		t.Fatal("different full distribution point names intersected")
	}
	if DistributionPointNamesIntersect(invalid, left, nil, nil) {
		t.Fatal("invalid distribution point name intersected")
	}
}

func TestDecodeDistributionPointsRejectsAdversarialDER(t *testing.T) {
	malformed := map[string][]byte{
		"absent value":        nil,
		"wrong outer tag":     {0x31, 0x00},
		"empty points":        {0x30, 0x00},
		"wrong point tag":     {0x30, 0x03, 0x02, 0x01, 0x00},
		"empty point":         {0x30, 0x02, 0x30, 0x00},
		"reasons only":        {0x30, 0x06, 0x30, 0x04, 0x81, 0x02, 0x06, 0x40},
		"empty issuer":        {0x30, 0x04, 0x30, 0x02, 0xa2, 0x00},
		"unknown field":       {0x30, 0x05, 0x30, 0x03, 0x83, 0x01, 0x00},
		"primitive name tag":  {0x30, 0x05, 0x30, 0x03, 0x80, 0x01, 0x00},
		"constructed reasons": {0x30, 0x06, 0x30, 0x04, 0xa1, 0x02, 0x06, 0x40},
		"out of order": {
			0x30, 0x0d, 0x30, 0x0b,
			0xa2, 0x03, 0x82, 0x01, 'x',
			0x81, 0x02, 0x06, 0x40,
		},
		"empty full name":     {0x30, 0x06, 0x30, 0x04, 0xa0, 0x02, 0xa0, 0x00},
		"empty relative name": {0x30, 0x06, 0x30, 0x04, 0xa0, 0x02, 0xa1, 0x00},
		"unknown name choice": {0x30, 0x07, 0x30, 0x05, 0xa0, 0x03, 0xa2, 0x01, 0x00},
	}
	for name, der := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDistributionPoints(der); err == nil {
				t.Fatalf("DecodeDistributionPoints(%x) accepted malformed DER", der)
			}
		})
	}
}

func buildBoundaryDistributionPoints(addPoint func(*cryptobyte.Builder)) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(points *cryptobyte.Builder) {
		points.AddASN1(cryptobyte_asn1.SEQUENCE, addPoint)
	})
	return builder.BytesOrPanic()
}
