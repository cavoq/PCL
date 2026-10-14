package crl

import (
	cryptopkix "crypto/x509/pkix"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
)

func TestCatalogSkipsNewerIncompatibleDelta(t *testing.T) {
	fixture := makeDeltaCatalogFixture(t)
	compatible := fixture.delta(t, 101, fixture.material.now.Add(-20*time.Minute), 100)
	newerIncompatible := fixture.delta(t, 105, fixture.material.now.Add(-5*time.Minute), 101)

	assessment := NewCatalog(
		[]*x509.RevocationList{newerIncompatible, fixture.base, compatible},
		fixture.context,
	).AssessCertificate(fixture.material.leaf)
	assertSelectedDelta(t, assessment, compatible)
}

func TestCatalogDeltaWinnerOrdering(t *testing.T) {
	fixture := makeDeltaCatalogFixture(t)
	equalTime := fixture.material.now.Add(-10 * time.Minute)
	higherNumberOlder := fixture.delta(t, 102, fixture.material.now.Add(-20*time.Minute), 100)
	lowerNumberNewer := fixture.delta(t, 101, fixture.material.now.Add(-5*time.Minute), 100)
	lowerNumberEqualTime := fixture.delta(t, 101, equalTime, 100)
	higherNumberEqualTime := fixture.delta(t, 102, equalTime, 100)

	tests := []struct {
		name   string
		first  *x509.RevocationList
		second *x509.RevocationList
		want   *x509.RevocationList
	}{
		{
			name:   "newer thisUpdate precedes higher CRL number",
			first:  higherNumberOlder,
			second: lowerNumberNewer,
			want:   lowerNumberNewer,
		},
		{
			name:   "higher CRL number breaks equal-time tie",
			first:  lowerNumberEqualTime,
			second: higherNumberEqualTime,
			want:   higherNumberEqualTime,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assessment := NewCatalog(
				[]*x509.RevocationList{test.first, fixture.base, test.second},
				fixture.context,
			).AssessCertificate(fixture.material.leaf)
			assertSelectedDelta(t, assessment, test.want)
		})
	}
}

func TestCatalogDeltaSelectionIsInputOrderIndependent(t *testing.T) {
	fixture := makeDeltaCatalogFixture(t)
	winner := fixture.delta(t, 102, fixture.material.now.Add(-10*time.Minute), 100)
	older := fixture.delta(t, 103, fixture.material.now.Add(-20*time.Minute), 100)
	newerIncompatible := fixture.delta(t, 104, fixture.material.now.Add(-5*time.Minute), 101)
	lists := []*x509.RevocationList{fixture.base, winner, older, newerIncompatible}

	for index, permutation := range revocationListPermutations(lists) {
		assessment := NewCatalog(permutation, fixture.context).
			AssessCertificate(fixture.material.leaf)
		if assessment.Status() != RevocationGood || len(assessment.Evidence) != 1 ||
			assessment.Evidence[0].Delta != winner {
			t.Fatalf(
				"permutation %d selected status %v, evidence %#v; want delta %p",
				index,
				assessment.Status(),
				assessment.Evidence,
				winner,
			)
		}
	}
}

type deltaCatalogFixture struct {
	material revocationMaterial
	base     *x509.RevocationList
	context  RevocationContext
}

func makeDeltaCatalogFixture(t *testing.T) deltaCatalogFixture {
	t.Helper()
	material := makeRevocationMaterial(t)
	base := makeAssessmentCRL(
		t,
		material.ca,
		100,
		material.now.Add(-2*time.Hour),
		material.now.Add(2*time.Hour),
		nil,
		[]cryptopkix.Extension{freshestCRLExtension(t)},
	)
	return deltaCatalogFixture{
		material: material,
		base:     base,
		context: RevocationContext{
			Now:       material.now,
			Issuers:   []*x509.Certificate{material.issuer},
			UseDeltas: true,
		},
	}
}

func (fixture deltaCatalogFixture) delta(
	t *testing.T,
	number int64,
	thisUpdate time.Time,
	baseNumber int64,
) *x509.RevocationList {
	t.Helper()
	return makeAssessmentCRL(
		t,
		fixture.material.ca,
		number,
		thisUpdate,
		fixture.material.now.Add(2*time.Hour),
		nil,
		[]cryptopkix.Extension{deltaCRLIndicator(t, baseNumber)},
	)
}

func assertSelectedDelta(
	t *testing.T,
	assessment Assessment,
	want *x509.RevocationList,
) {
	t.Helper()
	if assessment.Status() != RevocationGood || len(assessment.Evidence) != 1 ||
		!assessment.Evidence[0].Accepted || assessment.Evidence[0].Delta != want {
		t.Fatalf(
			"assessment = status %v, evidence %#v; want accepted delta %p",
			assessment.Status(),
			assessment.Evidence,
			want,
		)
	}
}

func revocationListPermutations(
	lists []*x509.RevocationList,
) [][]*x509.RevocationList {
	working := append([]*x509.RevocationList(nil), lists...)
	var permutations [][]*x509.RevocationList
	var visit func(int)
	visit = func(offset int) {
		if offset == len(working) {
			permutations = append(
				permutations,
				append([]*x509.RevocationList(nil), working...),
			)
			return
		}
		for index := offset; index < len(working); index++ {
			working[offset], working[index] = working[index], working[offset]
			visit(offset + 1)
			working[offset], working[index] = working[index], working[offset]
		}
	}
	visit(0)
	return permutations
}
