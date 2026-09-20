package crl

import (
	cryptox509 "crypto/x509"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestCatalogAndOneShotProduceExpectedAssessment(t *testing.T) {
	fixture := makeCatalogTargetFixture(t)
	lists := []*x509.RevocationList{
		fixture.secondList,
		nil,
		fixture.firstList,
		fixture.firstList,
	}

	assessments := []Assessment{
		AssessCertificate(fixture.firstTarget, lists, fixture.context),
		NewCatalog(lists, fixture.context).AssessCertificate(fixture.firstTarget),
	}
	for index, assessment := range assessments {
		if assessment.Status() != RevocationRevoked || assessment.Revocation == nil ||
			assessment.Revocation.CRL != fixture.firstList ||
			assessment.Revocation.EntryIndex != 0 ||
			len(assessment.Evidence) != 1 ||
			!assessment.Evidence[0].Accepted ||
			assessment.Evidence[0].CRL != fixture.firstList {
			t.Fatalf("assessment %d = %#v, want first-list revocation", index, assessment)
		}
	}
}

func TestCatalogReusesEqualRankedListsAcrossTargets(t *testing.T) {
	fixture := makeCatalogTargetFixture(t)
	catalog := NewCatalog(
		[]*x509.RevocationList{fixture.secondList, fixture.firstList},
		fixture.context,
	)

	tests := []struct {
		name        string
		target      *x509.Certificate
		revokingCRL *x509.RevocationList
	}{
		{name: "second target", target: fixture.secondTarget, revokingCRL: fixture.secondList},
		{name: "first target", target: fixture.firstTarget, revokingCRL: fixture.firstList},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assessment := catalog.AssessCertificate(test.target)
			if assessment.Status() != RevocationRevoked || assessment.Revocation == nil {
				t.Fatalf("assessment = status %v, revocation %#v, evidence %#v", assessment.Status(), assessment.Revocation, assessment.Evidence)
			}
			if assessment.Revocation.CRL != test.revokingCRL ||
				len(assessment.Evidence) != 1 || assessment.Evidence[0].CRL != test.revokingCRL {
				t.Fatalf("selected evidence = %#v, want target's equal-ranked CRL", assessment.Evidence)
			}
		})
	}
}

func TestCatalogKeepsSignerAuthorizationTargetScoped(t *testing.T) {
	material := makeRevocationMaterial(t)
	rejectedTarget := *material.leaf
	rejectedTarget.SerialNumber = new(big.Int).Add(material.leaf.SerialNumber, big.NewInt(1))

	var lock sync.Mutex
	calls := make(map[string]int)
	authorizer := SignerAuthorizerFunc(func(
		target, _ *x509.Certificate,
		_ *x509.RevocationList,
	) bool {
		serial := target.SerialNumber.String()
		lock.Lock()
		calls[serial]++
		lock.Unlock()
		return target.SerialNumber.Cmp(material.leaf.SerialNumber) == 0
	})
	catalog := NewCatalog([]*x509.RevocationList{material.clean}, RevocationContext{
		Now:             material.now,
		Issuers:         []*x509.Certificate{material.issuer},
		AuthorizeSigner: authorizer,
	})

	if assessment := catalog.AssessCertificate(material.leaf); assessment.Status() != RevocationGood {
		t.Fatalf("authorized target status = %v, evidence %#v", assessment.Status(), assessment.Evidence)
	}
	assessment := catalog.AssessCertificate(&rejectedTarget)
	if assessment.Status() != RevocationUnknown || len(assessment.Evidence) != 1 ||
		assessment.Evidence[0].Rejection != EvidenceSignerUnauthorized {
		t.Fatalf("rejected target assessment = status %v, evidence %#v", assessment.Status(), assessment.Evidence)
	}
	if assessment := catalog.AssessCertificate(material.leaf); assessment.Status() != RevocationGood {
		t.Fatalf("reused authorized target status = %v, evidence %#v", assessment.Status(), assessment.Evidence)
	}

	lock.Lock()
	defer lock.Unlock()
	if calls[material.leaf.SerialNumber.String()] == 0 || calls[rejectedTarget.SerialNumber.String()] == 0 {
		t.Fatalf("authorizer calls = %v, want independent calls for both targets", calls)
	}
}

func TestCatalogCachesSignerAuthorizationWithinAssessment(t *testing.T) {
	material := makeRevocationMaterial(t)
	target := *material.leaf
	target.Extensions = append(
		append([]pkix.Extension(nil), material.leaf.Extensions...),
		pkix.Extension{
			Id: zasn1.ObjectIdentifier{2, 5, 29, 31},
			Value: catalogDistributionPointsURIs(
				t,
				"http://example.test/first.crl",
				"http://example.test/second.crl",
			),
		},
	)

	calls := 0
	catalog := NewCatalog([]*x509.RevocationList{material.clean}, RevocationContext{
		Now:     material.now,
		Issuers: []*x509.Certificate{material.issuer},
		AuthorizeSigner: SignerAuthorizerFunc(func(
			_, _ *x509.Certificate,
			_ *x509.RevocationList,
		) bool {
			calls++
			return false
		}),
	})

	assessment := catalog.AssessCertificate(&target)
	if len(assessment.Evidence) != 2 {
		t.Fatalf("evidence count = %d, want 2: %#v", len(assessment.Evidence), assessment.Evidence)
	}
	for _, evidence := range assessment.Evidence {
		if evidence.Rejection != EvidenceSignerUnauthorized {
			t.Fatalf("evidence rejection = %q, want %q", evidence.Rejection, EvidenceSignerUnauthorized)
		}
	}
	if calls != 1 {
		t.Fatalf("authorizer calls = %d, want one cached decision", calls)
	}
}

func TestCatalogDefersSignerVerificationForMalformedTargetPoints(t *testing.T) {
	material := makeRevocationMaterial(t)
	malformed := *material.leaf
	malformed.Extensions = append(
		append([]pkix.Extension(nil), material.leaf.Extensions...),
		pkix.Extension{
			Id:    zasn1.ObjectIdentifier{2, 5, 29, 31},
			Value: []byte{0x05, 0x00},
		},
	)
	catalog := NewCatalog([]*x509.RevocationList{material.clean}, RevocationContext{
		Now:     material.now,
		Issuers: []*x509.Certificate{material.issuer},
	})

	assessment := catalog.AssessCertificate(&malformed)
	if len(assessment.Evidence) != 1 ||
		assessment.Evidence[0].Rejection != EvidenceCertificateDistributionPoint {
		t.Fatalf("malformed-point evidence = %#v", assessment.Evidence)
	}
	if catalog.records[0].authentication.value.sawVerifying {
		t.Fatal("malformed target triggered CRL signature verification")
	}

	if assessment := catalog.AssessCertificate(material.leaf); assessment.Status() != RevocationGood {
		t.Fatalf("valid target status = %v, evidence %#v", assessment.Status(), assessment.Evidence)
	}
	if !catalog.records[0].authentication.value.sawVerifying {
		t.Fatal("valid target did not initialize signer verification")
	}
}

func TestCatalogSupportsConcurrentReadOnlyReuse(t *testing.T) {
	fixture := makeCatalogTargetFixture(t)
	var authorizerCalls atomic.Int64
	fixture.context.AuthorizeSigner = SignerAuthorizerFunc(func(
		target, _ *x509.Certificate,
		_ *x509.RevocationList,
	) bool {
		authorizerCalls.Add(1)
		return target == fixture.firstTarget || target == fixture.secondTarget
	})
	catalog := NewCatalog(
		[]*x509.RevocationList{fixture.firstList, fixture.secondList},
		fixture.context,
	)

	type check struct {
		target *x509.Certificate
		list   *x509.RevocationList
	}
	checks := []check{
		{target: fixture.firstTarget, list: fixture.firstList},
		{target: fixture.secondTarget, list: fixture.secondList},
	}

	const workers = 32
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		check := checks[index%len(checks)]
		group.Add(1)
		go func() {
			defer group.Done()
			assessment := catalog.AssessCertificate(check.target)
			if assessment.Status() != RevocationRevoked || assessment.Revocation == nil ||
				assessment.Revocation.CRL != check.list {
				errors <- fmt.Errorf("status %v, revocation %#v", assessment.Status(), assessment.Revocation)
			}
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if authorizerCalls.Load() == 0 {
		t.Fatal("concurrent target-dependent authorizer was not called")
	}
}

type catalogTargetFixture struct {
	firstTarget  *x509.Certificate
	secondTarget *x509.Certificate
	firstList    *x509.RevocationList
	secondList   *x509.RevocationList
	context      RevocationContext
}

func makeCatalogTargetFixture(t *testing.T) catalogTargetFixture {
	t.Helper()
	material := makeRevocationMaterial(t)
	secondTarget := *material.leaf
	secondTarget.SerialNumber = new(big.Int).Add(material.leaf.SerialNumber, big.NewInt(1))

	thisUpdate := material.now.Add(-time.Hour)
	nextUpdate := material.now.Add(time.Hour)
	firstList := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		90,
		thisUpdate,
		nextUpdate,
		[]cryptox509.RevocationListEntry{{
			SerialNumber:   new(big.Int).Set(material.leaf.SerialNumber),
			RevocationTime: material.now.Add(-30 * time.Minute),
		}},
		nil,
	)
	secondList := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		90,
		thisUpdate,
		nextUpdate,
		[]cryptox509.RevocationListEntry{{
			SerialNumber:   new(big.Int).Set(secondTarget.SerialNumber),
			RevocationTime: material.now.Add(-30 * time.Minute),
		}},
		nil,
	)

	return catalogTargetFixture{
		firstTarget:  material.leaf,
		secondTarget: &secondTarget,
		firstList:    firstList,
		secondList:   secondList,
		context: RevocationContext{
			Now:     material.now,
			Issuers: []*x509.Certificate{material.issuer},
		},
	}
}

func catalogDistributionPointsURIs(t *testing.T, uris ...string) []byte {
	t.Helper()
	return marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		for _, uri := range uris {
			builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
				builder.AddASN1(
					cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(),
					func(builder *cryptobyte.Builder) {
						builder.AddASN1(
							cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(),
							func(builder *cryptobyte.Builder) {
								builder.AddASN1(
									cryptobyte_asn1.Tag(6).ContextSpecific(),
									func(builder *cryptobyte.Builder) {
										builder.AddBytes([]byte(uri))
									},
								)
							},
						)
					},
				)
			})
		}
	})
}
