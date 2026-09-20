package crl

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"math/big"
	"testing"
	"time"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestAssessmentAccumulatesReasonCoverage(t *testing.T) {
	material := makeRevocationMaterial(t)
	first := makeAssessmentCRL(t, material.issuerStd, material.issuerKey, 12,
		material.now.Add(-time.Hour), material.now.Add(time.Hour), nil,
		[]cryptopkix.Extension{issuingDistributionPointReasons(t, ReasonKeyCompromise)})
	duplicateCoverage := makeAssessmentCRL(t, material.issuerStd, material.issuerKey, 11,
		material.now.Add(-time.Hour), material.now.Add(time.Hour), nil,
		[]cryptopkix.Extension{issuingDistributionPointReasons(t, ReasonKeyCompromise)})
	second := makeAssessmentCRL(t, material.issuerStd, material.issuerKey, 10,
		material.now.Add(-time.Hour), material.now.Add(time.Hour), nil,
		[]cryptopkix.Extension{issuingDistributionPointReasons(t, AllReasons&^ReasonKeyCompromise)})
	context := RevocationContext{Now: material.now, Issuers: []*x509.Certificate{material.issuer}}

	partial := AssessCertificate(material.leaf, []*x509.RevocationList{first}, context)
	if partial.Status() != RevocationUnknown || partial.CoveredReasons != ReasonKeyCompromise {
		t.Fatalf("partial assessment = status %v, reasons %#x, evidence %+v", partial.Status(), partial.CoveredReasons, partial.Evidence)
	}

	complete := AssessCertificate(
		material.leaf,
		[]*x509.RevocationList{second, duplicateCoverage, first},
		context,
	)
	if complete.Status() != RevocationGood || complete.CoveredReasons != AllReasons {
		t.Fatalf("complete assessment = status %v, reasons %#x", complete.Status(), complete.CoveredReasons)
	}
	if len(complete.Evidence) != 3 ||
		complete.Evidence[1].Rejection != EvidenceNoNewReasons {
		t.Fatalf("duplicate reason partition was not skipped: %+v", complete.Evidence)
	}
}

func TestAssessmentDeltaRemoveFromCRLOverridesStaleBase(t *testing.T) {
	material := makeRevocationMaterial(t)
	hold := 6
	remove := 8
	base := makeAssessmentCRL(t, material.issuerStd, material.issuerKey, 20,
		material.now.Add(-48*time.Hour), material.now.Add(-24*time.Hour),
		[]cryptox509.RevocationListEntry{{
			SerialNumber: material.leaf.SerialNumber, RevocationTime: material.now.Add(-36 * time.Hour),
			ReasonCode: hold,
		}}, []cryptopkix.Extension{freshestCRLExtension(t)})
	delta := makeAssessmentCRL(t, material.issuerStd, material.issuerKey, 21,
		material.now.Add(-time.Hour), material.now.Add(time.Hour),
		[]cryptox509.RevocationListEntry{{
			SerialNumber: material.leaf.SerialNumber, RevocationTime: material.now.Add(-30 * time.Minute),
			ReasonCode: remove,
		}}, []cryptopkix.Extension{deltaCRLIndicator(t, 20)})

	withoutDeltas := AssessCertificate(material.leaf, []*x509.RevocationList{base, delta}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{material.issuer},
	})
	if withoutDeltas.Status() != RevocationUnknown {
		t.Fatalf("without deltas status = %v, want unknown", withoutDeltas.Status())
	}

	withDeltas := AssessCertificate(material.leaf, []*x509.RevocationList{delta, base}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{material.issuer}, UseDeltas: true,
	})
	if withDeltas.Status() != RevocationGood || withDeltas.Revocation != nil {
		t.Fatalf("with deltas assessment = status %v, revocation %+v, evidence %+v", withDeltas.Status(), withDeltas.Revocation, withDeltas.Evidence)
	}
	if len(withDeltas.Evidence) == 0 || withDeltas.Evidence[0].Delta == nil {
		t.Fatal("accepted evidence did not retain the applied delta CRL")
	}

	deltaWithFreshest := makeAssessmentCRL(t, material.issuerStd, material.issuerKey, 22,
		material.now.Add(-30*time.Minute), material.now.Add(time.Hour), nil,
		[]cryptopkix.Extension{deltaCRLIndicator(t, 20), freshestCRLExtension(t)})
	illegalDelta := AssessCertificate(
		material.leaf,
		[]*x509.RevocationList{base, deltaWithFreshest},
		RevocationContext{
			Now: material.now, Issuers: []*x509.Certificate{material.issuer}, UseDeltas: true,
		},
	)
	if illegalDelta.Status() != RevocationUnknown || len(illegalDelta.Evidence) == 0 ||
		illegalDelta.Evidence[0].Delta != nil ||
		illegalDelta.Evidence[0].Rejection != EvidenceNotCurrent {
		t.Fatalf("delta carrying Freshest was applied: %+v", illegalDelta)
	}
}

func TestAssessmentIndirectCRLInheritsCertificateIssuer(t *testing.T) {
	material := makeRevocationMaterial(t)
	delegateStd, delegate, delegateKey := makeCRLDelegate(t, material)
	certificate := *material.leaf
	certificate.Extensions = append(append([]zpkix.Extension(nil), material.leaf.Extensions...),
		zpkix.Extension{
			Id:    zasn1.ObjectIdentifier{2, 5, 29, 31},
			Value: distributionPointWithCRLIssuer(t, material.issuer.RawSubject, delegate.RawSubject),
		})
	entries := []cryptox509.RevocationListEntry{
		{
			SerialNumber: big.NewInt(7), RevocationTime: material.now.Add(-time.Hour),
			ExtraExtensions: []cryptopkix.Extension{certificateIssuerExtension(t, material.leaf.RawIssuer)},
		},
		{SerialNumber: material.leaf.SerialNumber, RevocationTime: material.now.Add(-30 * time.Minute)},
	}
	list := makeAssessmentCRL(t, delegateStd, delegateKey, 30,
		material.now.Add(-time.Hour), material.now.Add(time.Hour), entries,
		[]cryptopkix.Extension{indirectIssuingDistributionPoint(t)})

	assessment := AssessCertificate(&certificate, []*x509.RevocationList{list}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{delegate},
	})
	if assessment.Status() != RevocationRevoked || assessment.Revocation == nil ||
		assessment.Revocation.EntryIndex != 1 {
		t.Fatalf("indirect assessment = status %v, revocation %+v, evidence %+v", assessment.Status(), assessment.Revocation, assessment.Evidence)
	}
}

func TestAssessmentSignerAuthorizationAndKeyUsage(t *testing.T) {
	material := makeRevocationMaterial(t)
	reject := SignerAuthorizerFunc(func(
		_, _ *x509.Certificate,
		_ *x509.RevocationList,
	) bool {
		return false
	})
	unauthorized := AssessCertificate(material.leaf, []*x509.RevocationList{material.clean}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{material.issuer}, AuthorizeSigner: reject,
	})
	if unauthorized.Status() != RevocationUnknown || len(unauthorized.Evidence) != 1 ||
		unauthorized.Evidence[0].Rejection != EvidenceSignerUnauthorized {
		t.Fatalf("unauthorized assessment = status %v, evidence %+v", unauthorized.Status(), unauthorized.Evidence)
	}

	withoutCRLSign := *material.issuer
	withoutCRLSign.KeyUsage &^= x509.KeyUsageCRLSign
	badUsage := AssessCertificate(material.leaf, []*x509.RevocationList{material.clean}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{&withoutCRLSign},
	})
	if badUsage.Status() != RevocationUnknown || len(badUsage.Evidence) != 1 ||
		badUsage.Evidence[0].Rejection != EvidenceSignerKeyUsage {
		t.Fatalf("bad key usage assessment = status %v, evidence %+v", badUsage.Status(), badUsage.Evidence)
	}

	withoutSubjectKeyID := *material.issuer
	withoutSubjectKeyID.SubjectKeyId = nil
	badIdentifier := AssessCertificate(material.leaf, []*x509.RevocationList{material.clean}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{&withoutSubjectKeyID},
	})
	if badIdentifier.Status() != RevocationUnknown || len(badIdentifier.Evidence) != 1 ||
		badIdentifier.Evidence[0].Rejection != EvidenceSignerUnavailable {
		t.Fatalf("bad signer identifier assessment = status %v, evidence %+v", badIdentifier.Status(), badIdentifier.Evidence)
	}
}

func TestAssessmentIsOrderIndependentAndDeduplicates(t *testing.T) {
	material := makeRevocationMaterial(t)
	context := RevocationContext{Now: material.now, Issuers: []*x509.Certificate{material.issuer}}
	first := AssessCertificate(material.leaf, []*x509.RevocationList{material.clean, material.revoked}, context)
	second := AssessCertificate(material.leaf, []*x509.RevocationList{material.revoked, material.clean}, context)
	if first.Status() != RevocationRevoked || second.Status() != RevocationRevoked {
		t.Fatalf("conflicting status = %v and %v, want revoked", first.Status(), second.Status())
	}

	deduplicated := AssessCertificate(material.leaf, []*x509.RevocationList{material.clean, material.clean}, context)
	if deduplicated.Status() != RevocationGood || len(deduplicated.Evidence) != 1 {
		t.Fatalf("deduplicated assessment = status %v, evidence %d", deduplicated.Status(), len(deduplicated.Evidence))
	}
}

func TestAssessmentIdentityDifferencesCannotShadowValidCRL(t *testing.T) {
	material := makeRevocationMaterial(t)
	context := RevocationContext{Now: material.now, Issuers: []*x509.Certificate{material.issuer}}

	validFallbackValue := *material.clean
	validFallbackValue.RawIssuer = nil
	unrelatedFallbackValue := validFallbackValue
	unrelatedFallbackValue.Issuer = zpkix.Name{CommonName: "Unrelated CRL issuer"}

	invalidAlgorithmValue := *material.clean
	invalidAlgorithmValue.SignatureAlgorithm = x509.UnknownSignatureAlgorithm

	tests := []struct {
		name     string
		valid    *x509.RevocationList
		rejected *x509.RevocationList
	}{
		{
			name:     "fallback issuer",
			valid:    &validFallbackValue,
			rejected: &unrelatedFallbackValue,
		},
		{
			name:     "signature algorithm",
			valid:    material.clean,
			rejected: &invalidAlgorithmValue,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			orders := [][]*x509.RevocationList{
				{test.rejected, test.valid},
				{test.valid, test.rejected},
			}
			for index, lists := range orders {
				assessment := AssessCertificate(material.leaf, lists, context)
				if assessment.Status() != RevocationGood {
					t.Fatalf("order %d status = %v, want good; evidence = %+v", index, assessment.Status(), assessment.Evidence)
				}
			}
		})
	}
}

func TestRevocationListFingerprintIncludesExtensionCriticality(t *testing.T) {
	identifier := zasn1.ObjectIdentifier{1, 2, 3, 4}
	value := []byte{0x05, 0x00}
	tests := []struct {
		name  string
		first *x509.RevocationList
		other *x509.RevocationList
	}{
		{
			name: "crl extension",
			first: &x509.RevocationList{Extensions: []zpkix.Extension{{
				Id: identifier, Value: value,
			}}},
			other: &x509.RevocationList{Extensions: []zpkix.Extension{{
				Id: identifier, Critical: true, Value: value,
			}}},
		},
		{
			name: "entry extension",
			first: &x509.RevocationList{RevokedCertificates: []x509.RevokedCertificate{{
				Extensions: []zpkix.Extension{{Id: identifier, Value: value}},
			}}},
			other: &x509.RevocationList{RevokedCertificates: []x509.RevokedCertificate{{
				Extensions: []zpkix.Extension{{Id: identifier, Critical: true, Value: value}},
			}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if revocationListFingerprint(test.first) == revocationListFingerprint(test.other) {
				t.Fatal("criticality must contribute to the fallback fingerprint")
			}
		})
	}
}

func TestAssessmentNewerCompleteCRLSupersedesOlderRevocation(t *testing.T) {
	material := makeRevocationMaterial(t)
	older := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		50,
		material.now.Add(-2*time.Hour),
		material.now.Add(2*time.Hour),
		[]cryptox509.RevocationListEntry{{
			SerialNumber:   material.leaf.SerialNumber,
			RevocationTime: material.now.Add(-90 * time.Minute),
		}},
		nil,
	)
	newer := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		51,
		material.now.Add(-time.Hour),
		material.now.Add(3*time.Hour),
		nil,
		nil,
	)
	context := RevocationContext{Now: material.now, Issuers: []*x509.Certificate{material.issuer}}

	for _, lists := range [][]*x509.RevocationList{{older, newer}, {newer, older}} {
		assessment := AssessCertificate(material.leaf, lists, context)
		if assessment.Status() != RevocationGood || len(assessment.Evidence) != 1 ||
			assessment.Evidence[0].CRL != newer {
			t.Fatalf("newer assessment = status %v, evidence %+v", assessment.Status(), assessment.Evidence)
		}
	}
}

func TestAssessmentFallsBackAfterAdvertisedDistributionPointMismatch(t *testing.T) {
	material := makeRevocationMaterial(t)
	certificate := *material.leaf
	certificate.Extensions = append(
		append([]zpkix.Extension(nil), material.leaf.Extensions...),
		zpkix.Extension{
			Id:    zasn1.ObjectIdentifier{2, 5, 29, 31},
			Value: distributionPointsURI(t, "http://example.test/advertised.crl"),
		},
	)
	list := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		60,
		material.now.Add(-time.Hour),
		material.now.Add(time.Hour),
		nil,
		[]cryptopkix.Extension{issuingDistributionPointName(t, material.leaf.RawIssuer)},
	)

	assessment := AssessCertificate(&certificate, []*x509.RevocationList{list}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{material.issuer},
	})
	if assessment.Status() != RevocationGood || len(assessment.Evidence) != 2 ||
		assessment.Evidence[0].Rejection != EvidenceScopeMismatch ||
		!assessment.Evidence[1].Fallback || !assessment.Evidence[1].Accepted {
		t.Fatalf("fallback assessment = status %v, evidence %+v", assessment.Status(), assessment.Evidence)
	}
}

func TestAssessmentRejectsMismatchedCertificateClassScope(t *testing.T) {
	material := makeRevocationMaterial(t)
	list := makeAssessmentCRL(t, material.issuerStd, material.issuerKey, 40,
		material.now.Add(-time.Hour), material.now.Add(time.Hour), nil,
		[]cryptopkix.Extension{onlyCACertificatesIDP(t)})
	assessment := AssessCertificate(material.leaf, []*x509.RevocationList{list}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{material.issuer},
	})
	if assessment.Status() != RevocationUnknown || len(assessment.Evidence) != 1 ||
		assessment.Evidence[0].Applicable {
		t.Fatalf("class-mismatch assessment = status %v, evidence %+v", assessment.Status(), assessment.Evidence)
	}
}

func TestAssessmentRejectsExplicitUnspecifiedReasonInReasonPartition(t *testing.T) {
	material := makeRevocationMaterial(t)
	list := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		41,
		material.now.Add(-time.Hour),
		material.now.Add(time.Hour),
		[]cryptox509.RevocationListEntry{{
			SerialNumber:   material.leaf.SerialNumber,
			RevocationTime: material.now.Add(-30 * time.Minute),
			ReasonCode:     1,
		}},
		[]cryptopkix.Extension{issuingDistributionPointReasons(t, ReasonKeyCompromise)},
	)
	// crypto/x509 deliberately refuses to emit the discouraged explicit zero
	// value.  Change only the parsed extension view so this owner test reaches
	// the domain guard while the original signed TBSCertList remains valid.
	foundReason := false
	for index := range list.RevokedCertificates[0].Extensions {
		extension := &list.RevokedCertificates[0].Extensions[index]
		if extension.Id.String() == "2.5.29.21" {
			extension.Value = []byte{0x0a, 0x01, 0x00}
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatal("test CRL omitted reasonCode extension")
	}
	assessment := AssessCertificate(material.leaf, []*x509.RevocationList{list}, RevocationContext{
		Now: material.now, Issuers: []*x509.Certificate{material.issuer},
	})
	if assessment.Status() != RevocationUnknown || len(assessment.Evidence) != 1 ||
		assessment.Evidence[0].Rejection != EvidenceInvalidEntry {
		t.Fatalf("explicit-unspecified assessment = status %v, evidence %+v", assessment.Status(), assessment.Evidence)
	}

	absentReason := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		42,
		material.now.Add(-time.Hour),
		material.now.Add(time.Hour),
		[]cryptox509.RevocationListEntry{{
			SerialNumber:   material.leaf.SerialNumber,
			RevocationTime: material.now.Add(-30 * time.Minute),
		}},
		[]cryptopkix.Extension{issuingDistributionPointReasons(t, ReasonKeyCompromise)},
	)
	withoutExtension := AssessCertificate(
		material.leaf,
		[]*x509.RevocationList{absentReason},
		RevocationContext{Now: material.now, Issuers: []*x509.Certificate{material.issuer}},
	)
	if withoutExtension.Status() != RevocationRevoked || len(withoutExtension.Evidence) != 1 ||
		!withoutExtension.Evidence[0].Accepted {
		t.Fatalf("absent reasonCode extension was rejected: %+v", withoutExtension)
	}
}

func TestAssessmentAppliesIDPCertificateClassFromBasicConstraints(t *testing.T) {
	material := makeRevocationMaterial(t)
	tests := []struct {
		name                  string
		version               int
		basicConstraintsValid bool
		isCA                  bool
		extension             cryptopkix.Extension
		want                  RevocationStatus
	}{
		{
			name: "legacy end entity is in user scope", version: 2,
			extension: onlyUserCertificatesIDP(t), want: RevocationGood,
		},
		{
			name: "legacy end entity is outside CA scope", version: 2,
			extension: onlyCACertificatesIDP(t), want: RevocationUnknown,
		},
		{
			name: "v3 CA is outside user scope", version: 3,
			basicConstraintsValid: true, isCA: true,
			extension: onlyUserCertificatesIDP(t), want: RevocationUnknown,
		},
		{
			name: "v3 CA is in CA scope", version: 3,
			basicConstraintsValid: true, isCA: true,
			extension: onlyCACertificatesIDP(t), want: RevocationGood,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate := *material.leaf
			certificate.Version = test.version
			certificate.BasicConstraintsValid = test.basicConstraintsValid
			certificate.IsCA = test.isCA
			list := makeAssessmentCRL(
				t,
				material.issuerStd,
				material.issuerKey,
				42,
				material.now.Add(-time.Hour),
				material.now.Add(time.Hour),
				nil,
				[]cryptopkix.Extension{test.extension},
			)
			assessment := AssessCertificate(&certificate, []*x509.RevocationList{list}, RevocationContext{
				Now: material.now, Issuers: []*x509.Certificate{material.issuer},
			})
			if assessment.Status() != test.want || len(assessment.Evidence) != 1 {
				t.Fatalf("class scope = status %v, evidence %+v; want %v", assessment.Status(), assessment.Evidence, test.want)
			}
			if test.want == RevocationGood && !assessment.Evidence[0].Accepted {
				t.Fatalf("in-scope evidence was not accepted: %+v", assessment.Evidence)
			}
			if test.want == RevocationUnknown && assessment.Evidence[0].Rejection != EvidenceScopeMismatch {
				t.Fatalf("out-of-scope rejection = %q, want %q", assessment.Evidence[0].Rejection, EvidenceScopeMismatch)
			}
		})
	}
}

func TestAssessmentReportsStableRejectionReasons(t *testing.T) {
	material := makeRevocationMaterial(t)
	context := RevocationContext{Now: material.now, Issuers: []*x509.Certificate{material.issuer}}

	malformed := *material.clean
	if len(malformed.Extensions) == 0 {
		t.Fatal("test CRL has no extension to duplicate")
	}
	malformed.Extensions = append(
		append([]zpkix.Extension(nil), malformed.Extensions...),
		malformed.Extensions[0],
	)
	unsupported := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		70,
		material.now.Add(-time.Hour),
		material.now.Add(time.Hour),
		nil,
		[]cryptopkix.Extension{{
			Id: stdasn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00},
		}},
	)
	expired := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		71,
		material.now.Add(-2*time.Hour),
		material.now.Add(-time.Hour),
		nil,
		nil,
	)
	invalidEntry := makeAssessmentCRL(
		t,
		material.issuerStd,
		material.issuerKey,
		72,
		material.now.Add(-time.Hour),
		material.now.Add(time.Hour),
		[]cryptox509.RevocationListEntry{{
			SerialNumber:   material.leaf.SerialNumber,
			RevocationTime: material.now.Add(-30 * time.Minute),
			ReasonCode:     8,
		}},
		nil,
	)
	badDistributionPoint := *material.leaf
	badDistributionPoint.Extensions = append(
		append([]zpkix.Extension(nil), material.leaf.Extensions...),
		zpkix.Extension{
			Id: zasn1.ObjectIdentifier{2, 5, 29, 31}, Value: []byte{0x30, 0x00},
		},
	)
	unrelated := *material.clean
	unrelated.Issuer = zpkix.Name{CommonName: "Unrelated CRL issuer"}
	unrelated.RawIssuer = nil

	tests := []struct {
		name        string
		certificate *x509.Certificate
		lists       []*x509.RevocationList
		context     RevocationContext
		want        EvidenceRejection
	}{
		{name: "malformed CRL", certificate: material.leaf, lists: []*x509.RevocationList{&malformed}, context: context, want: EvidenceMalformed},
		{name: "unsupported critical", certificate: material.leaf, lists: []*x509.RevocationList{unsupported}, context: context, want: EvidenceUnsupportedCritical},
		{name: "not current", certificate: material.leaf, lists: []*x509.RevocationList{expired}, context: context, want: EvidenceNotCurrent},
		{name: "signer unavailable", certificate: material.leaf, lists: []*x509.RevocationList{material.clean}, context: RevocationContext{Now: material.now}, want: EvidenceSignerUnavailable},
		{name: "invalid entry", certificate: material.leaf, lists: []*x509.RevocationList{invalidEntry}, context: context, want: EvidenceInvalidEntry},
		{name: "bad certificate distribution point", certificate: &badDistributionPoint, lists: []*x509.RevocationList{material.clean}, context: context, want: EvidenceCertificateDistributionPoint},
		{name: "unrelated", certificate: material.leaf, lists: []*x509.RevocationList{&unrelated}, context: context, want: EvidenceUnrelated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assessment := AssessCertificate(test.certificate, test.lists, test.context)
			if assessment.Status() != RevocationUnknown || len(assessment.Evidence) != 1 ||
				assessment.Evidence[0].Rejection != test.want {
				t.Fatalf("assessment = status %v, evidence %+v; want rejection %q", assessment.Status(), assessment.Evidence, test.want)
			}
		})
	}
}

func TestCertificateRevocationPointsRejectsDuplicateExtensions(t *testing.T) {
	identifiers := []zasn1.ObjectIdentifier{
		{2, 5, 29, 18},
		{2, 5, 29, 31},
		{2, 5, 29, 46},
	}
	for _, identifier := range identifiers {
		t.Run(identifier.String(), func(t *testing.T) {
			extension := zpkix.Extension{Id: identifier, Value: []byte{0x05, 0x00}}
			certificate := &x509.Certificate{Extensions: []zpkix.Extension{extension, extension}}

			_, _, err := certificateRevocationPoints(certificate)
			if err != errDuplicateExtension {
				t.Fatalf("certificateRevocationPoints() error = %v, want %v", err, errDuplicateExtension)
			}
		})
	}
}

func makeAssessmentCRL(
	t *testing.T,
	issuer *cryptox509.Certificate,
	key *rsa.PrivateKey,
	number int64,
	thisUpdate, nextUpdate time.Time,
	entries []cryptox509.RevocationListEntry,
	extensions []cryptopkix.Extension,
) *x509.RevocationList {
	t.Helper()
	der, err := cryptox509.CreateRevocationList(rand.Reader, &cryptox509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		ExtraExtensions:           extensions,
	}, issuer, key)
	if err != nil {
		t.Fatalf("create assessment CRL: %v", err)
	}
	list, err := ParseCRL(der)
	if err != nil {
		t.Fatalf("parse assessment CRL: %v", err)
	}
	return list
}

func issuingDistributionPointReasons(t *testing.T, reasons ReasonSet) cryptopkix.Extension {
	t.Helper()
	value := marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.Tag(3).ContextSpecific(), func(builder *cryptobyte.Builder) {
			builder.AddBytes(reasonFlagsContents(reasons))
		})
	})
	return cryptopkix.Extension{Id: stdasn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: value}
}

func indirectIssuingDistributionPoint(t *testing.T) cryptopkix.Extension {
	t.Helper()
	value := marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.Tag(4).ContextSpecific(), func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte{0xff})
		})
	})
	return cryptopkix.Extension{Id: stdasn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: value}
}

func onlyCACertificatesIDP(t *testing.T) cryptopkix.Extension {
	t.Helper()
	value := marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte{0xff})
		})
	})
	return cryptopkix.Extension{Id: stdasn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: value}
}

func onlyUserCertificatesIDP(t *testing.T) cryptopkix.Extension {
	t.Helper()
	value := marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte{0xff})
		})
	})
	return cryptopkix.Extension{
		Id: stdasn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: value,
	}
}

func issuingDistributionPointName(t *testing.T, rawName []byte) cryptopkix.Extension {
	t.Helper()
	value := marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(builder *cryptobyte.Builder) {
			builder.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.Tag(4).Constructed().ContextSpecific(), func(builder *cryptobyte.Builder) {
					builder.AddBytes(rawName)
				})
			})
		})
	})
	return cryptopkix.Extension{
		Id: stdasn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: value,
	}
}

func freshestCRLExtension(t *testing.T) cryptopkix.Extension {
	t.Helper()
	return cryptopkix.Extension{
		Id:    stdasn1.ObjectIdentifier{2, 5, 29, 46},
		Value: distributionPointsURI(t, "http://example.test/delta.crl"),
	}
}

func deltaCRLIndicator(t *testing.T, baseNumber int64) cryptopkix.Extension {
	t.Helper()
	var builder cryptobyte.Builder
	builder.AddASN1BigInt(big.NewInt(baseNumber))
	value, err := builder.Bytes()
	if err != nil {
		t.Fatalf("marshal delta indicator: %v", err)
	}
	return cryptopkix.Extension{
		Id: stdasn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: value,
	}
}

func distributionPointsURI(t *testing.T, uri string) []byte {
	t.Helper()
	return marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
			builder.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(builder *cryptobyte.Builder) {
					builder.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(builder *cryptobyte.Builder) {
						builder.AddBytes([]byte(uri))
					})
				})
			})
		})
	})
}

func distributionPointWithCRLIssuer(t *testing.T, rawIssuers ...[]byte) []byte {
	t.Helper()
	return marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
			builder.AddASN1(cryptobyte_asn1.Tag(2).Constructed().ContextSpecific(), func(builder *cryptobyte.Builder) {
				for _, rawIssuer := range rawIssuers {
					builder.AddASN1(cryptobyte_asn1.Tag(4).Constructed().ContextSpecific(), func(builder *cryptobyte.Builder) {
						builder.AddBytes(rawIssuer)
					})
				}
			})
		})
	})
}

func certificateIssuerExtension(t *testing.T, rawIssuer []byte) cryptopkix.Extension {
	t.Helper()
	value := marshalASN1(t, cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.Tag(4).Constructed().ContextSpecific(), func(builder *cryptobyte.Builder) {
			builder.AddBytes(rawIssuer)
		})
	})
	return cryptopkix.Extension{
		Id: stdasn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: value,
	}
}

func reasonFlagsContents(reasons ReasonSet) []byte {
	highest := 0
	for bit := 1; bit <= 8; bit++ {
		if reasons&(1<<bit) != 0 {
			highest = bit
		}
	}
	if highest == 0 {
		return []byte{0}
	}
	byteCount := (highest + 8) / 8
	unused := byteCount*8 - (highest + 1)
	result := make([]byte, byteCount+1)
	result[0] = byte(unused)
	for bit := 1; bit <= highest; bit++ {
		if reasons&(1<<bit) != 0 {
			result[1+bit/8] |= 1 << (7 - bit%8)
		}
	}
	return result
}

func marshalASN1(
	t *testing.T,
	tag cryptobyte_asn1.Tag,
	contents func(*cryptobyte.Builder),
) []byte {
	t.Helper()
	var builder cryptobyte.Builder
	builder.AddASN1(tag, contents)
	value, err := builder.Bytes()
	if err != nil {
		t.Fatalf("marshal ASN.1: %v", err)
	}
	return value
}

func makeCRLDelegate(
	t *testing.T,
	material revocationMaterial,
) (*cryptox509.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CRL delegate key: %v", err)
	}
	template := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(900),
		Subject:               cryptopkix.Name{CommonName: "Delegated CRL Issuer"},
		NotBefore:             material.now.Add(-24 * time.Hour),
		NotAfter:              material.now.Add(24 * time.Hour),
		KeyUsage:              cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x90, 0x01},
	}
	der, err := cryptox509.CreateCertificate(
		rand.Reader, template, material.issuerStd, &key.PublicKey, material.issuerKey,
	)
	if err != nil {
		t.Fatalf("create CRL delegate: %v", err)
	}
	standard, err := cryptox509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse standard CRL delegate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CRL delegate: %v", err)
	}
	if !bytes.Equal(standard.RawSubject, parsed.RawSubject) {
		t.Fatal("delegate parsers disagree on subject DER")
	}
	return standard, parsed, key
}
