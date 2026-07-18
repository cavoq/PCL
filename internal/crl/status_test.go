package crl

import (
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/oid"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

type revocationMaterial struct {
	now       time.Time
	issuer    *x509.Certificate
	issuerStd *cryptox509.Certificate
	issuerKey *rsa.PrivateKey
	leaf      *x509.Certificate
	clean     *x509.RevocationList
	revoked   *x509.RevocationList
}

func makeRevocationMaterial(t *testing.T) revocationMaterial {
	t.Helper()
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	issuerTemplate := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "Status Test CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x10, 0x20, 0x30},
	}
	issuerDER, err := cryptox509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	issuerStd, err := cryptox509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse standard issuer: %v", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &cryptox509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      cryptopkix.Name{CommonName: "Status Test Leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}
	leafDER, err := cryptox509.CreateCertificate(rand.Reader, leafTemplate, issuerStd, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	material := revocationMaterial{
		now:       now,
		issuer:    issuer,
		issuerStd: issuerStd,
		issuerKey: issuerKey,
		leaf:      leaf,
	}
	material.clean = makeSignedStatusCRL(t, material, nil, nil)
	material.revoked = makeSignedStatusCRL(t, material, []cryptox509.RevocationListEntry{{
		SerialNumber:   leafTemplate.SerialNumber,
		RevocationTime: now.Add(-30 * time.Minute),
	}}, nil)
	return material
}

func makeSignedStatusCRL(
	t *testing.T,
	material revocationMaterial,
	entries []cryptox509.RevocationListEntry,
	extraExtensions []cryptopkix.Extension,
) *x509.RevocationList {
	t.Helper()
	der, err := cryptox509.CreateRevocationList(rand.Reader, &cryptox509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(1),
		ThisUpdate:                material.now.Add(-time.Hour),
		NextUpdate:                material.now.Add(24 * time.Hour),
		ExtraExtensions:           extraExtensions,
	}, material.issuerStd, material.issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	list, err := ParseCRL(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	return list
}

func TestStatusForCertificateRequiresAcceptedCRL(t *testing.T) {
	material := makeRevocationMaterial(t)
	validContext := RevocationContext{Now: material.now, Issuers: []*x509.Certificate{material.issuer}}

	forged := *material.clean
	forged.Signature = append([]byte(nil), material.clean.Signature...)
	forged.Signature[0] ^= 0xff

	expired := *material.clean
	expired.ThisUpdate = material.now.Add(-48 * time.Hour)
	expired.NextUpdate = material.now.Add(-24 * time.Hour)

	delta := *material.clean
	delta.Extensions = append(append([]pkix.Extension(nil), material.clean.Extensions...), pkix.Extension{
		Id: zasn1.ObjectIdentifier{2, 5, 29, 27},
	})

	scoped := *material.clean
	scoped.Extensions = append(append([]pkix.Extension(nil), material.clean.Extensions...), pkix.Extension{
		Id: zasn1.ObjectIdentifier{2, 5, 29, 28},
	})

	unrelated := *material.clean
	unrelated.Issuer = pkix.Name{CommonName: "Other CA"}
	unrelated.RawIssuer = nil

	unknownCritical := makeSignedStatusCRL(t, material, nil, []cryptopkix.Extension{{
		Id:       stdasn1.ObjectIdentifier{1, 2, 3, 4},
		Critical: true,
		Value:    []byte{0x05, 0x00},
	}})
	unknownNonCritical := makeSignedStatusCRL(t, material, nil, []cryptopkix.Extension{{
		Id:    stdasn1.ObjectIdentifier{1, 2, 3, 4},
		Value: []byte{0x05, 0x00},
	}})

	tests := []struct {
		name    string
		cert    *x509.Certificate
		lists   []*x509.RevocationList
		context RevocationContext
		want    RevocationStatus
	}{
		{name: "missing certificate", lists: []*x509.RevocationList{material.clean}, context: validContext, want: RevocationUnknown},
		{name: "no CRLs", cert: material.leaf, context: validContext, want: RevocationUnknown},
		{name: "no issuer proof", cert: material.leaf, lists: []*x509.RevocationList{material.clean}, context: RevocationContext{Now: material.now}, want: RevocationUnknown},
		{name: "only unrelated CRL", cert: material.leaf, lists: []*x509.RevocationList{&unrelated}, context: validContext, want: RevocationUnknown},
		{name: "forged clean CRL", cert: material.leaf, lists: []*x509.RevocationList{&forged}, context: validContext, want: RevocationUnknown},
		{name: "expired clean CRL", cert: material.leaf, lists: []*x509.RevocationList{&expired}, context: validContext, want: RevocationUnknown},
		{name: "delta CRL needs base processing", cert: material.leaf, lists: []*x509.RevocationList{&delta}, context: validContext, want: RevocationUnknown},
		{name: "IDP CRL needs scope processing", cert: material.leaf, lists: []*x509.RevocationList{&scoped}, context: validContext, want: RevocationUnknown},
		{name: "unknown critical extension is unsupported", cert: material.leaf, lists: []*x509.RevocationList{unknownCritical}, context: validContext, want: RevocationUnknown},
		{name: "unknown non-critical extension can be ignored", cert: material.leaf, lists: []*x509.RevocationList{unknownNonCritical}, context: validContext, want: RevocationGood},
		{name: "accepted clean CRL", cert: material.leaf, lists: []*x509.RevocationList{material.clean}, context: validContext, want: RevocationGood},
		{name: "accepted revoked CRL", cert: material.leaf, lists: []*x509.RevocationList{material.revoked}, context: validContext, want: RevocationRevoked},
		{name: "revoked wins", cert: material.leaf, lists: []*x509.RevocationList{material.clean, material.revoked}, context: validContext, want: RevocationRevoked},
		{name: "nil entries ignored", cert: material.leaf, lists: []*x509.RevocationList{nil, material.clean}, context: validContext, want: RevocationGood},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StatusForCertificate(tt.cert, tt.lists, tt.context); got != tt.want {
				t.Fatalf("StatusForCertificate = %v, want %v (IDP OID %s)", got, tt.want, oid.IssuingDistributionPoint)
			}
		})
	}
}

func TestIsCurrentAtInclusiveBoundaries(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	list := &x509.RevocationList{ThisUpdate: start, NextUpdate: start.Add(time.Hour)}
	if !IsCurrentAt(list, start) || !IsCurrentAt(list, list.NextUpdate) {
		t.Fatal("CRL time window must include both boundary instants")
	}
	if IsCurrentAt(&x509.RevocationList{ThisUpdate: start}, start) {
		t.Fatal("CRL without nextUpdate is not RFC 5280 current")
	}
}
