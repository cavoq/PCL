package ocsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	xocsp "golang.org/x/crypto/ocsp"
)

type evidenceFixture struct {
	now       time.Time
	leaf      *x509.Certificate
	issuer    *x509.Certificate
	leafStd   *stdx509.Certificate
	issuerStd *stdx509.Certificate
	issuerKey *rsa.PrivateKey
}

func newEvidenceFixture(t *testing.T, name string, leafSerial int64) evidenceFixture {
	t.Helper()

	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	issuerTemplate := &stdx509.Certificate{
		SerialNumber:          big.NewInt(leafSerial + 1000),
		Subject:               pkix.Name{CommonName: name + " issuer"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              stdx509.KeyUsageCertSign | stdx509.KeyUsageDigitalSignature,
	}
	issuerDER, err := stdx509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	issuerStd, err := stdx509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &stdx509.Certificate{
		SerialNumber: big.NewInt(leafSerial),
		Subject:      pkix.Name{CommonName: name + " leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     stdx509.KeyUsageDigitalSignature,
	}
	leafDER, err := stdx509.CreateCertificate(rand.Reader, leafTemplate, issuerStd, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafStd, err := stdx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse zcrypto issuer: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse zcrypto leaf: %v", err)
	}

	return evidenceFixture{
		now:       now,
		leaf:      leaf,
		issuer:    issuer,
		leafStd:   leafStd,
		issuerStd: issuerStd,
		issuerKey: issuerKey,
	}
}

func (fixture evidenceFixture) response(
	t *testing.T,
	status int,
	serial *big.Int,
	thisUpdate time.Time,
	nextUpdate time.Time,
	responseIssuer *stdx509.Certificate,
	signer crypto.Signer,
) *Info {
	t.Helper()
	if serial == nil {
		serial = fixture.leafStd.SerialNumber
	}
	if responseIssuer == nil {
		responseIssuer = fixture.issuerStd
	}
	if signer == nil {
		signer = fixture.issuerKey
	}

	raw, err := xocsp.CreateResponse(responseIssuer, responseIssuer, xocsp.Response{
		Status:       status,
		SerialNumber: serial,
		ProducedAt:   fixture.now,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	}, signer)
	if err != nil {
		t.Fatalf("create OCSP response: %v", err)
	}
	response, err := xocsp.ParseResponse(raw, nil)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	return &Info{Response: response}
}

func TestAssessResponse(t *testing.T) {
	fixture := newEvidenceFixture(t, "primary", 42)
	other := newEvidenceFixture(t, "other", 42)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	currentGood := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil, nil)
	currentRevoked := fixture.response(t, xocsp.Revoked, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil, nil)
	currentUnknown := fixture.response(t, xocsp.Unknown, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil, nil)
	differentSerial := fixture.response(t, xocsp.Good, big.NewInt(99), fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil, nil)
	issuerMismatch := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), other.issuerStd, other.issuerKey)
	stale := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour), nil, nil)
	badSignature := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil, wrongKey)

	tests := []struct {
		name           string
		info           *Info
		wantStatus     Status
		wantApplicable bool
		wantCurrent    bool
		wantIssuer     bool
		wantSignature  bool
		wantValid      bool
	}{
		{name: "absent", wantStatus: StatusNotApplicable},
		{name: "good", info: currentGood, wantStatus: StatusGood, wantApplicable: true, wantCurrent: true, wantIssuer: true, wantSignature: true, wantValid: true},
		{name: "revoked", info: currentRevoked, wantStatus: StatusRevoked, wantApplicable: true, wantCurrent: true, wantIssuer: true, wantSignature: true, wantValid: true},
		{name: "unknown", info: currentUnknown, wantStatus: StatusUnknown, wantApplicable: true, wantCurrent: true, wantIssuer: true, wantSignature: true, wantValid: true},
		{name: "different serial", info: differentSerial, wantStatus: StatusNotApplicable},
		{name: "issuer mismatch", info: issuerMismatch, wantStatus: StatusNotApplicable},
		{name: "stale", info: stale, wantStatus: StatusUnknown, wantApplicable: true, wantIssuer: true, wantSignature: true},
		{name: "bad signature", info: badSignature, wantStatus: StatusUnknown, wantApplicable: true, wantCurrent: true, wantIssuer: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := assessResponse(fixture.leaf, test.info, []*x509.Certificate{fixture.issuer}, fixture.now)
			if evidence.Status != test.wantStatus {
				t.Fatalf("status = %v, want %v", evidence.Status, test.wantStatus)
			}
			if evidence.Applicable != test.wantApplicable || evidence.Current != test.wantCurrent ||
				evidence.IssuerMatched != test.wantIssuer || evidence.SignatureValid != test.wantSignature {
				t.Fatalf("unexpected evidence: %+v", evidence)
			}
			if evidence.Valid() != test.wantValid {
				t.Fatalf("valid = %v, want %v", evidence.Valid(), test.wantValid)
			}
		})
	}
}

func TestAssessmentAggregatesAcceptedEvidence(t *testing.T) {
	fixture := newEvidenceFixture(t, "aggregate", 7)
	good := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil, nil)
	revoked := fixture.response(t, xocsp.Revoked, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil, nil)
	stale := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour), nil, nil)

	tests := []struct {
		name       string
		responses  []*Info
		wantStatus Status
		wantValid  bool
		wantGood   bool
	}{
		{name: "absent", wantStatus: StatusNotApplicable},
		{name: "stale only", responses: []*Info{stale}, wantStatus: StatusUnknown},
		{name: "good", responses: []*Info{good}, wantStatus: StatusGood, wantValid: true, wantGood: true},
		{name: "revoked wins but good is retained", responses: []*Info{good, revoked}, wantStatus: StatusRevoked, wantValid: true, wantGood: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assessment := AssessCertificate(fixture.leaf, test.responses, []*x509.Certificate{fixture.issuer}, fixture.now)
			if assessment.Status() != test.wantStatus {
				t.Fatalf("status = %v, want %v", assessment.Status(), test.wantStatus)
			}
			if assessment.Valid() != test.wantValid {
				t.Fatalf("valid = %v, want %v", assessment.Valid(), test.wantValid)
			}
			if assessment.HasGood() != test.wantGood {
				t.Fatalf("has good = %v, want %v", assessment.HasGood(), test.wantGood)
			}
		})
	}
}
