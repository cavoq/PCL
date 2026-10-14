package ocsp

import (
	stdx509 "crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/testpki"
	"github.com/zmap/zcrypto/x509"
	xocsp "golang.org/x/crypto/ocsp"
)

type evidenceFixture struct {
	now    time.Time
	ca     *testpki.Certificate
	issuer *x509.Certificate
	leaf   *x509.Certificate
}

func newEvidenceFixture(t *testing.T, name string, leafSerial int64) evidenceFixture {
	t.Helper()
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	ca := testpki.Issue(t, name+" issuer", nil, testpki.CA(), testpki.Serial(leafSerial+1000),
		testpki.Validity(now.Add(-24*time.Hour), now.Add(24*time.Hour)),
		testpki.Mutate(func(template *stdx509.Certificate) {
			template.KeyUsage = stdx509.KeyUsageCertSign | stdx509.KeyUsageDigitalSignature
		}))
	leaf := testpki.Issue(t, name+" leaf", ca, testpki.Serial(leafSerial),
		testpki.Validity(now.Add(-time.Hour), now.Add(time.Hour)),
		testpki.Mutate(func(template *stdx509.Certificate) { template.KeyUsage = stdx509.KeyUsageDigitalSignature }))
	return evidenceFixture{now: now, ca: ca, issuer: ca.Cert, leaf: leaf.Cert}
}

// response is a response about the fixture leaf, or about serial when set,
// signed by responder, or by the fixture CA when responder is nil.
func (fixture evidenceFixture) response(
	t *testing.T,
	status int,
	serial *big.Int,
	thisUpdate time.Time,
	nextUpdate time.Time,
	responder *testpki.Certificate,
) *Info {
	t.Helper()
	if serial == nil {
		serial = fixture.leaf.SerialNumber
	}
	if responder == nil {
		responder = fixture.ca
	}
	return &Info{Response: testpki.OCSPResponse(t, responder, responder, xocsp.Response{
		Status:       status,
		SerialNumber: serial,
		ProducedAt:   fixture.now,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	})}
}

func TestAssessResponse(t *testing.T) {
	fixture := newEvidenceFixture(t, "primary", 42)
	other := newEvidenceFixture(t, "other", 42)
	wrongSigner := &testpki.Certificate{Std: fixture.ca.Std, Key: testpki.RSAKey(t)}

	currentGood := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil)
	currentRevoked := fixture.response(t, xocsp.Revoked, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil)
	currentUnknown := fixture.response(t, xocsp.Unknown, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil)
	differentSerial := fixture.response(t, xocsp.Good, big.NewInt(99), fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil)
	issuerMismatch := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), other.ca)
	stale := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour), nil)
	badSignature := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), wrongSigner)

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
	good := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil)
	revoked := fixture.response(t, xocsp.Revoked, nil, fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour), nil)
	stale := fixture.response(t, xocsp.Good, nil, fixture.now.Add(-2*time.Hour), fixture.now.Add(-time.Hour), nil)

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
