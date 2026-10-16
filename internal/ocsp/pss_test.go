package ocsp

import (
	"crypto"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/testpki"
)

// RSASSA-PSS responses: x/crypto/ocsp neither verifies them nor parses them
// when they embed the responder certificate.
func TestRSASSAPSSResponses(t *testing.T) {
	fixture := newEvidenceFixture(t, "pss", 7001)
	responder := testpki.Issue(t, "pss responder", fixture.ca, testpki.OCSPSigning(), testpki.Serial(7002),
		testpki.Validity(fixture.now.Add(-time.Hour), fixture.now.Add(time.Hour)),
		testpki.Mutate(func(template *stdx509.Certificate) { template.SignatureAlgorithm = stdx509.SHA256WithRSAPSS }))
	sha256Salt32 := testpki.PSS{Hash: crypto.SHA256, MGFHash: crypto.SHA256, SaltLength: 32}

	response := func(signer *testpki.Certificate, embedded *stdx509.Certificate, params testpki.PSS) []byte {
		der := testpki.OCSPResponseDER(t, fixture.ca, signer, xocsp.Response{
			Status:       xocsp.Good,
			SerialNumber: fixture.leaf.SerialNumber,
			ProducedAt:   fixture.now,
			ThisUpdate:   fixture.now.Add(-time.Hour),
			NextUpdate:   fixture.now.Add(time.Hour),
			Certificate:  embedded,
		})
		return testpki.SignOCSPWithPSS(t, der, signer.Key.(*rsa.PrivateKey), params)
	}
	tampered := func(der []byte) []byte {
		der = append([]byte(nil), der...)
		// The signature BIT STRING ends the response when no certificate is
		// embedded.
		der[len(der)-1] ^= 0xff
		return der
	}

	tests := []struct {
		name      string
		der       []byte
		wantValid bool
	}{
		{"issuer signed, SHA-256", response(fixture.ca, nil, sha256Salt32), true},
		{"salt length differs from the hash length", response(fixture.ca, nil, testpki.PSS{Hash: crypto.SHA512, MGFHash: crypto.SHA512, SaltLength: 20}), true},
		{"delegated responder embedded", response(responder, responder.Std, sha256Salt32), true},
		{"tampered signature", tampered(response(fixture.ca, nil, sha256Salt32)), false},
		{"MGF1 hash differs from the message hash", response(fixture.ca, nil, testpki.PSS{Hash: crypto.SHA256, MGFHash: crypto.SHA1, SaltLength: 32}), false},
		{"SHA-1", response(fixture.ca, nil, testpki.PSS{Hash: crypto.SHA1, MGFHash: crypto.SHA1, SaltLength: 20}), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := ParseResponse(test.der)
			if err != nil {
				t.Fatalf("ParseResponse: %v", err)
			}
			if string(parsed.Raw) != string(test.der) {
				t.Error("Raw is not the parsed DER")
			}
			assessment := AssessCertificate(fixture.leaf, []*Info{{Response: parsed}}, []*x509.Certificate{fixture.issuer}, fixture.now)
			if got := assessment.Valid(); got != test.wantValid {
				t.Fatalf("Valid = %v, want %v (evidence %+v)", got, test.wantValid, assessment.Evidence)
			}
		})
	}
}

func TestParseResponseKeepsTheEmbeddedPSSResponder(t *testing.T) {
	fixture := newEvidenceFixture(t, "pss embedded", 7101)
	responder := testpki.Issue(t, "pss embedded responder", fixture.ca, testpki.OCSPSigning(), testpki.Serial(7102))
	der := testpki.SignOCSPWithPSS(t, testpki.OCSPResponseDER(t, fixture.ca, responder, xocsp.Response{
		Status:       xocsp.Good,
		SerialNumber: fixture.leaf.SerialNumber,
		ThisUpdate:   fixture.now,
		Certificate:  responder.Std,
	}), responder.Key.(*rsa.PrivateKey), testpki.PSS{Hash: crypto.SHA256, MGFHash: crypto.SHA256, SaltLength: 32})

	if _, err := xocsp.ParseResponse(der, nil); err == nil {
		t.Fatal("x/crypto/ocsp parsed the response; the workaround may be obsolete")
	}
	parsed, err := ParseResponse(der)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if parsed.Certificate == nil || !parsed.Certificate.Equal(responder.Std) {
		t.Fatalf("Certificate = %v, want the embedded responder", parsed.Certificate)
	}
	if parsed.SerialNumber.Cmp(fixture.leaf.SerialNumber) != 0 || parsed.Status != xocsp.Good {
		t.Fatalf("parsed serial %v status %d", parsed.SerialNumber, parsed.Status)
	}
	if name := SignatureAlgorithmName(parsed); name != "SHA256-RSAPSS" {
		t.Errorf("SignatureAlgorithmName = %q, want SHA256-RSAPSS", name)
	}
}

func TestParseResponseKeepsOtherParseErrors(t *testing.T) {
	if _, err := ParseResponse([]byte{0x30, 0x03, 0x0a, 0x01, 0x00}); err == nil {
		t.Fatal("ParseResponse accepted a truncated response")
	}
}
