package linter

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xocsp "golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/rule"
	"github.com/cavoq/PCL/internal/testpki"
)

// autoValidatePKI is a three-level PKI whose AIA, CRL and OCSP endpoints are
// served by a local HTTP server: the leaf names its issuer and an OCSP
// responder, the intermediate names the root and a root CRL.
type autoValidatePKI struct {
	root, intermediate, leaf *testpki.Certificate
	ocspRequests             atomic.Int32
	issuerRequests           atomic.Int32
	crlRequests              atomic.Int32
}

// responderDown makes the OCSP responder fail every request.
const responderDown = -1

func newAutoValidatePKI(t *testing.T, now time.Time, leafStatus int) *autoValidatePKI {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	pki := &autoValidatePKI{}
	pki.root = testpki.Issue(t, "Auto Root", nil, testpki.CA())
	pki.intermediate = testpki.Issue(t, "Auto Intermediate", pki.root, testpki.CA(), testpki.Serial(2),
		testpki.IssuingCertificateURLs(server.URL+"/root.cer"),
		testpki.Mutate(func(template *x509.Certificate) {
			template.CRLDistributionPoints = []string{server.URL + "/root.crl"}
		}))
	pki.leaf = testpki.Issue(t, "leaf.example", pki.intermediate, testpki.Serial(3),
		testpki.IssuingCertificateURLs(server.URL+"/intermediate.cer"),
		testpki.Mutate(func(template *x509.Certificate) {
			template.DNSNames = []string{"leaf.example"}
			template.OCSPServer = []string{server.URL + "/ocsp"}
		}))
	rootCRL := pki.root.RevocationList(t, &x509.RevocationList{
		ThisUpdate: now.Add(-24 * time.Hour),
		NextUpdate: now.Add(30 * 24 * time.Hour),
	})

	mux.HandleFunc("/root.cer", func(w http.ResponseWriter, _ *http.Request) {
		pki.issuerRequests.Add(1)
		_, _ = w.Write(pki.root.DER)
	})
	mux.HandleFunc("/intermediate.cer", func(w http.ResponseWriter, _ *http.Request) {
		pki.issuerRequests.Add(1)
		_, _ = w.Write(pki.intermediate.DER)
	})
	mux.HandleFunc("/root.crl", func(w http.ResponseWriter, _ *http.Request) {
		pki.crlRequests.Add(1)
		_, _ = w.Write(rootCRL)
	})
	// The responder answers the request PCL sent: it parses the CertID and
	// signs a response for that serial with the CertID's hash.
	mux.HandleFunc("/ocsp", func(w http.ResponseWriter, r *http.Request) {
		pki.ocspRequests.Add(1)
		if leafStatus == responderDown {
			http.Error(w, "responder down", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request, err := xocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		template := xocsp.Response{
			Status:       leafStatus,
			SerialNumber: request.SerialNumber,
			IssuerHash:   request.HashAlgorithm,
			ProducedAt:   now,
			ThisUpdate:   now.Add(-time.Hour),
			NextUpdate:   now.Add(time.Hour),
		}
		if leafStatus == xocsp.Revoked {
			template.RevokedAt = now.Add(-2 * time.Hour)
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(testpki.OCSPResponseDER(t, pki.intermediate, pki.intermediate, template))
	})
	return pki
}

const autoValidatePolicy = `id: auto-validate
version: "1"
rules:
  - id: path-valid
    when: {target: certificate.pathValidation, operator: present}
    target: certificate
    operator: pathValid
    severity: error
  - id: ocsp-valid
    target: certificate
    operator: ocspValid
    certType: [leaf]
    severity: error
  - id: not-revoked
    target: certificate
    operator: notRevokedByAvailableEvidence
    certType: [leaf, intermediate]
    severity: error
`

// A run given only the leaf and a trust anchor climbs to the root through
// CA Issuers URLs, fetches the root CRL and queries the OCSP responder, and
// decides path validity and revocation from that evidence.
func TestRunAutoValidateFetchesIssuersCRLsAndOCSP(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		status   int
		wantLeaf map[string]string
		wantWarn string
	}{
		{"good", xocsp.Good, map[string]string{
			"ocsp-valid": rule.VerdictPass, "not-revoked": rule.VerdictPass, "path-valid": rule.VerdictPass,
		}, ""},
		// A revoked leaf also invalidates the path under the default path
		// revocation mode, which uses the fetched OCSP evidence.
		{"revoked", xocsp.Revoked, map[string]string{
			"ocsp-valid": rule.VerdictPass, "not-revoked": rule.VerdictFail, "path-valid": rule.VerdictFail,
		}, ""},
		// Without a response the leaf's revocation is undecided, not failed.
		{"responder down", responderDown, map[string]string{
			"ocsp-valid": rule.VerdictInconclusive, "not-revoked": rule.VerdictInconclusive,
		}, "Warning: auto OCSP fetch failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pki := newAutoValidatePKI(t, now, test.status)
			dir := t.TempDir()
			policyPath := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(policyPath, []byte(autoValidatePolicy), 0o600); err != nil {
				t.Fatal(err)
			}

			var out, diagnostics bytes.Buffer
			err := Run(Config{
				PolicyPaths:      []string{policyPath},
				CertPath:         writePEMCert(t, dir, "leaf.pem", pki.leaf.DER),
				TrustAnchorPaths: []string{writePEMCert(t, dir, "root.pem", pki.root.DER)},
				AutoValidate:     true,
				ValidationTime:   now,
				CertTimeout:      5 * time.Second,
				OCSPTimeout:      5 * time.Second,
				OutputFmt:        output.FormatJSON,
				Verbosity:        2,
				ShowMeta:         true,
				Diagnostics:      &diagnostics,
			}, &out)
			if err != nil {
				t.Fatalf("Run: %v\n%s", err, diagnostics.String())
			}
			if pki.ocspRequests.Load() != 1 || pki.issuerRequests.Load() == 0 || pki.crlRequests.Load() == 0 {
				t.Fatalf("requests: OCSP %d, issuers %d, CRL %d", pki.ocspRequests.Load(), pki.issuerRequests.Load(), pki.crlRequests.Load())
			}
			if !strings.Contains(diagnostics.String(), "OCSP") || !strings.Contains(diagnostics.String(), test.wantWarn) {
				t.Errorf("-vv diagnostics lack the OCSP exchange or %q:\n%s", test.wantWarn, diagnostics.String())
			}

			var lint output.LintOutput
			if err := json.Unmarshal(out.Bytes(), &lint); err != nil {
				t.Fatalf("decode: %v\n%s", err, out.String())
			}
			if chain := lint.Meta.Chain; chain == nil || !chain.Anchored || len(chain.Certificates) != 3 {
				t.Fatalf("chain = %+v, want the climbed, anchored three-certificate path", chain)
			}
			verdicts := map[string]map[string]string{}
			for _, result := range lint.Results {
				verdicts[result.CertType] = map[string]string{}
				for _, ruleResult := range result.Results {
					verdicts[result.CertType][ruleResult.RuleID] = ruleResult.Verdict
				}
			}
			for certType, want := range map[string]map[string]string{
				"leaf":         test.wantLeaf,
				"intermediate": {"not-revoked": rule.VerdictPass},
			} {
				for ruleID, verdict := range want {
					if got := verdicts[certType][ruleID]; got != verdict {
						t.Errorf("%s %s = %q, want %q", certType, ruleID, got, verdict)
					}
				}
			}
		})
	}
}
