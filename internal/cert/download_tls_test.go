package cert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/testpki"
)

// serveTLS starts a TLS server presenting leaf and its issuing intermediate
// and returns its https URL.
func serveTLS(t *testing.T, leaf, intermediate *testpki.Certificate) string {
	t.Helper()
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{leaf.DER, intermediate.DER},
		PrivateKey:  leaf.Key,
	}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// The chain of a server PCL does not trust is still acquired; trust is a
// path validation decision, not an acquisition one.
func TestDownloadAndLoadCertificatesFetchesUntrustedChains(t *testing.T) {
	root := testpki.Issue(t, "Untrusted Root", nil, testpki.CA())
	intermediate := testpki.Issue(t, "Untrusted Intermediate", root, testpki.CA(), testpki.Serial(2))
	ip := testpki.Mutate(func(template *x509.Certificate) { template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)} })
	tests := map[string]*testpki.Certificate{
		"untrusted root": testpki.Issue(t, "127.0.0.1", intermediate, testpki.Serial(3), ip),
		"expired": testpki.Issue(t, "127.0.0.1", intermediate, testpki.Serial(4), ip,
			testpki.Validity(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))),
		"wrong name": testpki.Issue(t, "other.example", intermediate, testpki.Serial(5),
			testpki.Mutate(func(template *x509.Certificate) { template.DNSNames = []string{"other.example"} })),
	}
	for name, leaf := range tests {
		t.Run(name, func(t *testing.T) {
			url := serveTLS(t, leaf, intermediate)
			infos, cleanup, err := DownloadAndLoadCertificates([]string{url}, 5*time.Second, "")
			if cleanup != nil {
				t.Cleanup(cleanup)
			}
			if err != nil {
				t.Fatalf("DownloadAndLoadCertificates: %v", err)
			}
			if len(infos) != 2 || !bytes.Equal(infos[0].Cert.Raw, leaf.DER) || !bytes.Equal(infos[1].Cert.Raw, intermediate.DER) {
				t.Fatalf("loaded %d certificates, want the presented leaf and intermediate", len(infos))
			}
			if infos[0].Source.URL != url {
				t.Errorf("source URL = %q, want %q", infos[0].Source.URL, url)
			}
		})
	}
}

func TestFetchTLSChainReportsConnectionFailures(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	_ = listener.Close()
	if _, err := fetchTLSChain(host, port, time.Second); err == nil {
		t.Fatal("fetchTLSChain succeeded without a server")
	}
	if _, err := fetchTLSChain("", "443", time.Second); err == nil {
		t.Fatal("fetchTLSChain accepted an empty host")
	}
}
