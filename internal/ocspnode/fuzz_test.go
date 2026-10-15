package ocspnode

import (
	"testing"

	"golang.org/x/crypto/ocsp"

	pclocsp "github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/testpki"
)

// FuzzParseResponse runs the raw OCSP decoders on any input and projects
// every response golang.org/x/crypto/ocsp accepts.
func FuzzParseResponse(f *testing.F) {
	for _, seed := range testpki.SeedFiles(f, "tests/ocsps/*.ocsp", "tests/ocsps/*/*.ocsp") {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = pclocsp.ParseNonceFromRaw(raw)
		_, _ = pclocsp.ParseCertID(raw)
		_ = pclocsp.ParseOCSPSignatureAlgorithmParams(raw)

		response, err := ocsp.ParseResponse(raw, nil)
		if err != nil {
			return
		}
		if BuildTree(response) == nil {
			t.Fatal("BuildTree returned no tree")
		}
	})
}
