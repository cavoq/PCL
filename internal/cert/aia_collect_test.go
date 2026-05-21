package cert

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestCollectViaCAIssuers_noFetchWhenDisabled(t *testing.T) {
	seed := []*x509.Certificate{{
		Subject:      pkix.Name{CommonName: "Leaf"},
		SerialNumber: big.NewInt(1),
	}}
	got := CollectViaCAIssuers(seed, AIACollectConfig{})
	if len(got) != 1 || got[0] != seed[0] {
		t.Fatalf("CollectViaCAIssuers() = %v, want seed only", got)
	}
}

func TestFetchParentViaCAIssuers_noAIA(t *testing.T) {
	child := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Leaf"},
		SerialNumber: big.NewInt(1),
	}
	cert, info, url, err := FetchParentViaCAIssuers(child, time.Second, nil)
	if err != nil || cert != nil || url != "" || info.Type != "" {
		t.Fatalf("FetchParentViaCAIssuers() = (%v, %v, %q, %v), want nil,nil,\"\",nil", cert, info, url, err)
	}
}

func TestAppendUniqueCandidates_stopWhen(t *testing.T) {
	target := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Target"},
		SerialNumber: big.NewInt(42),
	}
	other := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Other"},
		SerialNumber: big.NewInt(43),
	}
	seen := map[string]bool{"1": true}

	added, stop := appendUniqueCandidates(seen, nil, []*x509.Certificate{
		{SerialNumber: big.NewInt(1)},
		target,
		other,
	}, func(c *x509.Certificate) bool {
		return c == target
	})
	if !stop || len(added) != 1 || added[0] != target {
		t.Fatalf("appendUniqueCandidates() = (%v, %v), want ([target], true)", added, stop)
	}
	if !seen["42"] || seen["43"] {
		t.Fatalf("seen after stop = %v, want only target serial recorded", seen)
	}
}

func TestMarkSerialSeen(t *testing.T) {
	seen := map[string]bool{}
	cert := &x509.Certificate{SerialNumber: big.NewInt(7)}
	if markSerialSeen(seen, cert) {
		t.Fatal("first mark should not be duplicate")
	}
	if !markSerialSeen(seen, cert) {
		t.Fatal("second mark should be duplicate")
	}
}

func TestWarnPEMDownload(t *testing.T) {
	var buf bytes.Buffer
	warnPEMDownload(&buf, "https://example.com/ca.cer", source.FormatPEM)
	if buf.Len() == 0 {
		t.Fatal("expected PEM warning")
	}
}
