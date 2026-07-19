package cert

import (
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestPathLenConstraintValidCountsNonSelfIssuedIntermediates(t *testing.T) {
	leaf := &Info{Cert: &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}}, Position: 0}
	intermediate := &Info{Cert: &x509.Certificate{
		Subject: pkix.Name{CommonName: "intermediate"},
		Issuer:  pkix.Name{CommonName: "root"},
	}, Position: 1}

	t.Run("root zero rejects one intermediate", func(t *testing.T) {
		root := constrainedCA(0, true)
		root.Position = 2
		chain := []*Info{leaf, intermediate, root}
		if PathLenConstraintValid(root, chain) {
			t.Fatal("root pathLenConstraint=0 accepted a non-self-issued intermediate")
		}
	})

	t.Run("root one accepts one intermediate", func(t *testing.T) {
		root := constrainedCA(1, false)
		root.Position = 2
		chain := []*Info{leaf, intermediate, root}
		if !PathLenConstraintValid(root, chain) {
			t.Fatal("root pathLenConstraint=1 rejected one non-self-issued intermediate")
		}
	})

	t.Run("self-issued intermediate is not counted", func(t *testing.T) {
		selfIssued := &Info{Cert: &x509.Certificate{
			Subject: pkix.Name{CommonName: "rollover"},
			Issuer:  pkix.Name{CommonName: "rollover"},
		}, Position: 1}
		root := constrainedCA(0, true)
		root.Position = 2
		chain := []*Info{leaf, selfIssued, root}
		if !PathLenConstraintValid(root, chain) {
			t.Fatal("self-issued intermediate consumed path length")
		}
	})

	t.Run("CA target at position zero is not an intermediate", func(t *testing.T) {
		target := &Info{Cert: &x509.Certificate{
			BasicConstraintsValid: true,
			IsCA:                  true,
			Subject:               pkix.Name{CommonName: "target CA"},
		}, Position: 0}
		root := constrainedCA(0, true)
		root.Position = 1
		if !PathLenConstraintValid(root, []*Info{target, root}) {
			t.Fatal("target certificate incorrectly consumed path length")
		}
	})
}

func TestPathLenConstraintValidBoundaries(t *testing.T) {
	certificate := &Info{Cert: &x509.Certificate{}, Position: 0}
	if PathLenConstraintValid(nil, []*Info{certificate}) {
		t.Fatal("nil current certificate passed")
	}
	if PathLenConstraintValid(certificate, nil) {
		t.Fatal("missing chain passed")
	}
	if !PathLenConstraintValid(certificate, []*Info{certificate}) {
		t.Fatal("certificate without a pathLenConstraint failed")
	}

	invalid := constrainedCA(0, true)
	invalid.Cert.Extensions = nil
	if PathLenConstraintValid(invalid, []*Info{invalid}) {
		t.Fatal("pathLenConstraint without Key Usage passed")
	}
}

func TestPathLenConstraintValidAcceptsStrictCounterBeyondNativeInt(t *testing.T) {
	large := []byte{0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		sequence.AddASN1Boolean(true)
		sequence.AddASN1(cryptobyte_asn1.INTEGER, func(integer *cryptobyte.Builder) {
			integer.AddBytes(large)
		})
	})
	basicConstraints := extensionForCertificateTest(oid.BasicConstraints)
	basicConstraints.Value = builder.BytesOrPanic()

	leaf := &Info{Cert: &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}}, Position: 0}
	intermediate := &Info{Cert: &x509.Certificate{
		Subject: pkix.Name{CommonName: "intermediate"},
		Issuer:  pkix.Name{CommonName: "root"},
	}, Position: 1}
	root := &Info{Cert: &x509.Certificate{
		Subject:  pkix.Name{CommonName: "root"},
		Issuer:   pkix.Name{CommonName: "root"},
		KeyUsage: x509.KeyUsageCertSign,
		Extensions: []pkix.Extension{
			basicConstraints,
			extensionForCertificateTest(oid.KeyUsage),
		},
	}, Position: 2}

	if !BasicConstraintsDependenciesValid(root.Cert) {
		t.Fatal("strict large pathLenConstraint dependencies failed")
	}
	if !KeyUsageDependenciesValid(root.Cert) {
		t.Fatal("strict large CA Basic Constraints did not authorize keyCertSign")
	}
	if got := GetCertType(root.Cert, 2, 3); got != "root" {
		t.Fatalf("GetCertType() = %q, want root for strict large CA Basic Constraints", got)
	}
	if !PathLenConstraintValid(root, []*Info{leaf, intermediate, root}) {
		t.Fatal("strict large pathLenConstraint rejected a finite chain")
	}
}

func constrainedCA(maxPathLen int, explicitZero bool) *Info {
	return &Info{Cert: &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        explicitZero,
		KeyUsage:              x509.KeyUsageCertSign,
		Extensions:            []pkix.Extension{extensionForCertificateTest(oid.KeyUsage)},
	}}
}
