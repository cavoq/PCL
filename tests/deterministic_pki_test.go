package tests

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/oid"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestDeterministicApplicationPurposeVectors(t *testing.T) {
	leaf := &cert.Info{
		Type: "leaf",
		Cert: &x509.Certificate{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			Extensions: []pkix.Extension{
				{Id: zasn1.ObjectIdentifier{2, 5, 29, 15}},
				{
					Id: zasn1.ObjectIdentifier{2, 5, 29, 37},
					Value: []byte{
						0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
						0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
					},
				},
			},
		},
	}

	vectors := []struct {
		purpose string
		want    bool
	}{
		{purpose: "serverAuth", want: true},
		{purpose: oid.ServerAuth, want: true},
		{purpose: "clientAuth", want: false},
		{purpose: "1.2.3.4", want: false},
		{purpose: "not-an-oid", want: false},
	}

	for _, vector := range vectors {
		t.Run(vector.purpose, func(t *testing.T) {
			if got := cert.ApplicationPurposeValid(leaf, vector.purpose); got != vector.want {
				t.Fatalf("ApplicationPurposeValid(%q) = %v, want %v", vector.purpose, got, vector.want)
			}
		})
	}
}

func TestDeterministicPathLengthVectors(t *testing.T) {
	leaf := &cert.Info{
		Position: 0,
		Type:     "leaf",
		Cert: &x509.Certificate{
			Subject: pkix.Name{CommonName: "Leaf"},
			Issuer:  pkix.Name{CommonName: "Intermediate"},
		},
	}
	intermediate := &cert.Info{
		Position: 1,
		Type:     "intermediate",
		Cert: &x509.Certificate{
			Subject:               pkix.Name{CommonName: "Intermediate"},
			Issuer:                pkix.Name{CommonName: "Root"},
			BasicConstraintsValid: true,
			IsCA:                  true,
		},
	}
	root := &cert.Info{
		Position: 2,
		Type:     "root",
		Cert: &x509.Certificate{
			Subject:               pkix.Name{CommonName: "Root"},
			Issuer:                pkix.Name{CommonName: "Root"},
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			KeyUsage:              x509.KeyUsageCertSign,
			Extensions: []pkix.Extension{{
				Id: zasn1.ObjectIdentifier{2, 5, 29, 15},
			}},
		},
	}

	chain := []*cert.Info{leaf, intermediate, root}
	if cert.PathLenConstraintValid(root, chain) {
		t.Fatal("pathLenConstraint=0 accepted a non-self-issued intermediate")
	}

	intermediate.Cert.Issuer = intermediate.Cert.Subject
	if !cert.PathLenConstraintValid(root, chain) {
		t.Fatal("self-issued intermediate incorrectly consumed pathLenConstraint")
	}
}
