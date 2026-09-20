package crl

import (
	"crypto/rsa"
	"math/big"
	"testing"

	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

func TestSameSignerPublicKeyUsesSyntheticKeyEncoding(t *testing.T) {
	first := prepareSignerPool([]*x509.Certificate{{
		PublicKey: &rsa.PublicKey{N: big.NewInt(65537), E: 3},
	}})
	equivalent := prepareSignerPool([]*x509.Certificate{{
		PublicKey: &rsa.PublicKey{N: big.NewInt(65537), E: 3},
	}})
	different := prepareSignerPool([]*x509.Certificate{{
		PublicKey: &rsa.PublicKey{N: big.NewInt(65539), E: 3},
	}})
	unknown := prepareSignerPool([]*x509.Certificate{{}})

	if !sameSignerPublicKey(&first[0], &equivalent[0]) {
		t.Fatal("equivalent synthetic public keys did not match")
	}
	if sameSignerPublicKey(&first[0], &different[0]) {
		t.Fatal("different synthetic public keys matched")
	}
	if sameSignerPublicKey(&unknown[0], &unknown[0]) {
		t.Fatal("two unavailable public-key encodings must not match")
	}
}

func TestSignerRejectionPreservesKeyUsagePrecedence(t *testing.T) {
	material := makeRevocationMaterial(t)
	badUsage := *material.issuer
	badUsage.KeyUsage &^= x509.KeyUsageCRLSign

	assessment := NewCatalog(
		[]*x509.RevocationList{material.clean},
		RevocationContext{
			Now:     material.now,
			Issuers: []*x509.Certificate{&badUsage, material.issuer},
			AuthorizeSigner: SignerAuthorizerFunc(func(
				_, _ *x509.Certificate,
				_ *x509.RevocationList,
			) bool {
				return false
			}),
		},
	).AssessCertificate(material.leaf)

	if assessment.Status() != RevocationUnknown || len(assessment.Evidence) != 1 ||
		assessment.Evidence[0].Rejection != EvidenceSignerKeyUsage {
		t.Fatalf("assessment = status %v, evidence %#v", assessment.Status(), assessment.Evidence)
	}
}

func TestAuthorityKeyIdentifierMatchesIssuerAndSerial(t *testing.T) {
	issuer := []byte{0x30, 0x03, 0x31, 0x01, 0x00}
	serial := x509ext.NonNegativeInteger{Content: []byte{0x00, 0x00, 0x07}}
	identifier := &crlzcrypto.AuthorityKeyIdentifierFacts{
		SerialNumber: &serial,
		AuthorityIssuer: []x509ext.GeneralName{{
			Tag: 4, RawValue: issuer,
		}},
	}
	candidate := &x509.Certificate{
		RawIssuer:    append([]byte(nil), issuer...),
		SerialNumber: big.NewInt(7),
	}

	if !authorityKeyIdentifierMatches(candidate, identifier) {
		t.Fatal("equivalent issuer and zero-padded serial did not match")
	}
	wrongIssuer := *candidate
	wrongIssuer.RawIssuer = []byte{0x30, 0x00}
	if authorityKeyIdentifierMatches(&wrongIssuer, identifier) {
		t.Fatal("different authority issuer matched")
	}
	wrongSerial := *candidate
	wrongSerial.SerialNumber = big.NewInt(8)
	if authorityKeyIdentifierMatches(&wrongSerial, identifier) {
		t.Fatal("different authority serial matched")
	}
}
