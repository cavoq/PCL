package cert

import (
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestCertificateSetUsesExactRawCertificateIdentity(t *testing.T) {
	encoded := &x509.Certificate{
		Raw:                     []byte{0x30, 0x01, 0x01},
		RawSubjectPublicKeyInfo: []byte{0x30, 0x00},
		Issuer:                  pkix.Name{CommonName: "Issuer A"},
		SerialNumber:            big.NewInt(1),
	}
	sameEncoding := &x509.Certificate{
		Raw:                     append([]byte(nil), encoded.Raw...),
		RawSubjectPublicKeyInfo: []byte{0x30, 0x01},
		Issuer:                  pkix.Name{CommonName: "Issuer B"},
		SerialNumber:            big.NewInt(2),
	}
	differentEncoding := &x509.Certificate{
		Raw:                     []byte{0x30, 0x01, 0x02},
		RawSubjectPublicKeyInfo: append([]byte(nil), encoded.RawSubjectPublicKeyInfo...),
		Issuer:                  encoded.Issuer,
		SerialNumber:            new(big.Int).Set(encoded.SerialNumber),
	}

	set := NewCertificateSet()
	if !set.Add(encoded) {
		t.Fatal("first encoded certificate should be new")
	}
	if set.Add(sameEncoding) {
		t.Fatal("identical Raw DER should be deduplicated")
	}
	if !set.Add(differentEncoding) {
		t.Fatal("different Raw DER should remain distinct")
	}
	if !SameCertificate(encoded, sameEncoding) {
		t.Fatal("SameCertificate should compare encoded certificates by Raw DER")
	}
}

func TestCertificateSetSyntheticIdentityIsIssuerAndKeySafe(t *testing.T) {
	base := &x509.Certificate{
		Issuer:                  pkix.Name{CommonName: "Issuer A"},
		SerialNumber:            big.NewInt(7),
		RawSubjectPublicKeyInfo: []byte{0x30, 0x01},
	}
	sameIdentity := &x509.Certificate{
		Issuer:                  base.Issuer,
		SerialNumber:            new(big.Int).Set(base.SerialNumber),
		RawSubjectPublicKeyInfo: append([]byte(nil), base.RawSubjectPublicKeyInfo...),
	}
	differentIssuer := &x509.Certificate{
		Issuer:                  pkix.Name{CommonName: "Issuer B"},
		SerialNumber:            new(big.Int).Set(base.SerialNumber),
		RawSubjectPublicKeyInfo: append([]byte(nil), base.RawSubjectPublicKeyInfo...),
	}
	differentKey := &x509.Certificate{
		Issuer:                  base.Issuer,
		SerialNumber:            new(big.Int).Set(base.SerialNumber),
		RawSubjectPublicKeyInfo: []byte{0x30, 0x02},
	}

	set := NewCertificateSet(base)
	if set.Add(sameIdentity) {
		t.Fatal("same synthetic issuer, serial, and SPKI should be deduplicated")
	}
	if !set.Add(differentIssuer) {
		t.Fatal("same serial from a different issuer should remain distinct")
	}
	if !set.Add(differentKey) {
		t.Fatal("same issuer and serial with a different SPKI should remain distinct")
	}
	if !SameCertificate(base, sameIdentity) {
		t.Fatal("SameCertificate should use the synthetic identity fallback")
	}
}

func TestCertificateSetSyntheticIdentityMarshalsPublicKey(t *testing.T) {
	first := &x509.Certificate{
		Issuer:       pkix.Name{CommonName: "Issuer"},
		SerialNumber: big.NewInt(9),
		PublicKey:    &rsa.PublicKey{N: big.NewInt(65537), E: 3},
	}
	duplicate := &x509.Certificate{
		Issuer:       first.Issuer,
		SerialNumber: new(big.Int).Set(first.SerialNumber),
		PublicKey:    &rsa.PublicKey{N: big.NewInt(65537), E: 3},
	}

	set := NewCertificateSet(first)
	if set.Add(duplicate) {
		t.Fatal("equivalent public keys should produce the same synthetic identity")
	}
}

func TestCertificateSetSyntheticSerialPreservesSign(t *testing.T) {
	positive := &x509.Certificate{
		Issuer:                  pkix.Name{CommonName: "Issuer"},
		SerialNumber:            big.NewInt(7),
		RawSubjectPublicKeyInfo: []byte{0x30, 0x01},
	}
	negative := &x509.Certificate{
		Issuer:                  positive.Issuer,
		SerialNumber:            big.NewInt(-7),
		RawSubjectPublicKeyInfo: append([]byte(nil), positive.RawSubjectPublicKeyInfo...),
	}

	set := NewCertificateSet(positive)
	if !set.Add(negative) {
		t.Fatal("positive and negative synthetic serial numbers must remain distinct")
	}
}

func TestCertificateSetRejectsCertificatesWithoutStableIdentity(t *testing.T) {
	var set CertificateSet
	unidentifiable := &x509.Certificate{}
	unsupportedKey := &x509.Certificate{SerialNumber: big.NewInt(1), PublicKey: struct{}{}}
	if set.Add(nil) || set.Add(unidentifiable) || set.Add(unsupportedKey) {
		t.Fatal("certificates without a stable identity must not be recorded")
	}
	if set.Contains(unidentifiable) {
		t.Fatal("unidentifiable certificate must not be reported as present")
	}
	if !SameCertificate(unidentifiable, unidentifiable) {
		t.Fatal("pointer-identical certificates should compare equal")
	}
	if SameCertificate(nil, nil) || SameCertificate(nil, unidentifiable) {
		t.Fatal("nil certificates must not compare equal")
	}
}
