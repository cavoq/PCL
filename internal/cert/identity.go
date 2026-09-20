package cert

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/zmap/zcrypto/x509"
)

// CertificateSet tracks certificates by their encoded identity. Parsed
// certificates use the complete DER encoding. Synthetic certificates, which
// have no Raw encoding, use their issuer, serial number, and subject public key
// information instead.
//
// The zero value is ready for use. Add reports whether it recorded a new
// certificate; nil certificates and synthetic certificates without a serial
// number cannot be recorded.
type CertificateSet struct {
	keys map[certificateKey]struct{}
}

type certificateKey struct {
	kind   certificateKeyKind
	digest [sha256.Size]byte
}

type certificateKeyKind uint8

const (
	encodedCertificateKey certificateKeyKind = iota + 1
	syntheticCertificateKey
)

const (
	missingIdentityField byte = iota
	rawIdentityField
	parsedIdentityField
)

// NewCertificateSet creates a set populated with certificates. Certificates
// for which no stable identity is available are ignored.
func NewCertificateSet(certificates ...*x509.Certificate) *CertificateSet {
	set := &CertificateSet{}
	for _, certificate := range certificates {
		set.Add(certificate)
	}
	return set
}

// SameCertificate reports whether left and right have the same stable
// certificate identity. Pointer-identical synthetic certificates compare equal
// even when they do not contain enough information to build an identity.
func SameCertificate(left, right *x509.Certificate) bool {
	if left == nil || right == nil {
		return false
	}
	if left == right {
		return true
	}
	leftKey, leftOK := certificateIdentity(left)
	rightKey, rightOK := certificateIdentity(right)
	return leftOK && rightOK && leftKey == rightKey
}

// Add records certificate and reports whether its identity was new.
func (s *CertificateSet) Add(certificate *x509.Certificate) bool {
	if s == nil {
		return false
	}
	key, ok := certificateIdentity(certificate)
	if !ok {
		return false
	}
	if s.keys == nil {
		s.keys = make(map[certificateKey]struct{})
	}
	if _, exists := s.keys[key]; exists {
		return false
	}
	s.keys[key] = struct{}{}
	return true
}

// Contains reports whether certificate has already been recorded.
func (s *CertificateSet) Contains(certificate *x509.Certificate) bool {
	if s == nil {
		return false
	}
	key, ok := certificateIdentity(certificate)
	if !ok {
		return false
	}
	_, exists := s.keys[key]
	return exists
}

func certificateIdentity(certificate *x509.Certificate) (certificateKey, bool) {
	if certificate == nil {
		return certificateKey{}, false
	}
	if len(certificate.Raw) > 0 {
		return certificateKey{
			kind:   encodedCertificateKey,
			digest: sha256.Sum256(certificate.Raw),
		}, true
	}
	if certificate.SerialNumber == nil {
		return certificateKey{}, false
	}

	issuerKind, issuer := certificateIssuerIdentity(certificate)
	publicKeyKind, publicKey, ok := certificatePublicKeyIdentity(certificate)
	if !ok {
		return certificateKey{}, false
	}
	identity := make([]byte, 0, len(issuer)+len(publicKey)+64)
	identity = appendIdentityField(identity, issuerKind, issuer)
	identity = appendIdentityField(identity, parsedIdentityField, []byte(certificate.SerialNumber.String()))
	identity = appendIdentityField(identity, publicKeyKind, publicKey)

	return certificateKey{
		kind:   syntheticCertificateKey,
		digest: sha256.Sum256(identity),
	}, true
}

func certificateIssuerIdentity(certificate *x509.Certificate) (byte, []byte) {
	if len(certificate.RawIssuer) > 0 {
		return rawIdentityField, certificate.RawIssuer
	}
	return parsedIdentityField, []byte(certificate.Issuer.String())
}

func certificatePublicKeyIdentity(certificate *x509.Certificate) (byte, []byte, bool) {
	if len(certificate.RawSubjectPublicKeyInfo) > 0 {
		return rawIdentityField, certificate.RawSubjectPublicKeyInfo, true
	}
	if certificate.PublicKey == nil {
		return missingIdentityField, nil, true
	}
	encoded, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return missingIdentityField, nil, false
	}
	return parsedIdentityField, encoded, true
}

func appendIdentityField(identity []byte, kind byte, value []byte) []byte {
	identity = append(identity, kind)
	identity = binary.BigEndian.AppendUint64(identity, uint64(len(value)))
	return append(identity, value...)
}
