package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
)

func GetSubjectNames(cert *x509.Certificate) []string {
	var names []string

	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}

	// Add SAN DNS names (important for leaf certs)
	if len(cert.DNSNames) > 0 {
		names = append(names, cert.DNSNames...)
	}

	return names
}

func GetIssuerNames(cert *x509.Certificate) []string {
	var names []string

	if cert.Issuer.CommonName != "" {
		names = append(names, cert.Issuer.CommonName)
	}

	return names
}

type PublicKeyAlgorithm string

const (
	PubKeyRSA     PublicKeyAlgorithm = "RSA"
	PubKeyEC      PublicKeyAlgorithm = "EC"
	PubKeyEd25519 PublicKeyAlgorithm = "Ed25519"
	PubKeyUnknown PublicKeyAlgorithm = "UNKNOWN"
)

func GetPublicKeyAlgorithm(cert *x509.Certificate) PublicKeyAlgorithm {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return PubKeyRSA
	case *ecdsa.PublicKey:
		return PubKeyEC
	case ed25519.PublicKey:
		return PubKeyEd25519
	default:
		return PubKeyUnknown
	}
}
