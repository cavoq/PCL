package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
)

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
