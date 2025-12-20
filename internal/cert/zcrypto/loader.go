package zcrypto

import (
	"encoding/pem"
	"errors"

	"github.com/zmap/zcrypto/x509"
)

type Loader struct{}

func NewLoader() *Loader {
	return &Loader{}
}

func (l *Loader) Load(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}
