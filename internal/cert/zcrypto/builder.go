package zcrypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"reflect"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/transform"
	"github.com/zmap/zcrypto/x509"
)

type ZCryptoBuilder struct {
	t *transform.Transformer
}

func NewZCryptoBuilder() *ZCryptoBuilder {
	t := transform.NewTransformer()

	t.Handle(reflect.TypeOf((*rsa.PublicKey)(nil)), handleRSA)
	t.Handle(reflect.TypeOf((*ecdsa.PublicKey)(nil)), handleECDSA)

	return &ZCryptoBuilder{t: t}
}

func (b *ZCryptoBuilder) Build(v any) *node.Node {
	return b.t.Transform("certificate", v)
}

func BuildTree(cert *x509.Certificate) *node.Node {
	return NewZCryptoBuilder().Build(cert)
}
