package zcrypto

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/cavoq/PCL/internal/node"
)

func handleRSA(name string, v any) *node.Node {
	key := v.(*rsa.PublicKey)

	n := node.New(name, nil)
	n.Children["keySize"] = node.New("keySize", key.N.BitLen())
	n.Children["exponent"] = node.New("exponent", key.E)

	return n
}

func handleECDSA(name string, v any) *node.Node {
	key := v.(*ecdsa.PublicKey)

	n := node.New(name, nil)
	n.Children["keySize"] = node.New("keySize", key.Curve.Params().BitSize)
	n.Children["curve"] = node.New("curve", key.Curve.Params().Name)

	return n
}
