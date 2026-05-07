package zcrypto

import (
	"encoding/pem"
	"os"
	"testing"

	"github.com/zmap/zcrypto/x509"
)

func TestBuildTree_CRL_OID(t *testing.T) {
	// 使用一个真实的 CRL 文件进行测试
	// 如果文件不存在，跳过测试
	data, err := os.ReadFile("/Users/m0nst3r/dev-local/ssl/sample-certs/evrca-crl1.crl")
	if err != nil {
		t.Skip("CRL file not found, skipping test")
	}

	// 尝试 PEM 解析
	block, _ := pem.Decode(data)
	var crl *x509.RevocationList
	if block != nil && block.Type == "X509 CRL" {
		crl, err = x509.ParseRevocationList(block.Bytes)
	} else {
		crl, err = x509.ParseRevocationList(data)
	}

	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	tree := BuildTree(crl)

	// 检查 signatureAlgorithm OID
	oidNode, ok := tree.Resolve("crl.signatureAlgorithm.oid")
	if !ok {
		t.Error("crl.signatureAlgorithm.oid not found")
	} else {
		oid, ok := oidNode.Value.(string)
		if !ok {
			t.Error("OID value is not a string")
		} else if oid != "1.2.840.113549.1.1.11" {
			t.Errorf("Expected OID 1.2.840.113549.1.1.11 (SHA256-RSA), got %s", oid)
		}
	}

	// 检查 tbsSignatureAlgorithm OID
	tbsOidNode, ok := tree.Resolve("crl.tbsSignatureAlgorithm.oid")
	if !ok {
		t.Error("crl.tbsSignatureAlgorithm.oid not found")
	} else {
		oid, ok := tbsOidNode.Value.(string)
		if !ok {
			t.Error("TBS OID value is not a string")
		} else if oid != "1.2.840.113549.1.1.11" {
			t.Errorf("Expected TBS OID 1.2.840.113549.1.1.11, got %s", oid)
		}
	}
}