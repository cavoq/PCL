package zcrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestBuildTree_OCSP_RSA_SHA256(t *testing.T) {
	// Generate test issuer and responder certificates
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	responderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate responder key: %v", err)
	}

	// Create issuer certificate
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuer"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerCert, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer certificate: %v", err)
	}

	// Create responder certificate
	responderTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test OCSP Responder"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	issuerCertParsed, err := x509.ParseCertificate(issuerCert)
	if err != nil {
		t.Fatalf("Failed to parse issuer certificate: %v", err)
	}
	responderCert, err := x509.CreateCertificate(rand.Reader, responderTemplate, issuerCertParsed, &responderKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create responder certificate: %v", err)
	}
	responderCertParsed, err := x509.ParseCertificate(responderCert)
	if err != nil {
		t.Fatalf("Failed to parse responder certificate: %v", err)
	}

	// Create OCSP response template
	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(100),
		ThisUpdate:   time.Now().Truncate(time.Minute),
		NextUpdate:   time.Now().Add(1 * time.Hour).Truncate(time.Minute),
		IssuerHash:   crypto.SHA256,
	}

	// Create OCSP response with SHA256WithRSA (OID 1.2.840.113549.1.1.11)
	ocspRespBytes, err := ocsp.CreateResponse(issuerCertParsed, responderCertParsed, template, responderKey)
	if err != nil {
		t.Fatalf("Failed to create OCSP response: %v", err)
	}

	// Parse OCSP response without signature verification (we just want to test parsing)
	ocspResp, err := ocsp.ParseResponse(ocspRespBytes, nil)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	// Build tree
	tree := BuildTree(ocspResp)
	if tree == nil {
		t.Fatal("BuildTree returned nil")
	}

	// Verify status
	statusNode, ok := tree.Resolve("ocsp.status")
	if !ok {
		t.Error("ocsp.status not found")
	} else {
		status, ok := statusNode.Value.(string)
		if !ok {
			t.Error("Status value is not a string")
		} else if status != "Good" {
			t.Errorf("Expected status 'Good', got %s", status)
		}
	}

	// Verify serial number
	serialNode, ok := tree.Resolve("ocsp.serialNumber")
	if !ok {
		t.Error("ocsp.serialNumber not found")
	} else {
		serial, ok := serialNode.Value.(string)
		if !ok {
			t.Error("SerialNumber value is not a string")
		} else if serial != "100" {
			t.Errorf("Expected serial '100', got %s", serial)
		}
	}

	// Verify signature algorithm OID
	oidNode, ok := tree.Resolve("ocsp.signatureAlgorithm.oid")
	if !ok {
		t.Error("ocsp.signatureAlgorithm.oid not found")
	} else {
		oid, ok := oidNode.Value.(string)
		if !ok {
			t.Error("OID value is not a string")
		} else if oid != "1.2.840.113549.1.1.11" {
			t.Logf("SignatureAlgorithm: %s", ocspResp.SignatureAlgorithm.String())
			t.Errorf("Expected OID 1.2.840.113549.1.1.11 (SHA256-RSA), got %s", oid)
		}
	}

	// Verify TBS signature algorithm OID (should be same as outer)
	tbsOidNode, ok := tree.Resolve("ocsp.tbsSignatureAlgorithm.oid")
	if !ok {
		t.Error("ocsp.tbsSignatureAlgorithm.oid not found")
	} else {
		oid, ok := tbsOidNode.Value.(string)
		if !ok {
			t.Error("TBS OID value is not a string")
		} else if oid != "1.2.840.113549.1.1.11" {
			t.Errorf("Expected TBS OID 1.2.840.113549.1.1.11, got %s", oid)
		}
	}

	// Verify NULL parameters for RSA
	nullNode, ok := tree.Resolve("ocsp.signatureAlgorithm.parameters.null")
	if !ok {
		t.Error("ocsp.signatureAlgorithm.parameters.null not found")
	} else {
		isNull, ok := nullNode.Value.(bool)
		if !ok {
			t.Error("Null parameter value is not a bool")
		} else if !isNull {
			t.Error("Expected NULL parameters for RSA signature algorithm")
		}
	}

	// Verify issuer hash
	issuerHashNode, ok := tree.Resolve("ocsp.issuerHash")
	if !ok {
		t.Error("ocsp.issuerHash not found")
	} else {
		hash, ok := issuerHashNode.Value.(string)
		if !ok {
			t.Error("IssuerHash value is not a string")
		} else if hash != "SHA256" {
			t.Errorf("Expected issuerHash 'SHA256', got %s", hash)
		}
	}
}

func TestBuildTree_OCSP_Revoked(t *testing.T) {
	// Generate test issuer and responder certificates
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	responderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate responder key: %v", err)
	}

	// Create issuer certificate
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuer"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerCert, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create issuer certificate: %v", err)
	}
	issuerCertParsed, err := x509.ParseCertificate(issuerCert)
	if err != nil {
		t.Fatalf("Failed to parse issuer certificate: %v", err)
	}

	// Create responder certificate
	responderTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test OCSP Responder"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	responderCert, err := x509.CreateCertificate(rand.Reader, responderTemplate, issuerCertParsed, &responderKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create responder certificate: %v", err)
	}
	responderCertParsed, err := x509.ParseCertificate(responderCert)
	if err != nil {
		t.Fatalf("Failed to parse responder certificate: %v", err)
	}

	// Create OCSP response with Revoked status
	template := ocsp.Response{
		Status:           ocsp.Revoked,
		SerialNumber:     big.NewInt(100),
		ThisUpdate:       time.Now().Truncate(time.Minute),
		NextUpdate:       time.Now().Add(1 * time.Hour).Truncate(time.Minute),
		RevokedAt:        time.Now().Add(-30 * time.Minute).Truncate(time.Minute),
		RevocationReason: ocsp.Superseded,
		IssuerHash:       crypto.SHA256,
	}

	ocspRespBytes, err := ocsp.CreateResponse(issuerCertParsed, responderCertParsed, template, responderKey)
	if err != nil {
		t.Fatalf("Failed to create OCSP response: %v", err)
	}

	ocspResp, err := ocsp.ParseResponse(ocspRespBytes, nil)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	tree := BuildTree(ocspResp)
	if tree == nil {
		t.Fatal("BuildTree returned nil")
	}

	// Verify status is Revoked
	statusNode, ok := tree.Resolve("ocsp.status")
	if !ok {
		t.Error("ocsp.status not found")
	} else {
		status, ok := statusNode.Value.(string)
		if !ok {
			t.Error("Status value is not a string")
		} else if status != "Revoked" {
			t.Errorf("Expected status 'Revoked', got %s", status)
		}
	}

	// Verify revokedAt exists
	_, ok = tree.Resolve("ocsp.revokedAt")
	if !ok {
		t.Error("ocsp.revokedAt not found for revoked certificate")
	}

	// Verify revocationReason exists
	_, ok = tree.Resolve("ocsp.revocationReason")
	if !ok {
		t.Error("ocsp.revocationReason not found for revoked certificate")
	}
}
