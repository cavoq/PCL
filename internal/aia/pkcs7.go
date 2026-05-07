package aia

import (
	certstd "crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/cavoq/PCL/internal/zcrypto"
	"github.com/zmap/zcrypto/x509"
)

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2} // id-signedData (1.2.840.113549.1.7.2)

// parsePKCS7CertsOnly parses a PKCS#7 SignedData structure and extracts certificates.
// PKCS#7 SignedData (certs-only) structure per RFC 5652:
//
//	ContentInfo ::= SEQUENCE {
//	  contentType ContentType,  -- OID: 1.2.840.113549.1.7.2 for signedData
//	  content [0] EXPLICIT ANY DEFINED BY contentType
//	}
//	SignedData ::= SEQUENCE {
//	  version INTEGER,
//	  digestAlgorithms SET,
//	  encapContentInfo SEQUENCE,
//	  certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
//	  signerInfos SET
//	}
func parsePKCS7CertsOnly(data []byte) ([]*x509.Certificate, error) {
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 ContentInfo: %w", err)
	}

	if !contentInfo.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("PKCS#7 contentType is not signedData: %v", contentInfo.ContentType)
	}

	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo struct {
			ContentType asn1.ObjectIdentifier
			Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
		}
		Certificates asn1.RawValue `asn1:"optional,implicit,tag:0"`
		CRLs         asn1.RawValue `asn1:"optional,implicit,tag:1"`
		SignerInfos  asn1.RawValue
	}
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 SignedData: %w", err)
	}

	if len(signedData.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("PKCS#7 SignedData contains no certificates")
	}

	certs, err := parseCertificateSet(signedData.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 certificates: %w", err)
	}

	return certs, nil
}

func parseCertificateSet(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	remaining := data
	for len(remaining) > 0 {
		var certRaw asn1.RawValue
		n, err := asn1.Unmarshal(remaining, &certRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate element: %w", err)
		}

		cert, err := x509.ParseCertificate(certRaw.FullBytes)
		if err != nil {
			stdCert, stdErr := certstd.ParseCertificate(certRaw.FullBytes)
			if stdErr != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			cert, err = zcrypto.FromStdCert(stdCert)
			if err != nil {
				return nil, fmt.Errorf("failed to convert certificate: %w", err)
			}
		}

		certs = append(certs, cert)
		remaining = n
	}

	return certs, nil
}
