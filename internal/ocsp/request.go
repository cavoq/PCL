package ocsp

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	stdasn1 "encoding/asn1"
	"encoding/hex"
	"fmt"

	der "github.com/cavoq/PCL/internal/asn1"
	"golang.org/x/crypto/ocsp"
)

var nonceOID = stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// NonceOptions configures nonce in OCSP requests (RFC 9654).
type NonceOptions struct {
	Length   int    // Length of nonce to generate (default 32, per RFC 9654)
	Value    string // Custom nonce value in hex format (optional)
	Disabled bool   // Disable nonce in requests
	Hash     string // Hash algorithm for CertID: "sha1" or "sha256" (default)
}

// RequestInfo contains OCSP request debug information.
type RequestInfo struct {
	Nonce         []byte // Nonce sent in request (nil if no nonce)
	NonceHex      string // Hex representation of nonce
	NonceLen      int    // Length of nonce in request (0 if no nonce)
	RequestLen    int    // Length of raw OCSP request bytes
	HashAlgorithm string // Hash algorithm used for CertID (e.g., "SHA256")
}

func buildOCSPRequest(cert, issuer *x509.Certificate, nonceOpts *NonceOptions) ([]byte, *RequestInfo, error) {
	hashAlgorithm, hashName := certIDHash(nonceOpts)
	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: hashAlgorithm})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	reqInfo := &RequestInfo{
		RequestLen:    len(req),
		HashAlgorithm: hashName,
	}

	if nonceOpts == nil || nonceOpts.Disabled {
		return req, reqInfo, nil
	}

	nonce, err := nonceBytes(nonceOpts)
	if err != nil {
		return nil, nil, err
	}

	req, err = addNonceToOCSPRequest(req, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to add nonce extension: %w", err)
	}

	reqInfo.Nonce = nonce
	reqInfo.NonceHex = hex.EncodeToString(nonce)
	reqInfo.NonceLen = len(nonce)
	reqInfo.RequestLen = len(req)

	return req, reqInfo, nil
}

func certIDHash(nonceOpts *NonceOptions) (crypto.Hash, string) {
	if nonceOpts != nil && nonceOpts.Hash == "sha1" {
		return crypto.SHA1, "SHA1"
	}
	return crypto.SHA256, "SHA256"
}

func nonceBytes(opts *NonceOptions) ([]byte, error) {
	if opts.Value != "" {
		nonce, err := parseNonceHex(opts.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid nonce hex value: %w", err)
		}
		return nonce, nil
	}

	length := opts.Length
	if length <= 0 {
		length = 32
	}
	if length < 1 || length > 128 {
		return nil, fmt.Errorf("nonce length must be 1-128 bytes (RFC 9654)")
	}
	return generateNonce(length)
}

func generateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

func parseNonceHex(hexValue string) ([]byte, error) {
	return hex.DecodeString(hexValue)
}

func addNonceToOCSPRequest(ocspRequest []byte, nonce []byte) ([]byte, error) {
	if len(ocspRequest) < 2 || ocspRequest[0] != 0x30 {
		return nil, fmt.Errorf("invalid OCSP request: expected SEQUENCE tag")
	}

	ocspLen, contentStart, err := der.ReadDERLength(ocspRequest, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid OCSP request: %w", err)
	}
	if contentStart+ocspLen > len(ocspRequest) {
		return nil, fmt.Errorf("invalid OCSP request: length mismatch")
	}

	tbsBytes := ocspRequest[contentStart : contentStart+ocspLen]
	if len(tbsBytes) < 2 || tbsBytes[0] != 0x30 {
		return nil, fmt.Errorf("invalid TBSRequest: expected SEQUENCE tag")
	}

	tbsLen, tbsContentStart, err := der.ReadDERLength(tbsBytes, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid TBSRequest: %w", err)
	}
	if tbsContentStart+tbsLen > len(tbsBytes) {
		return nil, fmt.Errorf("invalid TBSRequest: length mismatch")
	}

	nonceOIDDER, err := der.EncodeObjectIdentifier(nonceOID)
	if err != nil {
		return nil, err
	}

	tbsContent := tbsBytes[tbsContentStart : tbsContentStart+tbsLen]
	nonceOctetString := der.EncodeOctetString(nonce)
	extensionContent := append(nonceOIDDER, nonceOctetString...)
	extension := der.EncodeSequence(extensionContent)
	extensions := der.EncodeSequence(extension)
	requestExtensions := der.EncodeContextSpecificConstructed(2, extensions)

	newTbsContent := append(tbsContent, requestExtensions...)
	return der.EncodeSequence(der.EncodeSequence(newTbsContent)), nil
}
