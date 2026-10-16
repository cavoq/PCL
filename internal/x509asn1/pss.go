package x509asn1

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
)

// RSASSAPSS is the id-RSASSA-PSS signature algorithm OID (RFC 4055).
const RSASSAPSS = oidRSAPSS

// pssHashes are the hash functions PSS signatures are verified with. SHA-1
// is not accepted for signatures.
var pssHashes = map[string]crypto.Hash{
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

// ErrUnsupportedPSSParameters reports RSASSA-PSS parameters that are valid
// RFC 4055 encodings but outside what can be verified: a hash other than
// SHA-256, SHA-384 or SHA-512, or a mask generation function other than MGF1
// with the signature hash.
var ErrUnsupportedPSSParameters = errors.New("unsupported RSASSA-PSS parameters")

// VerifyRSASSAPSS verifies an RSASSA-PSS signature over signed with key,
// using the hash, mask generation function, salt length and trailer field
// of params, the parsed signature AlgorithmIdentifier. Unlike crypto/x509 it
// does not require the salt length to equal the hash length. A declared salt
// length of 0 is verified with automatic salt detection, the only zero-salt
// mode crypto/rsa offers.
func VerifyRSASSAPSS(params ParamsState, key any, signed, signature []byte) error {
	pss := params.PSS
	if params.OID != oidRSAPSS {
		return fmt.Errorf("signature algorithm %s is not RSASSA-PSS", params.OID)
	}
	if params.Malformed || pss == nil {
		return errors.New("malformed RSASSA-PSS parameters")
	}
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("RSASSA-PSS needs an RSA public key, have %T", key)
	}
	hash, ok := pssHashes[pss.HashAlgorithm.OID]
	if !ok {
		return fmt.Errorf("%w: hash %s", ErrUnsupportedPSSParameters, pss.HashAlgorithm.OID)
	}
	if pss.MaskGenAlgorithm.OID != oidMGF1 || pss.MaskGenAlgorithm.Params.OID != pss.HashAlgorithm.OID {
		return fmt.Errorf("%w: mask generation %s with %s", ErrUnsupportedPSSParameters,
			pss.MaskGenAlgorithm.OID, pss.MaskGenAlgorithm.Params.OID)
	}
	if pss.TrailerField != 1 || pss.SaltLength < 0 {
		return fmt.Errorf("invalid RSASSA-PSS trailerField %d or saltLength %d", pss.TrailerField, pss.SaltLength)
	}
	digest := hash.New()
	digest.Write(signed)
	return rsa.VerifyPSS(publicKey, hash, digest.Sum(nil), signature, &rsa.PSSOptions{SaltLength: pss.SaltLength, Hash: hash})
}
