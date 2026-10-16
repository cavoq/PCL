package x509asn1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

func TestVerifyRSASSAPSSRejectsWhatItCannotVerify(t *testing.T) {
	sha256PSS := ParamsState{OID: oidRSAPSS, PSS: &PSSParams{
		HashAlgorithm:    AlgorithmIdentifier{OID: "2.16.840.1.101.3.4.2.1"},
		MaskGenAlgorithm: AlgorithmIdentifier{OID: oidMGF1, Params: ParamsState{OID: "2.16.840.1.101.3.4.2.1"}},
		SaltLength:       32,
		TrailerField:     1,
	}}
	if err := VerifyRSASSAPSS(ParamsState{OID: "1.2.840.113549.1.1.11"}, nil, nil, nil); err == nil {
		t.Error("verified a non-PSS algorithm")
	}
	if err := VerifyRSASSAPSS(ParamsState{OID: oidRSAPSS, Malformed: true}, nil, nil, nil); err == nil {
		t.Error("verified malformed parameters")
	}
	if err := VerifyRSASSAPSS(sha256PSS, &ecdsa.PublicKey{}, nil, nil); err == nil {
		t.Error("verified with an ECDSA key")
	}
}

func TestVerifyRSASSAPSSReportsUnsupportedParameters(t *testing.T) {
	params := ParamsState{OID: oidRSAPSS, PSS: &PSSParams{
		HashAlgorithm:    AlgorithmIdentifier{OID: oidSHA1},
		MaskGenAlgorithm: AlgorithmIdentifier{OID: oidMGF1, Params: ParamsState{OID: oidSHA1}},
		SaltLength:       20,
		TrailerField:     1,
	}}
	err := VerifyRSASSAPSS(params, rsaKeyForTest(t), nil, nil)
	if !errors.Is(err, ErrUnsupportedPSSParameters) {
		t.Fatalf("error = %v, want ErrUnsupportedPSSParameters", err)
	}
}

func rsaKeyForTest(t *testing.T) *rsa.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey
}
