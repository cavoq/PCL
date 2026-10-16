package main

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"time"
)

// cabfPolicyVectors exercise the certificatePolicies profile of subscriber,
// CA, OCSP responder and root certificates.
func cabfPolicyVectors(w vectorWriter) error {
	group, err := newCABFGroup(w, "cabf-policies", 0x75, "Policy")
	if err != nil {
		return err
	}

	dv := cabfDVPolicy
	ev := cabfPolicyInformation{ID: asn1.ObjectIdentifier{2, 23, 140, 1, 1}}
	private := cabfPolicyInformation{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2}}
	anyPolicy := cabfPolicyInformation{ID: asn1.ObjectIdentifier{2, 5, 29, 32, 0}}
	cps := func(uri string) cabfPolicyQualifier {
		return cabfPolicyQualifier{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1},
			Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(uri)}}
	}
	withQualifiers := func(policy cabfPolicyInformation, qualifiers ...cabfPolicyQualifier) cabfPolicyInformation {
		policy.Qualifiers = qualifiers
		return policy
	}
	notice := cabfPolicyQualifier{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2},
		Value: asn1.RawValue{FullBytes: []byte{0x30, 0x00}}}
	unknown := cabfPolicyQualifier{ID: asn1.ObjectIdentifier{1, 2, 3, 4},
		Value: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}
	wrongTag := cps("https://example.com/cps")
	wrongTag.Value.Tag = asn1.TagUTF8String
	cutover := date(2023, 9, 15, 0, 0, 0)
	for index, vector := range []struct {
		name     string
		role     string
		policies []cabfPolicyInformation
		issuedAt time.Time
	}{
		{"subscriber-one-private", "leaf", []cabfPolicyInformation{dv, private}, time.Time{}},
		{"subscriber-multiple", "leaf", []cabfPolicyInformation{dv, ev}, time.Time{}},
		{"subscriber-none", "leaf", []cabfPolicyInformation{private}, time.Time{}},
		{"subscriber-private-first", "leaf", []cabfPolicyInformation{private, dv}, time.Time{}},
		{"cps-http", "leaf", []cabfPolicyInformation{withQualifiers(dv, cps("http://example.com/cps"))}, time.Time{}},
		{"cps-https", "leaf", []cabfPolicyInformation{dv, withQualifiers(private, cps("https://example.com/cps"))}, time.Time{}},
		{"qualifier-second-policy", "leaf", []cabfPolicyInformation{dv, withQualifiers(private, notice)}, time.Time{}},
		{"qualifier-second-value", "leaf", []cabfPolicyInformation{withQualifiers(dv, cps("https://example.com/cps"), notice)}, time.Time{}},
		{"qualifier-unknown", "leaf", []cabfPolicyInformation{withQualifiers(dv, unknown)}, time.Time{}},
		{"cps-ftp", "leaf", []cabfPolicyInformation{withQualifiers(dv, cps("ftp://example.com/cps"))}, time.Time{}},
		{"cps-no-host", "leaf", []cabfPolicyInformation{withQualifiers(dv, cps("https:cps"))}, time.Time{}},
		{"cps-wrong-tag", "leaf", []cabfPolicyInformation{withQualifiers(dv, wrongTag)}, time.Time{}},
		{"empty", "leaf", nil, time.Time{}},
		{"duplicate", "leaf", []cabfPolicyInformation{dv, dv}, time.Time{}},
		{"ca-any-alone", "intermediate", []cabfPolicyInformation{anyPolicy}, time.Time{}},
		{"ca-any-mixed", "intermediate", []cabfPolicyInformation{anyPolicy, dv}, time.Time{}},
		{"ca-multiple", "intermediate", []cabfPolicyInformation{dv, ev}, time.Time{}},
		{"ca-private-first", "intermediate", []cabfPolicyInformation{private, dv}, time.Time{}},
		{"ca-cps", "intermediate", []cabfPolicyInformation{withQualifiers(dv, cps("https://example.com/cps"))}, time.Time{}},
		{"non-tls-private", "nonTLS", []cabfPolicyInformation{private}, time.Time{}},
		{"responder-cps", "ocspSigning", []cabfPolicyInformation{withQualifiers(private, cps("https://example.com/cps"))}, time.Time{}},
		{"responder-unknown", "ocspSigning", []cabfPolicyInformation{withQualifiers(private, unknown)}, time.Time{}},
		{"root-any-mixed", "root", []cabfPolicyInformation{anyPolicy, dv}, time.Time{}},
		{"before-cutover", "leaf", []cabfPolicyInformation{dv, ev}, cutover.Add(-time.Second)},
		{"at-cutover", "leaf", []cabfPolicyInformation{dv, ev}, cutover},
	} {
		c, err := group.template(index, vector.role, vector.issuedAt, vector.policies)
		if err != nil {
			return err
		}
		var parent *x509.Certificate
		var signer crypto.Signer
		if vector.role == "root" {
			parent, signer = c, group.subjectKey
		}
		// Do not round-trip through Go's parser: the duplicate-policy vector
		// is intentionally rejected there but must reach PCL's own parser.
		if err := group.write(vector.name+".pem", c, parent, signer); err != nil {
			return err
		}
	}
	return nil
}
