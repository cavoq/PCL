# 🏛️ CA/B Forum TLS Baseline Requirements Coverage

[Documentation](../docs/POLICY_WRITING_GUIDE.md) · [Policy](CABF-TLS-BR.yaml)

## Scope

Certificate-profile conformance against the Baseline Requirements for the
Issuance and Management of Publicly-Trusted TLS Server Certificates, version
2.3.1 (2026-10-04): the Subscriber Certificate profile (7.1.2.7) and the
key, algorithm and name-encoding requirements that apply to every
certificate of the chain. A certificate answers only questions about its
contents; domain and identity validation (3.2), CA operations, audits,
Certificate Transparency and CAA checking need evidence beyond the
certificate and are out of scope.

Load the pack together with `rfc5280`: the Baseline Requirements apply
RFC 5280 except where they say otherwise, and this pack states only what
they add. Requirement levels follow the BR text: MUST and MUST NOT are
errors, SHOULD, SHOULD NOT and NOT RECOMMENDED are warnings.

## Requirement matrix

| Requirement | Status | Rules | Evidence |
|---|---|---|---|
| Key types and sizes (6.1.5), RSA exponent (6.1.6) | Covered | `br-rsa-key-size`, `br-rsa-key-size-multiple-of-8`, `br-rsa-exponent-odd`, `br-rsa-exponent-min`, `br-rsa-exponent-range` (SHOULD) | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| SubjectPublicKeyInfo encodings (7.1.3.1) | Covered | `br-spki-algorithm-encoding`: byte-for-byte rsaEncryption/NULL or P-256/P-384/P-521 | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Signature AlgorithmIdentifier encodings (7.1.3.2) | Covered | `br-signature-algorithm-encoding`: the nine permitted encodings | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Name encoding (7.1.4.1, 7.1.4.2) | Partial | `br-name-one-attribute-per-rdn`, `br-name-no-duplicate-attributes`, `br-subject-*-encoding`, `br-subject-*-length` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Subscriber Validity Period by issuance date (6.3.2) | Covered | `br-subscriber-validity-max-{398,200,100,47}-days` (MUST), `-{397,199,99,46}-days` (SHOULD), inclusive of notAfter | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Subscriber version (7.1.2.7) | Covered | `br-subscriber-version-3` | Conforming chain |
| Authority Information Access (7.1.2.7.7) | Covered | `br-subscriber-aia-present` (SHOULD), `br-subscriber-aia-access-methods`, `br-subscriber-aia-http-uri`, `br-subscriber-aia-ca-issuers` (SHOULD) | Conforming chain |
| Certificate Policies (7.1.2.7.9) | Partial | `br-subscriber-certificate-policies-present`, `-not-critical`, `br-subscriber-reserved-policy`, `br-subscriber-no-any-policy` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Extended Key Usage (7.1.2.7.10) | Covered | `br-subscriber-eku-present`, `-not-critical`, `-server-auth`, `-prohibited`, `-only-tls` (NOT RECOMMENDED) | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Subject Alternative Name (7.1.2.7.12) | Covered | `br-subscriber-san-*`; dNSName root label, wildcard position, LDH and reserved LDH labels, Internal Names, reverse zones (from 2026-03-15); Reserved IP Addresses | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Key Usage (7.1.2.7.11) | Covered | `br-subscriber-key-usage-*`, `br-subscriber-rsa-key-usage*`, `br-subscriber-ecc-key-usage*` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Basic Constraints, Name Constraints, SKI (7.1.2.7.6, 7.1.2.7.8) | Covered | `br-subscriber-basic-constraints-critical`, `br-subscriber-no-name-constraints`, `br-subscriber-no-subject-key-identifier` (NOT RECOMMENDED); cA and pathLenConstraint by `rfc5280` | Conforming chain |
| CRL Distribution Points (7.1.2.11.2) | Covered | `br-subscriber-crl-distribution-points-required*` (short-lived 10 days, 7 days from 2026-03-15), `br-crl-distribution-points-*` | Conforming chain |
| Subject by certificate type (7.1.2.7.2–7.1.2.7.4) | Covered for DV, OV, IV | `br-subscriber-dv-subject-attributes`, `br-subscriber-ov-*`, `br-subscriber-iv-*`, `br-subscriber-subject-not-metadata` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Common Name (7.1.4.3) | Partial | `br-subscriber-common-name-not-recommended`, `br-subscriber-common-name-from-san` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |

## Limits

| Area | Limit |
|---|---|
| Other profiles | Root, cross-certified, technically constrained and TLS subordinate CA profiles (7.1.2.1–7.1.2.6, 7.1.2.10), OCSP responder certificates (7.1.2.8), Precertificates (7.1.2.9), the CRL profile (7.2) and the OCSP profile (7.3) are not checked yet; the algorithm, key and name-encoding rules apply to every certificate |
| Extended Validation | EV subjects follow the EV Guidelines, which this pack does not implement |
| Issuance date | Certificates do not record issuance; notBefore stands in for it, which the BR bounds to 48 hours of signing |
| Certificate Policies | Exactly one Reserved Certificate Policy Identifier, the recommended order, and the permitted policyQualifiers (CPS URI only) are not checked |
| ECDSA signature hash | Matching the hash to the signing key's curve (7.1.3.2.2) needs the issuer's key and is not checked |
| Authority Key Identifier | authorityCertIssuer and authorityCertSerialNumber (7.1.2.11.1) are not projected |
| Serial numbers | 64 bits of CSPRNG output and non-sequential issuance are not observable in one certificate |
| Names | RDN order (7.1.4.2), byte-identical CA subject encodings across certificates (7.1.4.1), the IPv4/IPv6 text forms of a commonName, and Punycode validity of P-Labels are not checked |
| Internal Names | Top-level domains come from the Public Suffix List ICANN section, embedded or loaded with `--psl-file` |
| Reserved IP Addresses | The IANA special-purpose registries as of October 2026 |
| SCT list | The content of the Signed Certificate Timestamp List (7.1.2.11.3) is not checked |
| RFC 5280 | `rfc5280` recommends a subjectKeyIdentifier in end-entity certificates (4.2.1.2); the BR do not recommend it, so the two packs warn in opposite directions |
