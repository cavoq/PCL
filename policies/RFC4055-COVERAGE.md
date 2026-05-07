# RFC 4055 Policy Coverage

This document tracks implementation of [RFC 4055](https://datatracker.ietf.org/doc/html/rfc4055) requirements for RSA Cryptography.

> Items marked **(parsing)** are validated by the x509 library during parsing.
> Items marked **(not enforced)** are not currently implemented.

---

## RSA Algorithm OIDs (Section 1)

### 1.2 RSA Encryption OID

| Requirement | Level | Rule | Status |
|-------------|-------|------|--------|
| rsaEncryption OID (1.2.840.113549.1.1.1) MUST have NULL parameters | MUST | `cert-spki-rsa-params-null` | ✅ Implemented |

---

## Signature Algorithms (Section 5)

### 5.1 Algorithm Identifier Encoding

| Requirement | Level | Rule | Status |
|-------------|-------|------|--------|
| TBSCertificate.signature MUST have NULL parameters for RSA algorithms | MUST | `cert-tbs-signature-rsa-params-null` | ✅ Implemented |
| Certificate.signatureAlgorithm MUST have NULL parameters for RSA algorithms | MUST | `cert-signature-algorithm-rsa-params-null` | ✅ Implemented |
| TBSCertList.signature MUST have NULL parameters for RSA algorithms | MUST | `crl-tbs-signature-rsa-params-null` | ✅ Implemented |
| CRL.signatureAlgorithm MUST have NULL parameters for RSA algorithms | MUST | `crl-signature-algorithm-rsa-params-null` | ✅ Implemented |

### 5.2 Covered RSA Signature Algorithm OIDs

| OID | Algorithm | Certificate | CRL |
|-----|-----------|-------------|-----|
| 1.2.840.113549.1.1.1 | rsaEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.2 | md2WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.3 | md4WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.4 | md5WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.5 | sha1WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.11 | sha256WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.12 | sha384WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.13 | sha512WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.14 | sha224WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.15 | sha512-224WithRSAEncryption | ✅ | ✅ |
| 1.2.840.113549.1.1.16 | sha512-256WithRSAEncryption | ✅ | ✅ |

---

## RSASSA-PSS (Section 3)

### 3.1 Algorithm Identifier

| OID | Algorithm | Status |
|-----|-----------|--------|
| 1.2.840.113549.1.1.10 | id-RSASSA-PSS | ✅ Implemented |

### 3.2 RSASSA-PSS Parameters

RSASSA-PSS uses a SEQUENCE of parameters rather than NULL:

```asn1
RSASSA-PSS-params ::= SEQUENCE {
    hashAlgorithm      [0] HashAlgorithm DEFAULT sha1,
    maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
    saltLength         [2] INTEGER DEFAULT 20,
    trailerField       [3] TrailerField DEFAULT trailerFieldBC
}
```

| Requirement | Level | Rule | Status |
|-------------|-------|------|--------|
| hashAlgorithm must be a valid HashAlgorithm | MUST | `cert-tbs-pss-hash-algorithm-valid`, `cert-pss-hash-algorithm-valid`, `crl-tbs-pss-hash-algorithm-valid`, `crl-pss-hash-algorithm-valid` | ✅ Implemented |
| maskGenAlgorithm must be id-mgf1 (OID 1.2.840.113549.1.1.8) | MUST | `cert-tbs-pss-mgf-algorithm-valid`, `cert-pss-mgf-algorithm-valid`, `crl-tbs-pss-mgf-algorithm-valid`, `crl-pss-mgf-algorithm-valid` | ✅ Implemented |
| MGF1 hashAlgorithm must be valid | MUST | `cert-tbs-pss-mgf-hash-valid`, `cert-pss-mgf-hash-valid`, `crl-tbs-pss-mgf-hash-valid`, `crl-pss-mgf-hash-valid` | ✅ Implemented |
| saltLength must be non-negative integer | MUST | `cert-tbs-pss-salt-length-valid`, `cert-pss-salt-length-valid`, `crl-tbs-pss-salt-length-valid`, `crl-pss-salt-length-valid` | ✅ Implemented |
| trailerField must be 1 (trailerFieldBC) | MUST | `cert-tbs-pss-trailer-field-valid`, `cert-pss-trailer-field-valid`, `crl-tbs-pss-trailer-field-valid`, `crl-pss-trailer-field-valid` | ✅ Implemented |
| Parameters must be encoded as SEQUENCE | MUST | (parsing) | ✅ Implemented |
| Empty sequence means default values (SHA-1, MGF1-SHA1, saltLength=20) | MUST | (parsing defaults) | ✅ Implemented |

### 3.3 HashAlgorithm OIDs

| OID | Algorithm | Status |
|-----|-----------|--------|
| 1.3.14.3.2.26 | id-sha1 | ✅ Allowed (deprecated) |
| 2.16.840.1.101.3.4.2.1 | id-sha256 | ✅ Allowed |
| 2.16.840.1.101.3.4.2.2 | id-sha384 | ✅ Allowed |
| 2.16.840.1.101.3.4.2.3 | id-sha512 | ✅ Allowed |
| 2.16.840.1.101.3.4.2.4 | id-sha224 | ✅ Allowed |
| 2.16.840.1.101.3.4.2.5 | id-sha512-224 | ✅ Allowed |
| 2.16.840.1.101.3.4.2.6 | id-sha512-256 | ✅ Allowed |

### 3.4 MaskGenAlgorithm

| OID | Algorithm | Status |
|-----|-----------|--------|
| 1.2.840.113549.1.1.8 | id-mgf1 | ✅ Required |

> MGF1 requires a HashAlgorithm parameter, validated by `*-pss-mgf-hash-valid` rules.

---

## RSAES-OAEP (Section 4)

### 4.1 Algorithm Identifier

| OID | Algorithm | Status |
|-----|-----------|--------|
| 1.2.840.113549.1.1.7 | id-RSAES-OAEP | ✅ Implemented |

### 4.2 RSAES-OAEP Parameters

RSAES-OAEP uses a SEQUENCE of parameters:

```asn1
RSAES-OAEP-params ::= SEQUENCE {
    hashAlgorithm     [0] HashAlgorithm DEFAULT sha1,
    maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
    pSourceAlgorithm  [2] PSourceAlgorithm DEFAULT pSpecifiedEmpty
}
```

| Requirement | Level | Rule | Status |
|-------------|-------|------|--------|
| hashAlgorithm must be a valid HashAlgorithm | MUST | `cert-spki-oaep-hash-algorithm-valid` | ✅ Implemented |
| maskGenAlgorithm must be id-mgf1 (OID 1.2.840.113549.1.1.8) | MUST | `cert-spki-oaep-mgf-algorithm-valid` | ✅ Implemented |
| MGF1 hashAlgorithm must be valid | MUST | `cert-spki-oaep-mgf-hash-valid` | ✅ Implemented |
| pSourceAlgorithm must be id-pSpecified (OID 1.2.840.113549.1.1.9) | MUST | `cert-spki-oaep-psource-valid` | ✅ Implemented |
| Parameters must be encoded as SEQUENCE | MUST | (parsing) | ✅ Implemented |
| Empty sequence means default values | MUST | (parsing defaults) | ✅ Implemented |

### 4.3 PSourceAlgorithm

| OID | Algorithm | Status |
|-----|-----------|--------|
| 1.2.840.113549.1.1.9 | id-pSpecified | ✅ Required |

> pSpecified encoding of P is validated during parsing.

---

## Out of Scope

The following are handled by the x509 parsing library or are outside PCL's scope:

| Item | Reason |
|------|--------|
| RSA key size validation | Covered by RFC5280 best practices |
| RSA exponent validation | Covered by RFC5280 best practices |
| Signature algorithm selection for certificate signing | Implementation choice |
| Compatibility with legacy systems | Policy decision, not RFC requirement |
| MD5 hash algorithm validation | Deprecated, not recommended for new use |
| MD2/MD4 hash algorithm validation | Deprecated, not recommended |

---

## Future Work

The following items could be enhanced in future versions:

1. **PSS Hash/MGF Consistency Check**
   - Verify hashAlgorithm matches MGF1's hashAlgorithm (recommended but not required by RFC)

2. **OAEP P Label Validation**
   - Validate pSpecified P encoding (currently defaults to empty string)

3. **Additional OIDs**
   - Support for non-standard hash OIDs used by specific implementations

---

## Implementation Notes

### AlgorithmIdentifier Node Structure

```
signatureAlgorithm
  ├── algorithm: "SHA256-RSA"
  ├── oid: "1.2.840.113549.1.1.11"
  └── parameters
      ├── null: true      # ASN.1 NULL present
      └── absent: false   # parameters field absent
```

For algorithms with complex parameters (PSS, OAEP):
- `null: false` (not ASN.1 NULL)
- `absent: false` (parameters exist)
- Additional parameter fields would be added in future implementation

### Operators

| Operator | Purpose |
|----------|---------|
| `isNull` | Check if parameters is ASN.1 NULL |
| `isAbsent` | Check if parameters field is absent |

---

## References

- [RFC 4055](https://datatracker.ietf.org/doc/html/rfc4055) - Additional Algorithms and Identifiers for RSA Cryptography
- [RFC 5280 Section 4.1.2.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.3) - Signature Algorithm Identifier
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) - PKCS #1: RSA Cryptography Specifications Version 2.2