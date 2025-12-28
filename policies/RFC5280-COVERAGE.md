# RFC 5280 Policy Coverage

This document tracks implementation of [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) requirements.

> Items marked **(parsing)** are validated by the x509 library during parsing.

---

## Certificate Fields (Section 4.1)

### 4.1.2.1 Version
| Requirement | Level | Rule |
|-------------|-------|------|
| Version MUST be 3 when extensions present | MUST | `version-v3` |

### 4.1.2.2 Serial Number
| Requirement | Level | Rule |
|-------------|-------|------|
| Serial number MUST be positive integer | MUST | `serial-number-positive` |
| Serial number MUST be unique per CA | MUST | `serial-number-unique` |
| Serial number MUST NOT exceed 20 octets | MUST | `serial-number-length` |

### 4.1.2.3 Signature
| Requirement | Level | Rule |
|-------------|-------|------|
| Algorithm MUST match outer signatureAlgorithm | MUST | `signatureAlgorithmMatchesTBS` |
| Signature MUST be valid | MUST | `signedBy` |

### 4.1.2.4 Issuer
| Requirement | Level | Rule |
|-------------|-------|------|
| Issuer MUST contain non-empty DN | MUST | `issuer-not-empty` |

### 4.1.2.5 Validity
| Requirement | Level | Rule |
|-------------|-------|------|
| Certificate MUST be within validity period | MUST | `not-expired`, `not-yet-valid` |
| notBefore MUST precede notAfter | MUST | `validity-order-correct` |

### 4.1.2.6 Subject
| Requirement | Level | Rule |
|-------------|-------|------|
| Subject MUST be non-empty for CA certs | MUST | `subject-not-empty-for-ca` |
| If subject empty, SAN MUST be present | MUST | `san-required-if-empty-subject` |

### 4.1.2.8 Unique Identifiers
| Requirement | Level | Rule |
|-------------|-------|------|
| Unique identifiers MUST NOT appear in conforming certs | MUST NOT | `no-unique-identifiers` |

---

## Extensions (Section 4.2)

### 4.2.1.1 Authority Key Identifier
| Requirement | Level | Rule |
|-------------|-------|------|
| AKI MUST be included (except self-signed) | MUST | `authority-key-identifier-present` |
| AKI MUST NOT be critical | MUST NOT | `aki-not-critical` |
| AKI SHOULD match issuer SKI | SHOULD | `aki-matches-ski` |

### 4.2.1.2 Subject Key Identifier
| Requirement | Level | Rule |
|-------------|-------|------|
| SKI MUST appear in CA certificates | MUST | `subject-key-identifier-present` |
| SKI MUST NOT be critical | MUST NOT | `ski-not-critical` |

### 4.2.1.3 Key Usage
| Requirement | Level | Rule |
|-------------|-------|------|
| Key Usage SHOULD be present | SHOULD | `key-usage-present` |
| Key Usage SHOULD be critical | SHOULD | `key-usage-critical-for-ca` |
| CA certs MUST have keyCertSign | MUST | `ca-key-cert-sign` |
| Non-CA certs MUST NOT have keyCertSign | MUST NOT | `leaf-key-usage-valid` |

### 4.2.1.5 Policy Mappings
| Requirement | Level | Rule |
|-------------|-------|------|
| Policy Mappings MUST be critical | MUST | `policy-mappings-critical` |

### 4.2.1.6 Subject Alternative Name
| Requirement | Level | Rule |
|-------------|-------|------|
| SAN MUST be present if subject empty | MUST | `san-required-if-empty-subject` |
| SAN MUST be critical if subject empty | MUST | `san-critical-if-subject-empty` |

### 4.2.1.7 Issuer Alternative Name
| Requirement | Level | Rule |
|-------------|-------|------|
| IAN SHOULD NOT be critical | SHOULD NOT | `ian-not-critical` |

### 4.2.1.8 Subject Directory Attributes
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST NOT be critical | MUST NOT | `subject-directory-attributes-not-critical` |

### 4.2.1.9 Basic Constraints
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST be in CA certificates | MUST | `basic-constraints-present` |
| MUST be critical in CA certs | MUST | `basic-constraints-critical-for-ca` |
| cA MUST be TRUE for CA certs | MUST | `ca-basic-constraints` |
| pathLenConstraint enforced | MUST | `ca-path-len-valid` |

### 4.2.1.10 Name Constraints
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST be critical | MUST | `name-constraints-critical` |
| MUST be enforced in path validation | MUST | `nameConstraintsValid` |

### 4.2.1.11 Policy Constraints
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST be critical | MUST | `policy-constraints-critical` |

### 4.2.1.12 Extended Key Usage
| Requirement | Level | Rule |
|-------------|-------|------|
| Certificate used only for indicated purposes | MUST | `ekuContains`, `ekuServerAuth`, `ekuClientAuth` |

### 4.2.1.13 CRL Distribution Points
| Requirement | Level | Rule |
|-------------|-------|------|
| SHOULD be non-critical | SHOULD | (not enforced) |

### 4.2.1.14 Inhibit anyPolicy
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST be critical | MUST | `inhibit-any-policy-critical` |

### 4.2.1.15 Freshest CRL
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST NOT be critical | MUST NOT | `freshest-crl-not-critical` |

### 4.2.2.1 Authority Information Access
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST NOT be critical | MUST NOT | `aia-not-critical` |

### 4.2.2.2 Subject Information Access
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST NOT be critical | MUST NOT | `sia-not-critical` |

---

## Path Validation (Section 6)

| Requirement | Level | Rule |
|-------------|-------|------|
| Signature verification | MUST | `signedBy` |
| Issuer/Subject DN chaining | MUST | `issuedBy` |
| Validity period checking | MUST | `not-expired`, `not-yet-valid` |
| Path length constraints | MUST | `pathLenValid` |
| Name constraints processing | MUST | `nameConstraintsValid` |
| Policy processing | MUST | `certificatePolicyValid` |
| Unknown critical extensions rejection | MUST | `noUnknownCriticalExtensions` |

---

## CRL Profile (Section 5)

### CRL Fields
| Requirement | Level | Rule |
|-------------|-------|------|
| Signature valid | MUST | `crlSignedBy` |
| thisUpdate not in future | MUST | `crlValid` |
| nextUpdate after thisUpdate | MUST | `crlValid`, `crlNotExpired` |
| Serial number not in revoked list | MUST | `notRevoked` |

### CRL Extensions
| Requirement | Level | Rule |
|-------------|-------|------|
| AKI MUST NOT be critical | MUST NOT | `crl-aki-not-critical` |
| CRL Number MUST NOT be critical | MUST NOT | `crl-number-not-critical` |
| Delta CRL Indicator MUST be critical | MUST | `crl-delta-indicator-critical` |
| IDP MUST be critical | MUST | `crl-idp-critical` |

---

## OCSP (RFC 6960)

| Requirement | Rule |
|-------------|------|
| Response within validity window | `ocspValid` |
| Response signature valid | `ocspValid` |
| Certificate not revoked | `notRevokedOCSP` |
| Certificate has Good status | `ocspGood` |

---

## Best Practices (Not RFC 5280)

The following rules enforce modern security practices beyond RFC 5280:

| Rule | Description |
|------|-------------|
| `rsa-key-size-minimum` | RSA keys >= 2048 bits |
| `rsa-exponent-valid` | RSA exponent is odd |
| `rsa-exponent-recommended` | RSA exponent >= 65537 |
| `ecdsa-curve-allowed` | ECDSA uses P-256/P-384/P-521 |
| `signature-algorithm-allowed` | Modern signature algorithms only |
| `signature-algorithm-not-weak` | No MD5/SHA-1 signatures |

---

## Extension OID Reference

| Extension | OID | Path |
|-----------|-----|------|
| Authority Key Identifier | 2.5.29.35 | `certificate.extensions.2.5.29.35.critical` |
| Subject Key Identifier | 2.5.29.14 | `certificate.extensions.2.5.29.14.critical` |
| Key Usage | 2.5.29.15 | `certificate.extensions.2.5.29.15.critical` |
| Subject Alternative Name | 2.5.29.17 | `certificate.extensions.2.5.29.17.critical` |
| Issuer Alternative Name | 2.5.29.18 | `certificate.extensions.2.5.29.18.critical` |
| Basic Constraints | 2.5.29.19 | `certificate.extensions.2.5.29.19.critical` |
| Name Constraints | 2.5.29.30 | `certificate.extensions.2.5.29.30.critical` |
| Certificate Policies | 2.5.29.32 | `certificate.extensions.2.5.29.32.critical` |
| Policy Mappings | 2.5.29.33 | `certificate.extensions.2.5.29.33.critical` |
| Policy Constraints | 2.5.29.36 | `certificate.extensions.2.5.29.36.critical` |
| Extended Key Usage | 2.5.29.37 | `certificate.extensions.2.5.29.37.critical` |
| Freshest CRL | 2.5.29.46 | `certificate.extensions.2.5.29.46.critical` |
| Inhibit anyPolicy | 2.5.29.54 | `certificate.extensions.2.5.29.54.critical` |
| Authority Information Access | 1.3.6.1.5.5.7.1.1 | `certificate.extensions.1.3.6.1.5.5.7.1.1.critical` |
| Subject Information Access | 1.3.6.1.5.5.7.1.11 | `certificate.extensions.1.3.6.1.5.5.7.1.11.critical` |

---

## Out of Scope

Handled by the x509 parsing library:
- ASN.1 encoding validation
- UTCTime/GeneralizedTime encoding rules
- URI/name format validation
