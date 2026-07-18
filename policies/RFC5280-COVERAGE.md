# RFC 5280 Policy Coverage

This document tracks the RFC 5280 requirements implemented by PCL's profile
policy. The policy is a certificate and CRL **linter**; it is not an
RFC-equivalent Section 6 certification-path or revocation validator.

Implementation order, architectural ownership, and completion criteria are
tracked in the [RFC 5280 conformance roadmap](../docs/RFC5280_ROADMAP.md).

`Covered` means an active rule has executable positive and negative behavior.
`Partial` means the rule checks only part of the normative requirement.
Parser behavior is credited only where a dedicated malformed-DER test exists.

---

## Certificate Fields (Section 4.1)

### 4.1.2.1 Version
| Requirement | Level | Rule |
|-------------|-------|------|
| Version MUST be 3 when extensions present | MUST | `version-v3-when-extensions` |
| Version SHOULD be ≥2 when UniqueIdentifier present | SHOULD | `version-v2-when-unique-id`, `version-v2-when-subject-unique-id` |
| Version SHOULD be 1 when only basic fields | SHOULD | (not enforced - all versions valid) |

### 4.1.2.2 Serial Number
| Requirement | Level | Rule |
|-------------|-------|------|
| Serial number MUST be positive integer | MUST | `serial-number-positive` |
| Serial number MUST be unique per CA | MUST | External issuance-database requirement; not enforceable from one path |
| Serial number MUST NOT exceed 20 octets | MUST | `serial-number-length` |

### 4.1.2.3 Signature
| Requirement | Level | Rule |
|-------------|-------|------|
| Algorithm MUST match outer signatureAlgorithm | MUST | `signature-algorithm-matches-tbs` |
| Signature MUST be valid | MUST | `signature-valid` (partial path semantics) |

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
| CA signing certificates MUST include Key Usage | MUST | `key-usage-present` (the policy treats root/intermediate inputs as certificate-signing roles) |
| When present, at least one bit MUST be set | MUST | `key-usage-has-at-least-one-bit` |
| CA Key Usage SHOULD be critical | SHOULD | `key-usage-critical-for-ca` |
| Certificate-signing keys MUST have keyCertSign | MUST | `ca-key-cert-sign` (root/intermediate role assumption) |
| Non-CA certs MUST NOT have keyCertSign | MUST NOT | `leaf-key-usage-valid` |

### 4.2.1.5 Policy Mappings
| Requirement | Level | Rule |
|-------------|-------|------|
| Policy Mappings SHOULD be critical | SHOULD | `policy-mappings-critical` |

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
| MUST be enforced in path validation | MUST | `name-constraints-valid` (partial: not a complete §6 implementation) |

### 4.2.1.11 Policy Constraints
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST be critical | MUST | `policy-constraints-critical` |

### 4.2.1.12 Extended Key Usage
| Requirement | Level | Rule |
|-------------|-------|------|
| Certificate used only for indicated purposes | MUST | Not currently enforced by `RFC5280.yaml` |

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

The following are independent lint checks, not an implementation of the RFC
5280 Section 6 state machine. PCL currently has no explicit trust-anchor,
initial-policy-set, policy-inhibition, or application-purpose inputs.

| Requirement | Status | Rule |
|-------------|--------|------|
| Signature verification | Partial | `signature-valid` |
| Issuer/Subject DN chaining | Partial | `issuer-matches-subject-for-root` and internal chain heuristics |
| Validity period checking | Covered as profile lint | `not-expired`, `not-yet-valid` |
| Path length constraints | Partial | `ca-path-len-valid` |
| Name constraints processing | Partial | `name-constraints-valid` |
| Policy processing | Not active | `certificatePolicyValid` operator exists, but the policy rule is disabled |
| Unknown critical extensions rejection | Partial | `no-unknown-critical-extensions` |

---

## CRL Profile (Section 5)

### CRL Fields
| Requirement | Level | Rule |
|-------------|-------|------|
| Signature valid | MUST | `crl-signed-by` |
| Inner and outer signature algorithms match | MUST | `crl-signature-algorithm-matches-tbs` |
| thisUpdate not in future | MUST | `crl-valid` |
| nextUpdate present and current | MUST | `crl-next-update-present`, `crl-valid` |
| Certificate revocation status | Partial | `cert-not-revoked` (absent CRL input is N/A; supplied but unverified, stale, unrelated, delta, or scoped data remains unknown and fails the operator) |

### CRL Extensions
| Requirement | Level | Rule |
|-------------|-------|------|
| AKI MUST NOT be critical | MUST NOT | `crl-aki-not-critical` |
| AKI keyIdentifier MUST be present | MUST | `crl-authority-key-identifier-present` |
| CRL Number MUST NOT be critical | MUST NOT | `crl-number-not-critical` |
| CRL Number MUST be present | MUST | `crl-number-present` |
| Delta CRL Indicator MUST be critical | MUST | `crl-delta-indicator-critical` |
| IDP MUST be critical | MUST | `crl-idp-critical` |

---

## OCSP (RFC 6960)

OCSP is a different standard and does not contribute to RFC 5280 coverage.
The legacy RFC 5280 bundle still contains these rules for compatibility; they
should be loaded from a separate RFC 6960 policy in the policy-splitting work.

| Requirement | Rule |
|-------------|------|
| Response within validity window | `ocspValid` |
| Response signature valid | `ocspValid` |
| Certificate not revoked | `notRevokedOCSP` |
| Certificate has Good status | `ocspGood` |

---

## Supplemental Rules (Not RFC 5280 Coverage)

Rules whose references begin with `LOCAL-`, plus RFC 6960, RFC 9549, PSL,
CA/B Forum, and reasonable-size constraints, are supplemental profile checks.
They must not be counted as RFC 5280 requirements.

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

The current policy does not claim complete coverage for:

- RFC 5280 Section 6 path-validation and CRL-validation state machines
- RFC 5280 Section 7 internationalized name comparison
- CA-wide issuance properties such as serial-number uniqueness
- ASN.1, time, URI, or name validation without an explicit parser/operator test
