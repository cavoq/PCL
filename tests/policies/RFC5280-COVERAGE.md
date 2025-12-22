# RFC 5280 Policy Coverage Analysis

This document tracks implementation coverage of [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) requirements.

---

## Certificate Profile (Section 4)

### 4.1 Basic Certificate Fields

#### 4.1.1 Certificate Fields

- [x] **tbsCertificate** - Parsed by Go x509
- [x] **signatureAlgorithm** - `signatureAlgorithmMatchesTBS`
- [x] **signatureValue** - `signedBy`

#### 4.1.2 TBSCertificate

##### 4.1.2.1 Version
- [x] Version MUST be v3 when extensions present - `version-v3`

##### 4.1.2.2 Serial Number
- [x] Serial number MUST be present - `serial-number-present`
- [x] Serial number MUST be positive - `serial-number-positive`
- [x] Serial number MUST be unique per CA - `serial-number-unique`
- [x] Serial number MUST NOT exceed 20 octets - `serial-number-length`

##### 4.1.2.3 Signature
- [x] Algorithm MUST match outer signatureAlgorithm - `signatureAlgorithmMatchesTBS`

##### 4.1.2.4 Issuer
- [x] Issuer MUST be present - `issuer-present`
- [x] Issuer MUST be non-empty - `issuer-not-empty`
- [ ] Issuer MUST use PrintableString or UTF8String encoding
- [ ] Issuer attribute types MUST be from allowed set

##### 4.1.2.5 Validity
- [x] notBefore MUST be before current time - `not-yet-valid`
- [x] notAfter MUST be after current time - `not-expired`
- [x] notBefore MUST be before notAfter - `validity-order-correct`
- [ ] Dates through 2049 MUST use UTCTime
- [ ] Dates in 2050 or later MUST use GeneralizedTime

##### 4.1.2.6 Subject
- [x] Subject MUST be present - `subject-present`
- [x] Subject MUST be non-empty for CA certificates - `subject-not-empty-for-ca`
- [ ] Subject MUST use PrintableString or UTF8String encoding
- [ ] Subject attribute types MUST be from allowed set

##### 4.1.2.7 Subject Public Key Info
- [x] RSA key size MUST be at least 2048 bits - `rsa-key-size-minimum`
- [x] RSA exponent MUST be odd - `rsa-exponent-valid`
- [x] RSA exponent SHOULD be 65537 or greater - `rsa-exponent-recommended`
- [x] ECDSA curve MUST be P-256, P-384, or P-521 - `ecdsa-curve-allowed`
- [x] Ed25519 MUST NOT have parameters - `ed25519-no-params`

##### 4.1.2.8 Unique Identifiers
- [x] Unique identifiers MUST NOT be used - `no-unique-identifiers`

##### 4.1.2.9 Extensions
- [x] Extensions section present (implied by v3)
- [x] Unknown critical extensions MUST cause rejection - `no-unknown-critical-extensions`

### 4.2 Certificate Extensions

#### 4.2.1 Standard Extensions

##### 4.2.1.1 Authority Key Identifier
- [x] AKI SHOULD be present for non-self-issued - `authority-key-identifier-present`
- [x] AKI keyIdentifier SHOULD match issuer SKI - `aki-matches-ski`
- [x] AKI MUST NOT be marked critical - `aki-not-critical`

##### 4.2.1.2 Subject Key Identifier
- [x] SKI SHOULD be present in all certificates - `subject-key-identifier-present`
- [x] SKI MUST NOT be marked critical - `ski-not-critical`

##### 4.2.1.3 Key Usage
- [x] Key Usage SHOULD be present - `key-usage-present`
- [x] Key Usage MUST be critical for CA certificates - `key-usage-critical-for-ca`
- [x] CA certificates MUST have keyCertSign - `ca-key-cert-sign`
- [x] Leaf certificates MUST NOT have keyCertSign - `leaf-key-usage-valid`
- [ ] digitalSignature required for signature verification
- [ ] keyEncipherment only valid for RSA key transport
- [ ] keyAgreement only valid for DH/ECDH

##### 4.2.1.4 Certificate Policies
- [ ] Certificate policies MAY be present
- [ ] If critical, only recognized policies allowed
- [ ] Policy qualifiers properly formed

##### 4.2.1.5 Policy Mappings
- [ ] Policy mappings MAY be present in CA certificates
- [x] MUST be critical if present - `policy-mappings-critical`

##### 4.2.1.6 Subject Alternative Name
- [x] SAN required if subject is empty - `san-required-if-empty-subject`
- [x] SAN MUST be critical if subject is empty - `san-critical-if-subject-empty`
- [ ] SAN entries properly formed (DNS, IP, email, URI)

##### 4.2.1.7 Issuer Alternative Name
- [ ] IAN MAY be present
- [x] IAN SHOULD NOT be marked critical - `ian-not-critical`

##### 4.2.1.8 Subject Directory Attributes
- [x] Subject directory attributes MUST NOT be critical - `subject-directory-attributes-not-critical`

##### 4.2.1.9 Basic Constraints
- [x] Basic Constraints SHOULD be present - `basic-constraints-present`
- [x] Basic Constraints MUST be critical for CA - `basic-constraints-critical-for-ca`
- [x] cA MUST be TRUE for CA certificates - `ca-basic-constraints`
- [x] cA MUST NOT be TRUE for leaf certificates - `leaf-not-ca`
- [x] pathLenConstraint properly enforced - `ca-path-len-valid`

##### 4.2.1.10 Name Constraints
- [ ] Name Constraints MAY be present in CA certificates
- [x] Name Constraints MUST be critical - `name-constraints-critical`
- [ ] Permitted/excluded subtrees properly formed

##### 4.2.1.11 Policy Constraints
- [ ] Policy Constraints MAY be present in CA certificates
- [x] Policy Constraints MUST be critical - `policy-constraints-critical`
- [ ] requireExplicitPolicy/inhibitPolicyMapping values valid

##### 4.2.1.12 Extended Key Usage
- [ ] EKU MAY be present
- [ ] EKU values from allowed set
- [ ] EKU consistent with Key Usage

##### 4.2.1.13 CRL Distribution Points
- [ ] CDP MAY be present
- [ ] CDP URIs properly formed

##### 4.2.1.14 Inhibit anyPolicy
- [ ] Inhibit anyPolicy MAY be present in CA certificates
- [x] Inhibit anyPolicy MUST be critical - `inhibit-any-policy-critical`

##### 4.2.1.15 Freshest CRL
- [ ] Freshest CRL MAY be present
- [x] Freshest CRL MUST NOT be critical - `freshest-crl-not-critical`

#### 4.2.2 Private Internet Extensions

##### 4.2.2.1 Authority Information Access
- [ ] AIA MAY be present
- [x] AIA MUST NOT be critical - `aia-not-critical`
- [ ] OCSP responder URI properly formed
- [ ] CA Issuers URI properly formed

##### 4.2.2.2 Subject Information Access
- [ ] SIA MAY be present
- [x] SIA MUST NOT be critical - `sia-not-critical`

---

## Certification Path Validation (Section 6)

### 6.1 Basic Path Validation

- [x] Signature verification - `signedBy`
- [x] Issuer/Subject matching - `issuedBy`
- [x] Validity period checking - `not-expired`, `not-yet-valid`
- [x] Path length constraints - `pathLenValid`
- [ ] Certificate validity within issuer validity
- [ ] Name constraints processing
- [ ] Policy processing
- [ ] CRL/OCSP status checking

---

## CRL Profile (Section 5)

### 5.1 CRL Fields

#### 5.1.1 CertificateList Fields
- [ ] **tbsCertList** - Parsed structure
- [ ] **signatureAlgorithm** - Matches outer algorithm
- [ ] **signatureValue** - Cryptographic validation

#### 5.1.2 TBSCertList

##### 5.1.2.1 Version
- [ ] Version MUST be v2 when extensions present

##### 5.1.2.2 Signature
- [ ] Algorithm MUST match outer signatureAlgorithm

##### 5.1.2.3 Issuer
- [ ] Issuer MUST be present and non-empty
- [ ] Issuer MUST match CA certificate subject

##### 5.1.2.4 This Update
- [ ] thisUpdate MUST be present
- [ ] thisUpdate MUST NOT be in the future

##### 5.1.2.5 Next Update
- [ ] nextUpdate SHOULD be present
- [ ] nextUpdate MUST be after thisUpdate

##### 5.1.2.6 Revoked Certificates
- [ ] Each entry contains serial number
- [ ] Each entry contains revocation date
- [ ] Optional CRL entry extensions

##### 5.1.2.7 Extensions
- [ ] Extensions section (v2 CRLs)

### 5.2 CRL Extensions

#### 5.2.1 Authority Key Identifier
- [ ] AKI SHOULD be present
- [ ] AKI MUST NOT be critical

#### 5.2.2 Issuer Alternative Name
- [ ] IAN MAY be present
- [ ] IAN MUST NOT be critical

#### 5.2.3 CRL Number
- [ ] CRL Number SHOULD be present
- [ ] CRL Number MUST NOT be critical
- [ ] CRL Number monotonically increasing

#### 5.2.4 Delta CRL Indicator
- [ ] Delta CRL Indicator indicates delta CRL
- [ ] Delta CRL Indicator MUST be critical

#### 5.2.5 Issuing Distribution Point
- [ ] IDP MAY be present
- [ ] IDP MUST be critical

#### 5.2.6 Freshest CRL
- [ ] Freshest CRL MAY be present
- [ ] Freshest CRL MUST NOT be critical

#### 5.2.7 Authority Information Access
- [ ] AIA MAY be present
- [ ] AIA MUST NOT be critical

### 5.3 CRL Entry Extensions

#### 5.3.1 Reason Code
- [ ] Reason code MAY be present
- [ ] Reason code MUST NOT be critical

#### 5.3.2 Invalidity Date
- [ ] Invalidity date MAY be present
- [ ] Invalidity date MUST NOT be critical

#### 5.3.3 Certificate Issuer
- [ ] Certificate Issuer for indirect CRLs
- [ ] Certificate Issuer MUST be critical

---

## Signature Algorithm Validation

### Allowed Algorithms
- [x] SHA-256 with RSA - `signature-algorithm-allowed`
- [x] SHA-384 with RSA - `signature-algorithm-allowed`
- [x] SHA-512 with RSA - `signature-algorithm-allowed`
- [x] ECDSA with SHA-256 - `signature-algorithm-allowed`
- [x] ECDSA with SHA-384 - `signature-algorithm-allowed`
- [x] ECDSA with SHA-512 - `signature-algorithm-allowed`
- [x] Ed25519 - `signature-algorithm-allowed`

### Prohibited Algorithms
- [x] MD5 with RSA - `signature-algorithm-not-weak`
- [x] SHA-1 with RSA - `signature-algorithm-not-weak`
- [x] DSA with SHA-1 - `signature-algorithm-not-weak`
- [x] ECDSA with SHA-1 - `signature-algorithm-not-weak`

---

## Legend

- [x] Implemented
- [ ] Not yet implemented
