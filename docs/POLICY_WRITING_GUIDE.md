# Policy Rule Writing Guide

This document provides a comprehensive guide for writing policy rules in PCL (Policy-based Certificate Linter).

## Table of Contents

- [Overview](#overview)
- [Policy File Structure](#policy-file-structure)
- [Rule Structure](#rule-structure)
- [Target Paths](#target-paths)
- [Operators](#operators)
- [Severity Levels](#severity-levels)
- [Certificate Type Filtering](#certificate-type-filtering)
- [Conditional Rules (when)](#conditional-rules-when)
- [Best Practices](#best-practices)
- [Examples](#examples)

---

## Overview

PCL uses YAML-based policy files to define validation rules for X.509 certificates, CRLs (Certificate Revocation Lists), and OCSP responses. Each policy file contains a list of rules that are evaluated against PKI objects.

Key concepts:
- **Policy**: A collection of rules for validating PKI objects
- **Rule**: A single validation check with a target, operator, and expected result
- **Target**: A path to a specific field in the PKI object's data structure
- **Operator**: The comparison or validation logic to apply
- **Evaluation Context**: Runtime context containing certificate chain, CRLs, OCSP responses, etc.

### Supported Standards

PCL policies can validate compliance with various PKI standards:
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - Internet X.509 PKI Certificate and CRL Profile
- [RFC 4055](https://datatracker.ietf.org/doc/html/rfc4055) - Additional Algorithms and Identifiers for RSA Cryptography
- [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480) - Elliptic Curve Cryptography Subject Public Key Information
- [RFC 5758](https://datatracker.ietf.org/doc/html/rfc5758) - Additional Algorithms and Identifiers for DSA and ECDSA
- [RFC 5759](https://datatracker.ietf.org/doc/html/rfc5759) - DSA and ECDSA Algorithm Identifiers for CRLs
- [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960) - Online Certificate Status Protocol (OCSP)
- CA/Browser Forum Baseline Requirements (BR)
- CA/Browser Forum EV Guidelines
- CA/Browser Forum SMIME BR
- CA/Browser Forum Code Signing BR

---

## Policy File Structure

```yaml
id: policy-name           # Required: Unique identifier for the policy
version: "1.0"            # Optional: Policy version

rules:
  - id: rule-1
    ...
  - id: rule-2
    ...
```

### Metadata Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique policy identifier (e.g., `RFC5280`, `CA-Browser-BR`) |
| `version` | No | Version string for the policy |

---

## Rule Structure

Each rule has the following structure:

```yaml
- id: rule-id                    # Required: Unique rule identifier
  reference: RFC5280 4.1.2.1      # Optional: Reference to specification section
  target: certificate.version     # Required: Path to the field to check
  operator: eq                    # Required: Operator to apply
  operands: [3]                   # Required for some operators: Values to compare
  severity: error                 # Required: error, warning, or info
  appliesTo: [leaf, intermediate] # Optional: Certificate types this rule applies to
  when:                           # Optional: Precondition that must be met
    target: certificate.extensions
    operator: present
```

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique rule identifier within the policy |
| `reference` | No | Specification reference (RFC section, BR section, etc.) |
| `target` | Yes | Path to the field to validate (see Target Paths) |
| `operator` | Yes | Comparison/validation operator (see Operators) |
| `operands` | Some required | Values for operators that need them |
| `severity` | Yes | `error`, `warning`, or `info` |
| `appliesTo` | No | Types this rule applies to (see Certificate Type Filtering) |
| `when` | No | Precondition that must be true before evaluating the rule |

---

## Target Paths

Target paths use dot notation to navigate the node tree structure. The tree root is named by input type:

- `certificate.xxx` - Certificate fields
- `crl.xxx` - CRL fields
- `ocsp.xxx` - OCSP response fields

### Most Common Target Paths

Based on actual policy usage, these are the most frequently used target paths:

| Target Path | Usage Count | Description |
|-------------|-------------|-------------|
| `certificate.extKeyUsage` | 55 | Extended Key Usage extension |
| `certificate.subjectPublicKeyInfo.algorithm.oid` | 39 | Public key algorithm OID |
| `certificate.subjectAltName.dNSName` | 35 | SAN DNS names |
| `certificate.signatureAlgorithm.oid` | 29 | Signature algorithm OID |
| `certificate.subjectPublicKeyInfo.algorithm.parameters.namedCurve` | 22 | ECDSA curve OID |
| `certificate.subjectPublicKeyInfo.algorithm.algorithm` | 21 | Algorithm name (RSA, ECDSA) |
| `certificate.subject.commonName` | 19 | Subject CN |
| `certificate.tbsSignatureAlgorithm.oid` | 16 | TBSCertificate signature algorithm |
| `certificate.signedCertificateTimestamps` | 16 | SCT list |
| `crl` | 15 | CRL root (for CRL operators) |

### Certificate Target Paths

#### Basic Fields
```
certificate.version              # Certificate version (1, 2, 3)
certificate.serialNumber        # Serial number node
certificate.serialNumber.value  # Serial number value (string)
certificate.issuer              # Issuer DN node
certificate.subject             # Subject DN node
certificate.validity.notBefore  # NotBefore time
certificate.validity.notAfter   # NotAfter time
certificate.signatureAlgorithm  # Signature algorithm node
certificate.signatureAlgorithm.oid    # Algorithm OID
certificate.tbsSignatureAlgorithm      # TBSCertificate signature algorithm
```

#### Issuer/Subject DN Fields
```
certificate.issuer.commonName          # Common Name (CN)
certificate.issuer.countryName         # Country (C)
certificate.issuer.organizationName    # Organization (O)
certificate.issuer.organizationalUnitName  # Organizational Unit (OU)
certificate.issuer.stateOrProvinceName     # State/Province (ST)
certificate.issuer.localityName            # Locality (L)
certificate.issuer.domainComponent         # Domain Component (DC)
```

#### Extensions (by OID or friendly name)
```
certificate.extensions.2.5.29.14        # subjectKeyIdentifier extension
certificate.extensions.2.5.29.15        # keyUsage extension
certificate.extensions.2.5.29.19        # basicConstraints extension
certificate.extensions.2.5.29.35        # authorityKeyIdentifier extension
certificate.extensions.2.5.29.37        # extKeyUsage extension
certificate.extensions.1.3.6.1.5.5.7.1.1  # authorityInformationAccess
certificate.extensions.2.5.29.31        # cRLDistributionPoints
certificate.extensions.2.5.29.17        # subjectAltName
certificate.extensions.2.5.29.32        # certificatePolicies
certificate.extensions.2.5.29.30        # nameConstraints
```

#### Common Extension Fields
```
certificate.subjectKeyIdentifier        # SKI value (hex string)
certificate.authorityKeyIdentifier      # AKI value (hex string)
certificate.basicConstraints.cA         # cA boolean
certificate.basicConstraints.pathLenConstraint  # Path length
certificate.keyUsage                    # KeyUsage node
certificate.keyUsage.digitalSignature   # KeyUsage bit (boolean)
certificate.keyUsage.keyCertSign        # KeyUsage bit (boolean)
certificate.keyUsage.cRLSign            # KeyUsage bit (boolean)
certificate.extKeyUsage                  # ExtKeyUsage node
certificate.extKeyUsage.serverAuth       # EKU presence (boolean)
certificate.extKeyUsage.clientAuth       # EKU presence (boolean)
certificate.extKeyUsage.codeSigning      # EKU presence (boolean)
certificate.extKeyUsage.emailProtection  # EKU presence (boolean)
certificate.extKeyUsage.timeStamping     # EKU presence (boolean)
certificate.extKeyUsage.ocspSigning      # EKU presence (boolean)
```

#### Certificate Policies Fields
```
certificate.certificatePolicies        # Certificate Policies node
certificate.certificatePolicies.evPolicy     # EV policy OID (boolean)
certificate.certificatePolicies.ovPolicy     # OV policy OID (boolean)
certificate.certificatePolicies.dvPolicy     # DV policy OID (boolean)
certificate.certificatePolicies.smimeMailboxLegacy  # SMIME mailbox legacy (boolean)
```

#### SubjectPublicKeyInfo
```
certificate.subjectPublicKeyInfo.algorithm.algorithm  # Algorithm name (RSA, ECDSA)
certificate.subjectPublicKeyInfo.algorithm.oid        # Algorithm OID
certificate.subjectPublicKeyInfo.publicKey.keySize    # RSA key size (bits)
certificate.subjectPublicKeyInfo.publicKey.curve      # ECDSA curve name (P-256, P-384, P-521)
certificate.subjectPublicKeyInfo.algorithm.parameters  # Algorithm parameters node
certificate.subjectPublicKeyInfo.algorithm.parameters.namedCurve  # ECDSA curve OID
certificate.subjectPublicKeyInfo.algorithm.parameters.null        # NULL flag (boolean)
```

#### AIA (Authority Information Access)
```
certificate.extensions.authorityInfoAccess           # AIA extension node
certificate.extensions.authorityInfoAccess.accessDescriptions  # AccessDescriptions array
certificate.extensions.authorityInfoAccess.accessDescriptions.0.accessMethod  # OID
certificate.extensions.authorityInfoAccess.accessDescriptions.0.accessLocation.type  # GeneralName type
certificate.extensions.authorityInfoAccess.accessDescriptions.0.accessLocation.scheme  # URI scheme
certificate.extensions.authorityInfoAccess.accessDescriptions.0.accessLocation.value  # URI value
certificate.ocspURL           # OCSP URL from AIA
certificate.caIssuersURL      # CA Issuers URL from AIA
```

#### CRL Distribution Points
```
certificate.extensions.cRLDistributionPoints           # CRL DP extension node
certificate.extensions.cRLDistributionPoints.distributionPoints  # DistributionPoints array
certificate.extensions.cRLDistributionPoints.distributionPoints.0.distributionPoint.fullName.generalNames.0.scheme  # URI scheme
certificate.cRLDistributionPoints      # Legacy shortcut for CRL DP URLs
```

#### SCT (Signed Certificate Timestamps)
```
certificate.signedCertificateTimestamps  # SCT list node (count = number of SCTs)
```

#### SAN (Subject Alternative Name)
```
certificate.subjectAltName.dNSName              # DNS names
certificate.subjectAltName.rfc822Name           # Email addresses
certificate.subjectAltName.uniformResourceIdentifier  # URIs
certificate.subjectAltName.iPAddress            # IP addresses
```

### CRL Target Paths

```
crl.issuer                    # CRL issuer DN
crl.thisUpdate                 # ThisUpdate time
crl.nextUpdate                 # NextUpdate time (may be zero)
crl.isCACRL                   # Boolean: true if issuer is CA certificate
crl.signatureAlgorithm         # Signature algorithm node
crl.signatureAlgorithm.oid     # Algorithm OID
crl.signatureAlgorithm.parameters      # Parameters node
crl.tbsSignatureAlgorithm      # TBSCertList signature algorithm
crl.crlNumber                  # CRL number (string)
crl.authorityKeyIdentifier     # AKI value
crl.revokedCertificates        # Revoked certificates list
crl.revokedCertificates.0.serialNumber     # Serial number of revoked cert
crl.revokedCertificates.0.revocationDate   # Revocation time
crl.revokedCertificates.0.extensions       # Entry extensions
crl.extensions.2.5.29.20       # crlNumber extension
crl.extensions.2.5.29.35       # authorityKeyIdentifier extension
```

### OCSP Target Paths

```
ocsp.status                    # Response status (good, revoked, unknown)
ocsp.signatureAlgorithm        # Signature algorithm node
ocsp.signatureAlgorithm.oid    # Algorithm OID
ocsp.tbsSignatureAlgorithm     # TBSResponseData signature algorithm
ocsp.responderID               # Responder ID node
ocsp.producedAt                # ProducedAt time
ocsp.thisUpdate                # ThisUpdate time
ocsp.nonce                     # nonce extension node
ocsp.nonce.present             # nonce presence (boolean)
```

---

## Operators

PCL provides 107 operators organized by category. All operators are defined in `internal/operator/operator.go`.

### Operator Categories

1. **Presence Operators** - Check if fields exist or are empty
2. **Equality Operators** - Compare values for equality or membership
3. **Comparison Operators** - Numeric comparisons
4. **String Operators** - Regex matching and length checks
5. **Date Operators** - Time validation
6. **Extension Operators** - Criticality and structure checks
7. **EKU Operators** - Extended Key Usage validation
8. **Chain Operators** - Certificate chain validation
9. **CRL Operators** - CRL structure and revocation checking
10. **OCSP Operators** - OCSP response validation
11. **Component Operators** - Multi-valued field validation
12. **CIDR Operators** - IP address range checking
13. **PSL/TLD Operators** - Domain and TLD validation
14. **ASN.1 Time Operators** - Encoding format validation
15. **ASN.1 String Operators** - String type validation
16. **Unique Value Operators** - Duplicate checking
17. **DER Encoding Operators** - Byte-for-byte validation

### 1. Presence Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `present` | None | Returns true if target exists in the tree |
| `absent` | None | Returns true if target does NOT exist in the tree |
| `isEmpty` | None | Returns true if target value is empty |
| `notEmpty` | None | Returns true if target value is NOT empty |
| `isNull` | None | Returns true if node exists with `null=true` child (explicit NULL encoding) |

**Usage Frequency**: `present` (157), `absent` (94)

**Examples:**
```yaml
# Check extension is present (most common pattern)
- id: ski-present
  target: certificate.subjectKeyIdentifier
  operator: present
  severity: error

# Check extension is absent
- id: no-issuer-unique-id
  target: certificate.issuerUniqueID
  operator: absent
  severity: error

# RSA parameters MUST be NULL (RFC 4055)
- id: rsa-params-null
  target: certificate.signatureAlgorithm.parameters
  operator: isNull
  severity: error
  when:
    target: certificate.signatureAlgorithm.oid
    operator: in
    operands:
      - "1.2.840.113549.1.1.1"
      - "1.2.840.113549.1.1.11"

# ECDSA parameters MUST be absent (RFC 5758)
- id: ecdsa-params-absent
  target: certificate.signatureAlgorithm.parameters
  operator: absent
  severity: error
  when:
    target: certificate.signatureAlgorithm.oid
    operator: in
    operands:
      - "1.2.840.10045.4.3.2"
      - "1.2.840.10045.4.3.3"
```

### 2. Equality Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `eq` | [value] | Returns true if target equals operand |
| `neq` | [value] | Returns true if target does NOT equal operand |
| `in` | [value1, value2, ...] | Returns true if target is in the list |
| `notIn` | [value1, value2, ...] | Returns true if target is NOT in the list |
| `contains` | [value] | Returns true if target contains the specified value |
| `matches` | [fieldPath] | Returns true if target equals the value at another field path |

**Usage Frequency**: `eq` (136+), `in` (31+), `neq` (7)

**Examples:**
```yaml
# Check version is 3 (most common eq usage)
- id: version-v3
  target: certificate.version
  operator: eq
  operands: [3]
  severity: error

# Check OID is in allowed list
- id: ecdsa-curve-valid
  target: certificate.subjectPublicKeyInfo.algorithm.parameters.namedCurve
  operator: in
  operands:
    - "1.2.840.10045.3.1.7"   # P-256
    - "1.3.132.0.34"          # P-384
    - "1.3.132.0.35"          # P-521
  severity: error

# Check basicConstraints.cA is false
- id: leaf-not-ca
  target: certificate.basicConstraints.cA
  operator: eq
  operands: [false]
  severity: error
  appliesTo: [leaf]

# Check signature algorithm matches tbsSignatureAlgorithm
- id: sig-alg-matches-tbs
  target: certificate.signatureAlgorithm.oid
  operator: matches
  operands: ["certificate.tbsSignatureAlgorithm.oid"]
  severity: error
```

### 3. Comparison Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `gte` | [number] | Returns true if target >= operand (numeric comparison) |
| `gt` | [number] | Returns true if target > operand |
| `lte` | [number] | Returns true if target <= operand |
| `lt` | [number] | Returns true if target < operand |
| `positive` | None | Returns true if target is a positive number |
| `odd` | None | Returns true if target is an odd number |

**Usage Frequency**: `gte` (21), `lte` (4)

**Examples:**
```yaml
# RSA key size at least 2048 bits (common pattern)
- id: rsa-key-size-min
  target: certificate.subjectPublicKeyInfo.publicKey.keySize
  operator: gte
  operands: [2048]
  severity: error
  when:
    target: certificate.subjectPublicKeyInfo.algorithm.algorithm
    operator: eq
    operands: [RSA]

# Serial number positive
- id: serial-positive
  target: certificate.serialNumber.value
  operator: positive
  severity: error
```

### 4. String Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `regex` | [pattern] | Returns true if target matches regex pattern |
| `notRegex` | [pattern] | Returns true if target does NOT match regex pattern |
| `minLength` | [count] | Returns true if node has at least N children/values |
| `maxLength` | [count] | Returns true if node has at most N children/values |

**Usage Frequency**: `regex` (17), `notRegex` (19), `maxLength` (17), `minLength` (6)

**Examples:**
```yaml
# Check subject does NOT contain underscore
- id: no-underscore-in-cn
  target: certificate.subject.commonName
  operator: notRegex
  operands: ["_"]
  severity: warning

# Check at least 2 SCTs present
- id: sct-min-2-logs
  target: certificate.signedCertificateTimestamps
  operator: minLength
  operands: [2]
  severity: error

# Serial number length <= 20 bytes
- id: serial-number-max-length
  target: certificate.serialNumber
  operator: maxLength
  operands: [20]
  severity: warning
```

### 5. Date Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `before` | None | Returns true if target date is before current time |
| `after` | [date] | Returns true if target date is after specified date (or current time if empty) |
| `validityOrderCorrect` | None | Returns true if notBefore < notAfter |
| `validityDays` | [days] | Returns true if validity period <= N days |
| `dateDiff` | [{start, end, maxDays, maxMonths, minHours}] | Returns true if date difference is within limits |

**Usage Frequency**: `validityDays` (9), `dateDiff` (3), `after` (8)

**Examples:**
```yaml
# Certificate must not be expired
- id: cert-not-expired
  target: certificate.validity.notAfter
  operator: after
  severity: error

# Subscriber cert validity <= 398 days
- id: subscriber-validity-max
  target: certificate.validity
  operator: validityDays
  operands: [398]
  severity: error
  appliesTo: [leaf]

# CRL nextUpdate within 10 days
- id: crl-nextupdate-10-days
  target: crl
  operator: dateDiff
  operands:
    - start: thisUpdate
      end: nextUpdate
      maxDays: 10
  severity: error
```

### 6. Extension Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `isCritical` | None | Returns true if the extension is marked critical |
| `notCritical` | None | Returns true if the extension is NOT marked critical |
| `noUnknownCriticalExtensions` | None | Returns true if no unhandled critical extensions exist |

**Examples:**
```yaml
# SKI must not be critical
- id: ski-not-critical
  target: certificate.extensions.2.5.29.14
  operator: notCritical
  severity: error

# basicConstraints must be critical for CA
- id: ca-bc-critical
  target: certificate.extensions.2.5.29.19
  operator: isCritical
  severity: error
  appliesTo: [root, intermediate]
```

### 7. EKU Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `ekuContains` | [ekuName] | Returns true if extKeyUsage contains the specified EKU |
| `ekuNotContains` | [ekuName] | Returns true if extKeyUsage does NOT contain the specified EKU |
| `ekuServerAuth` | None | Returns true if extKeyUsage contains serverAuth |
| `ekuClientAuth` | None | Returns true if extKeyUsage contains clientAuth |

**Usage Frequency**: `ekuContains` (48)

**EKU names**: `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`

**Examples:**
```yaml
# Subscriber must have serverAuth EKU
- id: subscriber-serverauth-eku
  target: certificate.extKeyUsage
  operator: ekuContains
  operands: [serverAuth]
  severity: error
  appliesTo: [leaf]
```

### 8. Key Usage Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `keyUsageCA` | None | Returns true if keyUsage has correct CA bits |
| `keyUsageLeaf` | None | Returns true if keyUsage has correct leaf bits |
| `sanRequiredIfEmptySubject` | None | Returns true if SAN is present when subject is empty |

**Examples:**
```yaml
# CA keyUsage validation
- id: ca-key-usage
  target: certificate.keyUsage
  operator: keyUsageCA
  severity: error
  appliesTo: [root, intermediate]
```

### 9. Certificate Chain Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `signatureValid` | None | Returns true if certificate signature is valid |
| `signatureAlgorithmMatchesTBS` | None | Returns true if signatureAlgorithm matches tbsSignatureAlgorithm |
| `issuedBy` | None | Returns true if certificate's issuer DN matches issuer's subject DN |
| `akiMatchesSki` | None | Returns true if AKI matches issuer's SKI |
| `pathLenValid` | None | Returns true if pathLenConstraint is valid for chain position |
| `serialNumberUnique` | None | Returns true if serial number is unique within the chain |
| `noUniqueIdentifiers` | None | Returns true if issuerUniqueID and subjectUniqueID are absent |

**Examples:**
```yaml
# Verify signature is valid
- id: signature-valid
  target: certificate
  operator: signatureValid
  severity: error

# Verify AKI matches issuer's SKI
- id: aki-matches-ski
  target: certificate
  operator: akiMatchesSki
  severity: warning
```

### 10. CRL Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `crlValid` | None | Returns true if CRL is valid (time check) |
| `crlNotExpired` | None | Returns true if CRL has not expired |
| `crlSignedBy` | None | Returns true if CRL signature is valid |
| `notRevoked` | None | Returns true if certificate is not in CRL's revoked list |

**Examples:**
```yaml
- id: crl-valid
  target: crl
  operator: crlValid
  severity: error

- id: cert-not-revoked
  target: certificate
  operator: notRevoked
  severity: error
```

### 11. OCSP Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `ocspValid` | None | Returns true if OCSP response is valid |
| `notRevokedOCSP` | None | Returns true if OCSP status is not "revoked" |
| `ocspGood` | None | Returns true if OCSP status is explicitly "Good" |

**Examples:**
```yaml
- id: ocsp-response-valid
  target: ocsp
  operator: ocspValid
  severity: error
```

### 12. Every Operator (Array Iteration)

The `every` operator checks that ALL elements in an array satisfy a condition.

| Operator | Operands | Description |
|----------|----------|-------------|
| `every` | [{path, operator, operands, skipMissing}] | Iterates array elements and checks each |

**Usage Frequency**: `every` (14)

**Parameters:**
- `path`: Sub-path relative to each element (supports `*` wildcard)
- `operator`: Inner operator name
- `operands`: Operands for the inner operator
- `skipMissing`: Skip elements where path doesn't exist (default: false)

**Examples:**
```yaml
# All CRL entries must have valid reason codes
- id: crl-entries-valid-reason
  target: crl.revokedCertificates
  operator: every
  operands:
    path: extensions.2.5.29.21.value
    operator: in
    operands: [0, 1, 2, 3, 4, 5, 6, 8, 9, 10]
  severity: warning
  when:
    target: crl.revokedCertificates
    operator: present

# All CRL DP URIs must use HTTP
- id: crl-dp-http-uri
  target: certificate.extensions.cRLDistributionPoints.distributionPoints
  operator: every
  operands:
    path: "*.distributionPoint.fullName.generalNames.*.scheme"
    operator: eq
    operands: ["http"]
  severity: error
  when:
    target: certificate.extensions.cRLDistributionPoints
    operator: present
```

### 13. Path Validation Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `nameConstraintsValid` | None | Returns true if names are valid against chain's constraints |
| `certificatePolicyValid` | None | Returns true if policy OIDs are valid through chain |

### 14. Component Operators (Multi-Valued Fields)

| Operator | Operands | Description |
|----------|----------|-------------|
| `componentMaxLength` | [length, separator] | Each component has at most N characters |
| `componentMinLength` | [length, separator] | Each component has at least N characters |
| `componentRegex` | [pattern] | Each component matches regex |
| `componentNotRegex` | [pattern] | Each component does NOT match regex |
| `anyComponentMatches` | [pattern] | ANY component matches regex |
| `noComponentMatches` | [pattern] | NO component matches regex |

**Usage Frequency**: `componentNotRegex` (12)

**Examples:**
```yaml
# DNS names must not contain wildcard
- id: san-no-wildcard
  target: certificate.subjectAltName.dNSName
  operator: noComponentMatches
  operands: ["^\\*"]
  severity: warning
```

### 15. CIDR Operators (IP Address)

| Operator | Operands | Description |
|----------|----------|-------------|
| `componentInCIDR` | [cidr1, cidr2, ...] | Each IP is in any CIDR range |
| `componentNotInCIDR` | [cidr1, cidr2, ...] | Each IP is NOT in any CIDR range |

**Examples:**
```yaml
# SAN IP addresses must not be in reserved ranges
- id: no-reserved-ipv4
  target: certificate.subjectAltName.iPAddress
  operator: componentNotInCIDR
  operands:
    - "10.0.0.0/8"
    - "127.0.0.0/8"
    - "192.168.0.0/16"
  severity: error
```

### 16. PSL/TLD Operators (Domain Validation)

| Operator | Operands | Description |
|----------|----------|-------------|
| `tldRegistered` | None | TLD is in IANA Root Zone Database |
| `tldNotRegistered` | None | TLD is NOT registered |
| `isPublicSuffix` | None | Domain is a public suffix |
| `isNotPublicSuffix` | None | Domain is NOT a public suffix |
| `componentTLDRegistered` | None | Each domain's TLD is registered |
| `componentTLDNotRegistered` | None | Each domain's TLD is NOT registered |
| `componentIsPublicSuffix` | None | Any domain is a public suffix |
| `componentNotPublicSuffix` | None | All domains are NOT public suffixes |

**Examples:**
```yaml
# No internal names (BR 4.2.2)
- id: no-internal-names
  target: certificate.subjectAltName.dNSName
  operator: componentTLDRegistered
  severity: error
```

### 17. ASN.1 Time Format Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `utctimeHasSeconds` | None | UTCTime includes seconds |
| `utctimeHasZulu` | None | UTCTime ends with 'Z' |
| `generalizedTimeHasZulu` | None | GeneralizedTime ends with 'Z' |
| `generalizedTimeNoFraction` | None | No fractional seconds |
| `isUTCTime` | None | Field uses UTCTime encoding |
| `isGeneralizedTime` | None | Field uses GeneralizedTime encoding |

### 18. ASN.1 String Type Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `isIA5String` | None | Field uses IA5String encoding (ASCII) |
| `isPrintableString` | None | Field uses PrintableString encoding |
| `isUTF8String` | None | Field uses UTF8String encoding |
| `validIA5String` | None | String contains only valid IA5String chars (ASCII, 0-127) |
| `validPrintableString` | None | String contains only valid PrintableString chars (A-Z, a-z, 0-9, + specific specials) |
| `utf8NoBom` | None | UTF-8 string has no BOM |
| `containsBOM` | None | String contains BOM |

**Usage Frequency**: `validIA5String` (4), `isIA5String`, `isUTF8String` (for encoding type checks)

### 19. Unique Value Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `uniqueValues` | None | All values in array are unique |
| `uniqueChildren` | None | All children have unique content |

### 20. DER Encoding Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `derEqualsHex` | [hexString] | DER encoding matches expected hex bytes |

**Usage Frequency**: `derEqualsHex` (8)

### 21. Subject DN Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `noDuplicateAttributes` | None | Subject DN has no duplicate attributes |

---

## Severity Levels

| Severity | Description | Behavior |
|----------|-------------|----------|
| `error` | MUST requirement violation | FAIL results in policy FAIL |
| `warning` | SHOULD requirement violation | FAIL results in policy WARN |
| `info` | MAY/NOT RECOMMENDED | FAIL does not affect verdict |

---

## Certificate Type Filtering

The `appliesTo` field filters rules by certificate type or input type.

### Certificate Types (Roles)

| Type | Description |
|------|-------------|
| `leaf` | End-entity (subscriber) certificate |
| `intermediate` | Subordinate CA certificate |
| `root` | Self-signed root CA certificate |
| `ocspSigning` | OCSP responder certificate |

### Input Types

| Type | Description |
|------|-------------|
| `crl` | Certificate Revocation List |
| `ocsp` | OCSP response |

**Important:** Certificate types are roles (leaf, intermediate, root, ocspSigning). Do NOT use `cert` as a value - it is not valid.

**Examples:**
```yaml
# Apply only to leaf certificates
- id: subscriber-serverauth-eku
  target: certificate.extKeyUsage
  operator: ekuContains
  operands: [serverAuth]
  severity: error
  appliesTo: [leaf]

# Apply to CA certificates
- id: ca-key-cert-sign
  target: certificate.keyUsage.keyCertSign
  operator: present
  severity: error
  appliesTo: [root, intermediate]

# Apply only to CRL inputs
- id: crl-validity-check
  target: crl
  operator: crlValid
  severity: error
  appliesTo: [crl]
```

---

## Conditional Rules (when)

The `when` clause adds a precondition. If false, the rule is skipped.

**Common Use Cases:**

**1. Algorithm-specific rules:**
```yaml
- id: rsa-key-size-min
  target: certificate.subjectPublicKeyInfo.publicKey.keySize
  operator: gte
  operands: [2048]
  severity: error
  when:
    target: certificate.subjectPublicKeyInfo.algorithm.algorithm
    operator: eq
    operands: [RSA]
```

**2. Extension conditional checks:**
```yaml
- id: crl-dp-http-scheme
  target: certificate.cRLDistributionPoints.0
  operator: regex
  operands: ["^http://"]
  severity: error
  when:
    target: certificate.cRLDistributionPoints
    operator: present
```

---

## Best Practices

### Rule Naming

Use descriptive, consistent naming:
- Format: `<POLICY>_<SECTION>_<CHECK>`
- Example: `RFC5280_4_1_2_1_VERSION_V3`

### Include References

Always include specification references:
```yaml
- id: subscriber-serverauth-eku
  reference: BR 7.1.2.7.10
  ...
```

### Severity Selection

- `error`: MUST requirements
- `warning`: SHOULD requirements
- `info`: MAY requirements or informational

### Use appliesTo Appropriately

Use `appliesTo` to avoid confusing SKIP messages:
```yaml
# Without appliesTo: will SKIP on CA certs
- id: subscriber-not-ca
  target: certificate.basicConstraints.cA
  operator: eq
  operands: [false]
  severity: error
  appliesTo: [leaf]  # Clear: only evaluated on leaf
```

---

## Examples

### Complete Policy Example

```yaml
id: example-policy
version: "1.0"

rules:
  # Certificate Structure
  - id: version-v3
    reference: RFC5280 4.1.2.1
    target: certificate.version
    operator: eq
    operands: [3]
    severity: error

  # Extensions
  - id: ski-present
    reference: RFC5280 4.2.1.2
    target: certificate.subjectKeyIdentifier
    operator: present
    severity: warning
    appliesTo: [root, intermediate]

  - id: ski-not-critical
    reference: RFC5280 4.2.1.2
    target: certificate.extensions.2.5.29.14.critical
    operator: eq
    operands: [false]
    severity: error

  # Basic Constraints
  - id: leaf-not-ca
    reference: RFC5280 4.2.1.9
    target: certificate.basicConstraints.cA
    operator: eq
    operands: [false]
    severity: error
    appliesTo: [leaf]

  # Key Usage
  - id: ca-key-cert-sign
    reference: RFC5280 4.2.1.3
    target: certificate.keyUsage.keyCertSign
    operator: present
    severity: error
    appliesTo: [root, intermediate]

  # Algorithm-Specific
  - id: rsa-key-size-min
    reference: BR 7.1.3.1.1
    target: certificate.subjectPublicKeyInfo.publicKey.keySize
    operator: gte
    operands: [2048]
    severity: error
    when:
      target: certificate.subjectPublicKeyInfo.algorithm.algorithm
      operator: eq
      operands: [RSA]

  # CRL Rules
  - id: crl-valid
    reference: RFC5280 5.1
    target: crl
    operator: crlValid
    severity: error
    appliesTo: [crl]
```

---

## Appendix: OID Reference

### Extension OIDs

| OID | Name |
|-----|------|
| 2.5.29.14 | subjectKeyIdentifier |
| 2.5.29.15 | keyUsage |
| 2.5.29.17 | subjectAltName |
| 2.5.29.19 | basicConstraints |
| 2.5.29.20 | crlNumber |
| 2.5.29.31 | cRLDistributionPoints |
| 2.5.29.35 | authorityKeyIdentifier |
| 2.5.29.37 | extKeyUsage |
| 1.3.6.1.5.5.7.1.1 | authorityInformationAccess |
| 1.3.6.1.4.1.11129.2.4.2 | SCT list |

### Algorithm OIDs

| OID | Algorithm |
|-----|-----------|
| 1.2.840.113549.1.1.1 | rsaEncryption |
| 1.2.840.113549.1.1.10 | RSASSA-PSS |
| 1.2.840.113549.1.1.11 | sha256WithRSAEncryption |
| 1.2.840.10045.2.1 | id-ecPublicKey |
| 1.2.840.10045.4.3.2 | ecdsa-with-SHA256 |
| 1.2.840.10045.3.1.7 | secp256r1 (P-256) |

### EKU OIDs

| OID | Purpose |
|-----|---------|
| 1.3.6.1.5.5.7.3.1 | serverAuth |
| 1.3.6.1.5.5.7.3.2 | clientAuth |
| 1.3.6.1.5.5.7.3.3 | codeSigning |
| 1.3.6.1.5.5.7.3.4 | emailProtection |
| 1.3.6.1.5.5.7.3.8 | timeStamping |
| 1.3.6.1.5.5.7.3.9 | ocspSigning |