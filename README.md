# 🔐 PCL - Policy-based Certificate Linter

[![CI](https://github.com/cavoq/PCL/actions/workflows/ci.yml/badge.svg)](https://github.com/cavoq/PCL/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cavoq/PCL/branch/master/graph/badge.svg)](https://codecov.io/gh/cavoq/PCL)
[![Go Report Card](https://goreportcard.com/badge/github.com/cavoq/PCL)](https://goreportcard.com/report/github.com/cavoq/PCL)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)

A flexible X.509 certificate linter that validates certificates against configurable YAML-based policies. Ensure compliance with RFC 5280, organizational standards, or industry best practices.

## 🚀 Quick Start

```bash
go install github.com/cavoq/PCL/cmd/pcl@latest
pcl --policy <path> [--policy <path>...] --cert <path> [--crl <path>] [--ocsp <path>] [--output text|json|yaml]
```

Multiple policies can be specified with repeatable `--policy` flags. All rules from all policies will be applied.

By default, only failed rules are shown. Use `-v` to include passed rules and `-vv` to include skipped rules.

### Auto-Validate Mode

Automatically fetch PKI resources from certificate extensions (OCSP, CRL, CA Issuers) and climb the certificate chain:

```bash
pcl --policy <path> --cert leaf.pem --auto-validate
```

This mode:
- **Chain Climbing**: Recursively fetches issuer certificates via CA Issuers URLs
- **PKCS#7 Support**: Parses `.p7c` certificate bundles per RFC 5280/5652
- **Auto OCSP/CRL**: Fetches revocation information from AIA extensions
- **Issuer Matching**: Handles multi-certificate bundles by matching Issuer DN and AKI-SKI

Options for granular control:
```bash
# Limit chain depth
pcl --policy <path> --cert leaf.pem --auto-validate --max-chain-depth 5

# Disable specific auto-fetch features
pcl --policy <path> --cert leaf.pem --auto-validate --no-auto-chain
pcl --policy <path> --cert leaf.pem --auto-validate --no-auto-crl
pcl --policy <path> --cert leaf.pem --auto-validate --no-auto-ocsp

# OCSP nonce configuration (RFC 9654)
pcl --policy <path> --cert leaf.pem --auto-validate --ocsp-nonce-length 32
pcl --policy <path> --cert leaf.pem --auto-validate --ocsp-nonce-value aabbcc...
pcl --policy <path> --cert leaf.pem --auto-validate --no-ocsp-nonce

# OCSP CertID hash algorithm (RFC 5019 vs modern)
pcl --policy <path> --cert leaf.pem --auto-validate --ocsp-hash sha1   # RFC 5019
pcl --policy <path> --cert leaf.pem --auto-validate --ocsp-hash sha256 # Modern (default)
```

### Public Suffix List (PSL) Options

PCL uses the Public Suffix List to validate TLDs and domain names (BR 4.2.2, 3.2.2.6):

```bash
# Use default PSL location (./data/public_suffix_list.dat or ~/.pcl/data/)
pcl --policy <path> --cert cert.pem

# Specify custom PSL file
pcl --policy <path> --cert cert.pem --psl-file /path/to/public_suffix_list.dat

# Disable PSL loading (use regex fallback)
pcl --policy <path> --cert cert.pem --use-psl=false

# Update/download PSL to default location
pcl update-data

# Update PSL to custom directory
pcl update-data --data-dir /custom/data/path
```

### Debug OCSP Requests

Use `-vv` to see detailed OCSP request/response information:
```bash
pcl --policy policies/RFC6960.yaml --cert leaf.pem --auto-validate -vv
```

Output includes:
- Request nonce length and hex value
- CertID hash algorithm (SHA1/SHA256)
- Response nonce and match status
- OCSP response timing details

### Fetch TLS Certificates from URLs

Fetch certificate chains from HTTPS endpoints:

```bash
pcl --policy <path> --cert-url https://example.test --cert-url-timeout 10s --cert-url-save-dir ./downloads
```

## 📝 Policy Configuration

Policies are YAML files defining validation rules with a simple declarative syntax.

```yaml
id: rfc5280
version: 1.0

rules:
  # -------------------------------------------------
  # Certificate structure (Section 4.1)
  # -------------------------------------------------

  # Version MUST be 3 when extensions are present
  - id: version-v3-when-extensions
    reference: RFC5280 4.1.2.1
    when:
      target: certificate.extensions
      operator: present
    target: certificate.version
    operator: eq
    operands: [3]
    severity: error

  # Serial number MUST be positive integer
  - id: serial-number-positive
    reference: RFC5280 4.1.2.2
    target: certificate.serialNumber.value
    operator: positive
    severity: error

  # Local diagnostic only: this cannot establish CA-wide RFC 5280 uniqueness
  - id: serial-number-duplicate-in-chain
    reference: LOCAL-CHAIN-HEURISTIC
    target: certificate
    operator: serialNumberUnique
    severity: warning

  # -------------------------------------------------
  # Signature validation (Section 4.1.2.3)
  # -------------------------------------------------

  - id: signature-valid
    reference: RFC5280 4.1.2.3
    target: certificate
    operator: signatureValid
    severity: error

  - id: signature-algorithm-matches-tbs
    reference: RFC5280 4.1.2.3
    target: certificate
    operator: signatureAlgorithmMatchesTBS
    severity: error

  # -------------------------------------------------
  # Basic Constraints (Section 4.2.1.9)
  # -------------------------------------------------

  - id: ca-basic-constraints
    reference: RFC5280 4.2.1.9
    target: certificate.basicConstraints.cA
    operator: eq
    operands: [true]
    severity: error
    certType: [root, intermediate]

  # -------------------------------------------------
  # Key Usage (Section 4.2.1.3)
  # -------------------------------------------------

  - id: key-usage-ca
    reference: RFC5280 4.2.1.3
    when:
      target: certificate.extensions.keyUsage
      operator: present
    target: certificate.keyUsage.keyCertSign
    operator: eq
    operands: [true]
    severity: error
    certType: [root, intermediate]

  # -------------------------------------------------
  # AIA Extension - Best Practice (INFO severity)
  # -------------------------------------------------

  - id: leaf-ca-issuers-url-recommended
    reference: RFC5280 4.2.2.1
    target: certificate.extensions.authorityInfoAccess.containsCaIssuers
    operator: eq
    operands: [true]
    severity: info
    certType: [leaf]

  # -------------------------------------------------
  # Subject Alternative Name (Section 4.2.1.6)
  # -------------------------------------------------

  - id: san-required-if-empty-subject
    reference: RFC5280 4.2.1.6
    when:
      target: certificate.subject
      operator: isEmpty
    target: certificate.subjectAltName
    operator: present
    severity: error

  # -------------------------------------------------
  # Conditional RSA validation (RFC 4055)
  # -------------------------------------------------

  - id: rsa-params-null
    reference: RFC4055 Section 5
    when:
      target: certificate.signatureAlgorithm.oid
      operator: in
      operands:
        - "1.2.840.113549.1.1.11"  # sha256WithRSAEncryption
        - "1.2.840.113549.1.1.12"  # sha384WithRSAEncryption
        - "1.2.840.113549.1.1.13"  # sha512WithRSAEncryption
    target: certificate.signatureAlgorithm.parameters.null
    operator: eq
    operands: [true]
    severity: error
```

## 🏛️ Supported Policies

- `policies/RFC5280.yaml` — RFC 5280 certificate and CRL profile checks
- `policies/RFC4055.yaml` — RSA algorithm-identifier checks from RFC 4055
- `policies/RFC6960.yaml` — fail-closed OCSP evidence checks for leaf certificates
- `policies/LOCAL-PROFILE.yaml` — explicitly supplemental local/WebPKI checks

These are lint policies, not claims that PCL implements every state machine in
the named standard. See the coverage matrices and conformance roadmap for the
exact scope.

Load independent bundles together by repeating `--policy`, for example
`--policy policies/RFC5280.yaml --policy policies/RFC6960.yaml`.

The RFC 6960 bundle runs during leaf-certificate evaluation because it binds a
response to the certificate and issuer chain. Loading it opts into requiring
valid OCSP evidence; a missing, unrelated, stale, or non-good response fails.

Related profiles used by selected rules and acquisition features include:

- [RFC 9549](https://datatracker.ietf.org/doc/html/rfc9549) - Internationalization Updates to RFC 5280 (IDN, DNS labels)
- [RFC 9598](https://datatracker.ietf.org/doc/html/rfc9598) - Internationalized Email Addresses in X.509 (rfc822Name)
- [RFC 9654](https://datatracker.ietf.org/doc/html/rfc9654) - OCSP Nonce Extension
- CA/Browser Forum Baseline Requirements (BR)
- CA/Browser Forum Extended Validation Guidelines (EVG)
- CA/Browser Forum S/MIME Baseline Requirements (SMIME BR)
- CA/Browser Forum Code Signing Baseline Requirements (CS BR)


## ➕ Supported Operators

### Comparison Operators

| Operator | Description |
|----------|-------------|
| `eq` | Equality check |
| `neq` | Not equal check |
| `gt`, `gte` | Greater than (or equal) |
| `lt`, `lte` | Less than (or equal) |
| `in` | Value in allowed list |
| `notIn` | Value not in disallowed list |
| `contains` | String/array contains value |
| `matches` | Compare two field paths for equality |

### Presence & Value Operators

| Operator | Description |
|----------|-------------|
| `present` | Field existence check |
| `absent` | Field does not exist |
| `isEmpty`, `notEmpty` | Value emptiness check |
| `isNull` | Explicit ASN.1 NULL marker check |
| `positive` | Value is a positive number |
| `odd` | Value is an odd number (for RSA exponent validation) |
| `maxLength`, `minLength` | String/array length constraints |
| `regex`, `notRegex` | Regular expression pattern matching |
| `componentMaxLength`, `componentMinLength` | Per-component length validation (DNS labels, path segments) |
| `componentRegex`, `componentNotRegex` | Per-component regex validation |
| `anyComponentMatches`, `noComponentMatches` | ANY/NO component matches regex (for wildcard detection) |
| `componentInCIDR`, `componentNotInCIDR` | Per-component CIDR range validation (for IP address checking) |
| `utf8NoBom`, `containsBom` | UTF-8 BOM detection |
| `derEqualsHex` | Compare DER bytes with an expected hexadecimal value |

### Date Operators

| Operator | Description |
|----------|-------------|
| `before` | Date is before current time |
| `after` | Date is after current time |
| `onOrBefore` | Date is before or equal to the comparison time |
| `onOrAfter` | Date is after or equal to the comparison time |
| `validityOrderCorrect` | Validates notBefore < notAfter |
| `validityDays` | Certificate validity period check |
| `dateDiff` | Date difference validation with maxDays/maxMonths limits (for CRL nextUpdate) |

### Extension Operators

| Operator | Description |
|----------|-------------|
| `isCritical`, `notCritical` | Extension criticality check |
| `noUnknownCriticalExtensions` | No critical extension outside the RFC 5280 location catalog; this does not prove value processing support |

### Certificate Chain Operators

| Operator | Description |
|----------|-------------|
| `signatureValid` | Cryptographic signature verification |
| `signatureAlgorithmMatchesTBS` | Signature algorithm matches TBS certificate |
| `issuedBy` | Issuer DN matches issuer's subject DN |
| `akiMatchesSki` | Authority Key ID matches issuer's Subject Key ID |
| `pathLenValid` | Path length constraint validation |
| `serialNumberUnique` | Duplicate issuer/serial diagnostic within the supplied chain; not CA-wide uniqueness |

### Key Usage & Constraints Operators

| Operator | Description |
|----------|-------------|
| `ekuContains`, `ekuNotContains` | Extended key usage checks |
| `ekuServerAuth`, `ekuClientAuth` | TLS authentication EKU checks |

### Collection/Array Operators

| Operator | Description |
|----------|-------------|
| `every` | Apply one scalar operator to every canonical collection element |
| `uniqueValues` | All children have unique values (for CRL DP, AIA URLs) |
| `uniqueChildren` | All children have unique string values |
| `noDuplicateAttributes` | CABF single-instance subject attributes do not repeat |

### CRL Operators

| Operator | Description |
|----------|-------------|
| `crlValid` | CRL is within thisUpdate/nextUpdate window |
| `crlNotExpired` | Compatibility check: nextUpdate is present and has not passed |
| `crlSignedBy` | Cryptographic CRL signature verification against resolved issuers |
| `notRevoked` | Certificate absent from an applicable CRL; missing/unrelated CRLs return false (unknown) |

### OCSP Operators

| Operator | Description |
|----------|-------------|
| `ocspValid` | At least one response is bound to the certificate and issuer, current, and signed by the issuer or an authorized responder |
| `notRevokedOCSP` | Accepted aggregate status is Good; absent, unknown, stale, unrelated, invalidly signed, and revoked evidence fail |
| `ocspGood` | At least one accepted response explicitly reports Good |

### Path Validation Operators

| Operator | Description |
|----------|-------------|
| `nameConstraintsValid` | Validates names against permitted/excluded subtrees from chain |
| `certificatePolicyValid` | Validates policy OIDs through chain with mappings and constraints |

ASN.1 time details are projected as ordinary fields (`encoding`, `rawValue`,
`hasSeconds`, `hasFraction`, and `hasZulu`) and are checked with generic
comparison operators.

### Public Suffix List (PSL) / TLD Operators

| Operator | Description |
|----------|-------------|
| `tldRegistered` | TLD is registered in IANA Root Zone Database (via PSL ICANN section) |
| `tldNotRegistered` | TLD is NOT registered in IANA Root Zone Database |
| `isPublicSuffix` | Domain is a public suffix (ICANN or private) |
| `isNotPublicSuffix` | Domain is NOT a public suffix |
| `componentTLDNotRegistered` | At least one domain has an unregistered TLD |
| `componentIsPublicSuffix` | FQDN portion of wildcard is a public suffix (BR 3.2.2.6) |
| `componentNotPublicSuffix` | FQDN portion of wildcard is NOT a public suffix |

These operators use the Public Suffix List (PSL) from [publicsuffix.org](https://publicsuffix.org). The PSL ICANN section contains all IANA-registered TLDs, enabling validation of:
- **BR 4.2.2**: Internal Names - certificates must not contain domains with unregistered TLDs
- **BR 3.2.2.6**: Wildcard certificates - FQDN portion must not be a public suffix

### ASN.1 Encoding Operators

| Operator | Description |
|----------|-------------|
| `isIA5String` | Value uses IA5String encoding (ASCII) |
| `isPrintableString` | Value uses PrintableString encoding |
| `isUTF8String` | Value uses UTF8String encoding |
| `validIA5String` | All characters valid for IA5String (ASCII) |
| `validPrintableString` | All characters valid for PrintableString |

`validIA5String` and `componentRegex` validate one scalar value. Wrap them in
`every` when the target is a SAN, IAN, DN, or other collection.

## 🔀 Conditional Rules

Rules can include a `when` clause to apply only when certain conditions are met:

```yaml
# Only validate RSA key size when certificate uses RSA algorithm
- id: rsa-key-size-minimum
  reference: RFC4055
  when:
    target: certificate.subjectPublicKeyInfo.algorithm.algorithm
    operator: eq
    operands: [RSA]
  target: certificate.subjectPublicKeyInfo.publicKey.keySize
  operator: gte
  operands: [2048]
  severity: error

# Only check SAN when subject is empty (RFC 5280 4.2.1.6)
- id: san-required-if-empty-subject
  reference: RFC5280 4.2.1.6
  when:
    target: certificate.subject
    operator: isEmpty
  target: certificate.subjectAltName
  operator: present
  severity: error

# EV certificate MUST have SCT (only applies to EV certs)
- id: ev-sct-required
  reference: CA/Browser Forum BR Appendix B
  when:
    target: certificate.extensions.certificatePolicies.2.23.140.1.1
    operator: present
  target: certificate.signedCertificateTimestamps
  operator: present
  severity: warning
  certType: [leaf]
```

When the `when` condition is not met, the rule status is **SKIP** (not displayed by default, use `-vv` to see).

## ⚠️ Severity Levels

PCL supports three severity levels:

| Level | Color | Description |
|-------|-------|-------------|
| `error` | Red | Mandatory compliance requirement |
| `warning` | Yellow | Important best practice or conditional requirement |
| `info` | Blue | Recommended best practice (non-blocking) |

Example: EV certificates should have SCT embedded (warning), while AIA extension presence is recommended (info) for interoperability.

## Certificate Chain Support

PCL automatically builds and validates certificate chains, applying rules based on certificate position and BasicConstraints:

- `leaf`: End-entity certificates (position 0, no BasicConstraints or IsCA=false)
- `intermediate`: Subordinate CA certificates (position 0+ with IsCA=true, not self-signed)
- `root`: Self-signed root CA certificates (IsCA=true, Subject==Issuer)

**Enhanced Detection:** At position 0, PCL checks BasicConstraints to correctly identify CA certificates even when linted directly (without a subscriber certificate chain). This allows linting intermediate CA certificates standalone.

Use `certType` on individual rules to target certificate roles (`leaf`, `intermediate`, `root`, `ocspSigning`). Rules without `certType` run on every role (others are **SKIP** when the role does not match).

## 📥 Policy and input filtering

**Policy-level** (top of the YAML file, next to `id` / `version`):

- `appliesTo`: which **input object** the policy is for — `cert`, `crl`, `ocsp`, `tst`, `sct`, or `attrCert` (for example, `appliesTo: [ocsp]` for an OCSP-object policy).
- `certType`: optional filter so the **whole policy** runs only on matching certificate roles (used with certificate linting).

An explicit `appliesTo` is authoritative. If it is omitted, PCL infers an order-independent set of inputs from every rule's primary target namespace (`certificate`, `crl`, `ocsp`, `tst`, `sct`, or `attrCert`). A `when` target is a dependency only and does not change the execution input; an unqualified primary target is input-agnostic. The current CLI has certificate, CRL, and OCSP loaders; the other values are reserved by the policy schema. Role filtering remains per-rule `certType`.

## 🌳 Node Tree Structure

Rules target fields using a dot-separated path notation. The node tree structure mirrors the certificate/CRL/OCSP structure:

### Certificate Node Tree

```
certificate
├── version                 # Integer (1, 2, 3)
├── serialNumber
│   ├── value              # String representation
│   └── ...                # Raw bytes
├── signatureAlgorithm
│   ├── algorithm          # String name (e.g., "SHA256-RSA")
│   ├── oid                # OID string
│   └── parameters
│       ├── null           # Boolean (true if NULL)
│       ├── absent         # Boolean (true if omitted)
│       └── pss/oaep       # PSS/OAEP parameters (if present)
├── tbsSignatureAlgorithm  # Same structure as signatureAlgorithm
├── issuer / subject
│   ├── countryName
│   ├── organizationName
│   ├── commonName
│   └── ...
├── validity
│   ├── notBefore          # time.Time
│   ├── notAfter           # time.Time
├── subjectPublicKeyInfo
│   ├── algorithm
│   │   ├── algorithm      # String (RSA, ECDSA)
│   │   ├── oid            # OID string
│   └── publicKey
│       ├── keySize        # Integer
│       ├── exponent       # RSA exponent
│       ├── curve          # ECDSA curve name
├── extensions
│   ├── <oid>              # Each extension keyed by OID
│   │   ├── oid
│   │   ├── critical       # Boolean
│   │   └── value          # Raw bytes
├── basicConstraints
│   ├── cA                 # Boolean
│   ├── pathLenConstraint  # Integer (if present)
├── keyUsage               # Integer bitmask
│   ├── digitalSignature   # Boolean (per bit)
│   ├── keyCertSign        # Boolean
│   └── ...
├── extKeyUsage
│   ├── serverAuth         # Boolean
│   ├── clientAuth         # Boolean
│   └── ...
├── subjectKeyIdentifier   # Bytes
├── authorityKeyIdentifier # Bytes
├── subjectAltName
│   ├── dNSName
│   ├── iPAddress
│   └── ...
├── signedCertificateTimestamps  # SCT list
└── ...                    # AIA, CRLDP, and certificatePolicies decode under extensions
```

### CRL Node Tree

```
crl
├── signatureAlgorithm     # Same as certificate
├── issuer                 # Same as certificate
├── thisUpdate             # time.Time
├── nextUpdate             # time.Time
├── isCACRL                # Boolean: CA signer or >10-day profile inference
├── revokedCertificates
│   ├── <serial>           # Each revoked cert
│   │   ├── serialNumber
│   │   ├── revocationDate
│   │   └── extensions
│   │       └── 2.5.29.21  # reasonCode; decoded integer is under value
└── extensions
    └── ...
```

**CRL type detection (`isCACRL`):** True when a verified or identity-matched
signer from the available chain is a CA. If no CA signer is available, a CRL
window longer than 10 days selects the CA/other-CRL profile as a classification
fallback; signature and revocation decisions still require verified evidence.
With `--auto-validate`, PCL can also resolve a signer through CA Issuers URLs.

### OCSP Node Tree

```
ocsp
├── status                 # String (Good, Revoked, Unknown)
├── producedAt             # time.Time
├── thisUpdate             # time.Time
├── nextUpdate             # time.Time
├── revocationReason       # Integer (if revoked)
├── signatureAlgorithm     # Same as certificate
├── nonce                  # RFC 9654 nonce extension
│   ├── present            # Boolean
│   ├── value              # []byte (raw nonce)
│   ├── length             # Integer (bytes)
│   └── hexValue           # String (hex representation)
└── responderID            # Responder identification
```

## 🔧 Development

```bash
go build -o pcl ./cmd/pcl
go test -v -race ./...
golangci-lint run ./...
```
