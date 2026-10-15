# 🔐 PCL - Policy-based Certificate Linter

[![CI](https://github.com/cavoq/PCL/actions/workflows/ci.yml/badge.svg)](https://github.com/cavoq/PCL/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cavoq/PCL/branch/master/graph/badge.svg)](https://codecov.io/gh/cavoq/PCL)
[![Go Report Card](https://goreportcard.com/badge/github.com/cavoq/PCL)](https://goreportcard.com/report/github.com/cavoq/PCL)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)

A flexible X.509 certificate linter that validates certificates against configurable YAML-based policies. Ensure compliance with RFC 5280, organizational standards, or industry best practices.

## 🚀 Quick Start

```bash
go install github.com/cavoq/PCL/cmd/pcl@latest
pcl --policy <path> [--policy <path>...] --cert <path> [--crl <path>] [--ocsp <path>] [--purpose <eku-name-or-oid>] [--output text|json|yaml]
```

Multiple policies can be specified with repeatable `--policy` flags. All rules from all policies will be applied.

Subcommands help with writing policies:

```bash
pcl inspect --cert <path> --paths   # list every rule target path with its value
pcl test <suite-or-directory>       # run policy test suites (*.test.yaml)
pcl schema                          # print the policy JSON Schema for editors
```

By default, only failed rules are shown. Use `-v` to include passed rules and `-vv` to include skipped rules.

`pcl` exits with status 1 when it cannot complete the run. Failed rules do not
change the exit status unless `--fail-on` names a severity: with
`--fail-on error`, any failed rule of severity `error` makes `pcl` exit with
status 1 after writing the results; `warning` and `info` also count failed rules
of those and higher severities. This makes `pcl` usable as a CI gate:

```bash
pcl --policy policies/RFC5280.yaml --cert leaf.pem --fail-on error
```

Use `--purpose serverAuth` (or another supported friendly EKU name or dotted
OID) to activate RFC 5280 application-purpose evaluation. The shipped rule
checks EKU across the supplied certificate chain and compatible end-entity Key
Usage. The wildcard values `any`, `anyExtendedKeyUsage`, and `2.5.29.37.0` are
not application purposes and are rejected. Private EKU OIDs are accepted as
purpose identifiers, but fail closed when end-entity Key Usage is present
because RFC 5280 defines no Key Usage mapping for them. Without `--purpose`, the
conditional rule is skipped.

### Auto-Validate Mode

Automatically fetch PKI resources from certificate extensions (OCSP, CRL, CA Issuers) and climb the certificate chain:

```bash
pcl --policy <path> --cert leaf.pem --auto-validate
```

This mode:
- **Chain Climbing**: Recursively fetches issuer certificates via CA Issuers URLs,
  also to find the signers of CRLs and delegated OCSP responders. Without
  `--auto-validate`, or with `--no-auto-chain`, PCL makes no CA Issuers requests.
- **PKCS#7 Support**: Parses `.p7c` certificate bundles per RFC 5280/5652
- **Auto OCSP/CRL**: Fetches OCSP from AIA and bounded DER CRLs over HTTP(S)
  from certificate CRL Distribution Points and Freshest CRL locations, then
  follows Freshest CRL locations on complete CRLs. CRL retrieval uses
  `--cert-url-timeout` (10 seconds by default); automatic CRL retrieval does
  not accept PEM.
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

PCL uses the Public Suffix List to validate TLDs and domain names (BR 4.2.2, 3.2.2.6).
Without a list, rules that use the public suffix and TLD operators fail with a
message saying the list is not loaded; other rules are unaffected. A `--psl-file`
that cannot be loaded is an error. `pcl inspect` and `pcl test` accept the same
options:

```bash
# Use default PSL location (./data/public_suffix_list.dat or ~/.pcl/data/)
pcl --policy <path> --cert cert.pem

# Specify custom PSL file
pcl --policy <path> --cert cert.pem --psl-file /path/to/public_suffix_list.dat

# Disable PSL loading (rules using public suffix and TLD operators then fail)
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

### Inspect the Node Tree

`pcl inspect` prints the node tree that policies evaluate, after the same
loading, chain building and automatic retrieval as a lint run. It accepts the
same input flags (`--cert`, `--issuer`, `--crl`, `--ocsp`, `--purpose`,
`--auto-validate`, ...) and needs no policy.

```bash
# Tree for every certificate in the chain
pcl inspect --cert leaf.pem --issuer chain/

# Every rule target path with its value and type, ready to copy into a rule
pcl inspect --cert leaf.pem --paths | grep subjectAltName
# certificate.subjectAltName.dNSName.0 = leaf.example.test (string)

# Machine-readable tree or path list
pcl inspect --crl list.crl --output json
```

Byte values are shown as hex (shortened in text output), times in RFC 3339 UTC.

### Editor Support

Policy files have a JSON Schema at
[`schemas/policy.schema.json`](schemas/policy.schema.json). Editors using the
YAML language server (for example VS Code with the Red Hat YAML extension)
complete fields and operator names, and flag unknown operators, invalid
severities and operands that do not match the operator. Add this first line to
a policy:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cavoq/PCL/master/schemas/policy.schema.json
```

`pcl schema` prints the schema for the installed version. Linting still
performs the authoritative checks, including regular expression syntax and
value ranges a schema cannot express.

### Test Policies

`pcl test` runs policy test suites (`*.test.yaml`) that lint example inputs
and check the expected verdict per input and rule, so policy changes can be
verified like code:

```yaml
policy: ../policies/my-profile.yaml
time: 2026-10-01
tests:
  - name: compliant server certificate
    cert: certs/good-leaf.pem
    issuers: [certs/intermediate.pem, certs/root.pem]
    expect:
      - input: leaf
        verdict: pass
        rules: {san-present: pass, key-size-minimum: pass}
```

```bash
pcl test policies/tests
```

See the [policy writing guide](docs/POLICY_WRITING_GUIDE.md#testing-policies)
for the full format and [`tests/policy-suites`](tests/policy-suites) for
examples.

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
- `policies/TR03116-TLS-SERVER.yaml` — BSI TR-03116 TLS server certificate profile
- `policies/LOCAL-PROFILE.yaml` — explicitly supplemental local/WebPKI checks

These are lint policies, not claims that PCL implements every state machine in
the named standard. See the coverage matrices and conformance roadmap for the
exact scope.

The TR-03116 profile implements the certificate checklist from TR-03116-TS
v1.1 using the certificate cryptography requirements from TR-03116-4 (2025).
Its [coverage matrix](policies/TR03116-TLS-SERVER-COVERAGE.md) identifies the
hostname, service-availability, and application-context checks that require
evidence outside a standalone certificate.

RFC 5280 P3 revocation processing is complete within its documented boundary:
strict extension parsing, scoped complete and delta CRLs, indirect issuer
inheritance, reason coverage, explicit Good/Revoked/Unknown status, and bounded
CRLDP/Freshest acquisition. Full Sections 6 and 7 path, policy, signer-path,
and name processing remains P4. See the
[coverage matrix](policies/RFC5280-COVERAGE.md) and
[roadmap](docs/RFC5280_ROADMAP.md).

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


## ✅ Conformance

The integration tests run the NIST Public Key Interoperability Test Suite
(PKITS 1.0.1), the reference suite for RFC 5280 path validation, through the
lint command: 240 of the 244 runs PCL can express reach the PKITS result. The
remaining four use certificates the underlying zcrypto parser cannot load. See
[`tests/pkits`](tests/pkits/README.md) for the mapping and the known gaps.

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
| `noUnknownCriticalExtensions` | Extension OIDs must be unique; a critical extension must be processable at its exact certificate, CRL, or CRL-entry location and its decoded node must not be malformed or unprocessed |

### Certificate Chain Operators

| Operator | Description |
|----------|-------------|
| `signatureValid` | Cryptographic signature verification |
| `signatureAlgorithmMatchesTBS` | Signature algorithm matches TBS certificate |
| `issuedBy` | Issuer DN matches issuer's subject DN |
| `akiMatchesSki` | Authority Key ID matches issuer's Subject Key ID |
| `pathLenValid` | Counts non-self-issued intermediates in the supplied ordered chain; not a Section 6 path engine |
| `serialNumberUnique` | Duplicate issuer/serial diagnostic within the supplied chain; not CA-wide uniqueness |

### Key Usage & Constraints Operators

| Operator | Description |
|----------|-------------|
| `ekuContains`, `ekuNotContains` | Extended key usage checks |
| `ekuServerAuth`, `ekuClientAuth` | TLS authentication EKU checks |
| `applicationPurposeValid` | Explicit `--purpose` compatibility with EKU and end-entity Key Usage |
| `anyExtendedKeyUsageNotCritical` | Rejects critical EKU when it asserts anyExtendedKeyUsage |
| `basicConstraintsDependenciesValid`, `keyUsageDependenciesValid` | Basic Constraints/Key Usage profile dependencies, including keyCertSign => CA |
| `nameConstraintsDependenciesValid`, `nameConstraintsDistancesValid` | CA-only and GeneralSubtree distance requirements |
| `crlDistributionPointsDependenciesValid` | CRLDP structural dependencies; P3 status scope remains domain-owned |
| `policyMappingsDependenciesValid`, `policyMappingsIssuerPoliciesPresent` | Policy Mapping profile restrictions |
| `policyConstraintsDependenciesValid`, `inhibitAnyPolicyDependenciesValid` | CA-only policy-extension restrictions |

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

### Combined Revocation Operators

| Operator | Description |
|----------|-------------|
| `notRevokedByAvailableEvidence` | Combines the CRL and OCSP assessments: revoked evidence wins, otherwise at least one mechanism must establish Good |

### Path Validation Operators

| Operator | Description |
|----------|-------------|
| `nameConstraintsValid` | Applies DNS, email, URI, IP and directoryName constraints across the chain (RFC 5280 4.2.1.10) |
| `certificatePolicyValid` | RFC 5280 6.1 policy processing from the trust anchor to the certificate. With operands, one of the listed policies must be valid for the path; without operands, the path must satisfy its own policy constraints (not active in `RFC5280.yaml`) |

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

Rules target fields using a dot-separated path notation. The node tree structure mirrors the certificate/CRL/OCSP structure. Run `pcl inspect --paths` to list every path for a concrete input:

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
│   │   ├── value          # Raw bytes
│   │   └── malformed      # Present when strict decoding fails
├── basicConstraints
│   ├── cA                 # Boolean
│   ├── cAPresent          # Encoded DEFAULT-field presence
│   ├── pathLenConstraint  # Integer (if present)
│   └── pathLenConstraintPresent
├── keyUsage               # Integer bitmask
│   ├── digitalSignature   # Boolean (per bit)
│   ├── keyCertSign        # Boolean
│   └── ...
├── extKeyUsage
│   ├── serverAuth         # Boolean
│   ├── clientAuth         # Boolean
│   ├── usages.0.oid       # Ordered known or private KeyPurposeId
│   └── ...
├── applicationPurpose     # Present only with --purpose
├── subjectKeyIdentifier   # Bytes
├── authorityKeyIdentifier # Bytes
├── subjectAltName
│   ├── dNSName
│   ├── iPAddress
│   └── ...
├── revocation             # Present when CRL checking was requested
│   ├── status             # good, revoked, or unknown
│   ├── evidenceCount
│   ├── coveredReasons     # RFC 5280 reason-mask coverage
│   ├── reasonCode         # Present when revoked
│   └── revocationTime     # Present when revoked
├── signedCertificateTimestamps  # SCT list
└── ...                    # AIA, CRLDP, policies, and constraints decode under extensions
```

P2 adds presence-preserving schemas under
`certificate.extensions.policyMappings` (`mappings.*.{issuerDomainPolicy,subjectDomainPolicy}`),
`policyConstraints` (the two counters and `*Present` facts),
`inhibitAnyPolicy.skipCerts`, and
`nameConstraints.{permittedSubtrees,excludedSubtrees}`. Name Constraints keep
each GeneralSubtree base, tag, raw DER, minimum/maximum values, and independent
presence facts. Counter nodes retain exact `decimal` text and a `fitsInt` fact,
so a valid `(0..MAX)` value larger than the native integer range is not
misreported as malformed. CRLDP supports both full GeneralNames and a lossless
`nameRelativeToCRLIssuer` RDN. See the
[policy-writing guide](docs/POLICY_WRITING_GUIDE.md#p2-profile-extension-schemas)
for canonical paths.

The extension identity catalog and processed-extension registry are separate.
Processing authorization is location-specific: PCL registers only strictly
decoded certificate, CRL, and CRL-entry extensions whose supported semantics
are implemented. Known-but-unprocessed, wrong-location, malformed, or
partially unprocessed critical extensions fail `noUnknownCriticalExtensions`.
Duplicate extension OIDs also fail before criticality is considered;
non-critical unique extensions remain available to ordinary profile rules.

### CRL Node Tree

```
crl
├── signatureAlgorithm     # Same as certificate
├── tbsSignatureAlgorithm
├── issuer                 # Same as certificate
├── thisUpdate             # time.Time
├── nextUpdate             # time.Time
├── isCACRL                # Boolean: CA signer or >10-day profile inference
├── authorityKeyIdentifier # Key identifier bytes
├── crlNumber              # Exact decimal string
├── deltaCRLIndicator      # Base CRL number plus decimal/fitsInt metadata
├── issuingDistributionPoint
│   ├── distributionPoint
│   ├── onlyContainsUserCerts / onlyContainsCACerts
│   ├── onlySomeReasons
│   ├── indirectCRL
│   └── onlyContainsAttributeCerts
├── freshestCRL
│   └── distributionPoints # Canonical full/relative names and GeneralNames
├── revokedCertificates
│   ├── <serial>           # Each revoked cert
│   │   ├── serialNumber
│   │   ├── revocationDate
│   │   └── extensions
│   │       ├── cRLReason
│   │       ├── invalidityDate
│   │       └── certificateIssuer
└── extensions
    └── <oid-or-alias>     # raw/critical plus strict P3 projections
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

## P2/P3 Migration Notes

- Custom policies relying on catalog membership for critical-extension
  acceptance may now fail closed; only strict processing registered for the
  extension's exact certificate, CRL, or CRL-entry location authorizes it.
- Test optional/default extension fields through their `*Present` nodes rather
  than treating zero as absence, and check the concrete extension's
  `malformed` child before consuming decoded values.
- `pathLenValid` uses the supplied leaf-to-root chain and excludes self-issued
  intermediates. It does not build or establish trust in a path.
- Add `--purpose` only when application-specific EKU enforcement is desired;
  omitting it preserves conditional-skip behavior.

## 🔧 Development

```bash
go build -o pcl ./cmd/pcl
go test -v -race ./...
golangci-lint run ./...
```
