# 🌳 Node Model

[Documentation](POLICY_WRITING_GUIDE.md) · [Policy format](POLICY_FORMAT.md) · [Operators](OPERATORS.md)

The node tree is the policy-facing representation of acquired evidence.
Parsing facts retain raw encodings and presence; domain decisions are projected
separately. Use `pcl inspect --cert leaf.pem --issuer chain/ --paths` to discover
paths for an actual input. Missing optional fields are absent from that tree.

## Certificate Target Paths

### Basic Fields
```
certificate.version              # Certificate version (1, 2, 3)
certificate.serialNumber        # Serial number node
certificate.serialNumber.value  # Serial number value (string)
certificate.serialNumber.raw    # Complete encoded INTEGER
certificate.serialNumber.length # Encoded INTEGER content length
certificate.issuer              # Issuer DN node
certificate.subject             # Subject DN node
certificate.validity.notBefore  # NotBefore time
certificate.validity.notAfter   # NotAfter time
certificate.validity.notBefore.encoding    # 23 (UTC) or 24 (Generalized)
certificate.validity.notBefore.hasSeconds  # Raw encoding includes seconds
certificate.validity.notBefore.hasZulu     # Raw encoding uses Z
certificate.issuerUniqueID      # Present even for a zero-bit identifier
certificate.subjectUniqueID     # Present even for a zero-bit identifier
certificate.signatureAlgorithm  # Signature algorithm node
certificate.signatureAlgorithm.oid    # Algorithm OID
certificate.tbsSignatureAlgorithm      # TBSCertificate signature algorithm
```

### Issuer/Subject DN Fields
```
certificate.issuer.commonName          # Common Name (CN)
certificate.issuer.countryName         # Country (C)
certificate.issuer.organizationName    # Organization (O)
certificate.issuer.organizationalUnitName  # Organizational Unit (OU)
certificate.issuer.stateOrProvinceName     # State/Province (ST)
certificate.issuer.localityName            # Locality (L)
certificate.issuer.domainComponent         # Domain Component (DC)
```

### Distinguished Name collection contract

Certificate subjects and issuers, and `crl.issuer`, share one representation.
The Name node's scalar `Value` remains a display-string compatibility view; it
does not preserve RDN grouping and must not be used as encoding evidence. The
canonical paths preserve the encoded structure:

```text
subject
├── rdns.0.attributes.0
├── rdns.1.attributes.0
└── attributes
    ├── 2.5.4.3.0
    └── commonName.0       # alias of the same OID collection
```

- `rdns` contains numeric elements in encoded RDN order. Each RDN keeps its
  attributes together and exposes them as numeric elements in DER SET order.
- `attributes` groups all occurrences by OID. Known friendly names and direct
  Name children are aliases: for example, `attributes.2.5.4.3`,
  `attributes.commonName`, `2.5.4.3`, and `commonName` identify the same
  collection. A collection's scalar `Value` remains the first occurrence for
  compatibility; policies that apply to all values must iterate the numeric
  occurrences.
- Each occurrence exposes `value`, `oid`, `tag`, `encoding`, `encodingName`,
  `raw`, and `rawValue`. `tag` and the compatibility field `encoding` are the
  numeric ASN.1 tag; `encodingName` is its readable name; `raw` is the complete
  AttributeTypeAndValue DER and `rawValue` is the value element's content.

`CollectionElements`, and therefore `every` and its wildcard traversal, uses
numeric children in integer order whenever any are present. Metadata and named
aliases are then ignored, so one occurrence is not checked twice. For older
object-shaped nodes without numeric children, iteration falls back to unique,
non-nil child nodes in deterministic key order.

These guarantees are lossless only when raw Name DER is available. Synthetic
`pkix.Name` inputs preserve the values and grouping exposed by that parsed
structure, but report `encodingName: unknown`, tag/encoding `0`, and empty raw
fields. Malformed raw Names retain `raw` plus `malformed: true` and do not
silently substitute lossy attribute collections. Name Constraints and
relative CRL distribution-point names reuse the same representation; the
path domain uses the shared Section 7 distinguished-name
comparison when binding issuers and directoryName subtrees. Attribute
values with unknown tags remain opaque raw bytes; validating a locally defined
attribute's syntax belongs to the policy or domain that defines that OID.

### Extensions (by OID or friendly name)
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
certificate.extensions.2.5.29.33        # policyMappings
certificate.extensions.2.5.29.36        # policyConstraints
certificate.extensions.2.5.29.54        # inhibitAnyPolicy
```

### Common Extension Fields
```
certificate.subjectKeyIdentifier        # SKI value ([]byte)
certificate.authorityKeyIdentifier      # AKI value ([]byte)
certificate.basicConstraints.cA         # cA boolean
certificate.basicConstraints.cAPresent  # encoded BOOLEAN presence
certificate.basicConstraints.pathLenConstraint  # Path length
certificate.basicConstraints.pathLenConstraintPresent # encoded INTEGER presence
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
certificate.extKeyUsage.usages.0.oid      # every known/private KeyPurposeId
certificate.extKeyUsage.unknown.0.oid     # private/unknown KeyPurposeId
```

### Certificate Policies Fields
```
certificate.extensions.certificatePolicies        # Certificate Policies node
certificate.extensions.certificatePolicies.evPolicy     # EV PolicyInformation node
certificate.extensions.certificatePolicies.ovPolicy     # OV PolicyInformation node
certificate.extensions.certificatePolicies.dvPolicy     # DV PolicyInformation node
certificate.extensions.certificatePolicies.smimeMailboxLegacy  # S/MIME PolicyInformation node
```

### SubjectPublicKeyInfo
```
certificate.subjectPublicKeyInfo.algorithm.algorithm  # Algorithm name (RSA, DSA, ECDSA)
certificate.subjectPublicKeyInfo.algorithm.oid        # Algorithm OID
certificate.subjectPublicKeyInfo.publicKey.keySize    # RSA/DSA/ECDSA key size (bits)
certificate.subjectPublicKeyInfo.publicKey.subgroupSize # DSA subgroup size (bits)
certificate.subjectPublicKeyInfo.publicKey.curve      # ECDSA curve name (P-256, P-384, P-521)
certificate.subjectPublicKeyInfo.algorithm.parameters  # Algorithm parameters node
certificate.subjectPublicKeyInfo.algorithm.parameters.namedCurve  # ECDSA curve OID
certificate.subjectPublicKeyInfo.algorithm.parameters.null        # NULL flag (boolean)
```

### AIA (Authority Information Access)
```
certificate.extensions.authorityInfoAccess           # AIA extension node
certificate.extensions.authorityInfoAccess.accessDescriptions  # AccessDescriptions array
certificate.extensions.authorityInfoAccess.accessDescriptions.0.accessMethod  # OID
certificate.extensions.authorityInfoAccess.accessDescriptions.0.accessLocation.type  # GeneralName type
certificate.extensions.authorityInfoAccess.accessDescriptions.0.accessLocation.scheme  # URI scheme
certificate.extensions.authorityInfoAccess.accessDescriptions.0.accessLocation.value  # URI value
certificate.extensions.authorityInfoAccess.containsOCSP       # OCSP method present
certificate.extensions.authorityInfoAccess.containsCaIssuers  # CA Issuers method present
```

### CRL Distribution Points
```
certificate.extensions.cRLDistributionPoints           # CRL DP extension node
certificate.extensions.cRLDistributionPoints.distributionPoints  # DistributionPoints array
certificate.extensions.cRLDistributionPoints.distributionPoints.0.distributionPoint.fullName.generalNames.0.scheme  # URI scheme
certificate.extensions.cRLDistributionPoints.distributionPoints.0.distributionPoint.nameRelativeToCRLIssuer.rdns # lossless RDN
certificate.extensions.cRLDistributionPoints.distributionPoints.0.reasons.keyCompromise # ReasonFlags boolean (every flag is true or false)
certificate.extensions.cRLDistributionPoints.distributionPoints.0.reasons      # value: reason mask; also present, raw, value, unusedBits
certificate.extensions.cRLDistributionPoints.distributionPoints.0.cRLIssuer.entries # ordered GeneralNames
```

### Strict profile extension schemas

Strictly decoded extensions retain raw DER and put `malformed: true` on the
concrete `certificate.extensions.<oid-or-alias>` node when decoding fails.
Presence booleans distinguish an omitted DEFAULT/OPTIONAL value from an
encoded zero. A valid extension value that includes semantics outside PCL's
processed subset has `unprocessed: true`; critical-extension handling rejects
that value even though its DER remains available to policies.

```text
certificate.extensions.policyMappings
├── raw
├── count
└── mappings.0
    ├── issuerDomainPolicy
    ├── subjectDomainPolicy
    └── raw

certificate.extensions.policyConstraints
├── raw
├── requireExplicitPolicyPresent
├── requireExplicitPolicy        # only when present; has raw child
├── inhibitPolicyMappingPresent
└── inhibitPolicyMapping         # only when present; has raw child

certificate.extensions.inhibitAnyPolicy
├── skipCerts                    # non-negative INTEGER; decimal/fitsInt children
└── raw

certificate.extensions.nameConstraints
├── raw
├── permittedSubtrees.0
└── excludedSubtrees.0
    ├── base                     # canonical GeneralName
    ├── value / type / tag / raw
    ├── minimum / minimumPresent
    └── maximum / maximumPresent
```

Every projected extension counter that is present has `decimal` and `fitsInt`
metadata. Its scalar remains an integer when representable; larger valid
`(0..MAX)` values use the exact decimal string and remain well-formed.

The root compatibility projections `certificate.basicConstraints`,
`certificate.keyUsage`, `certificate.extKeyUsage`, and
`certificate.nameConstraints` use the same strict facts. Policies should use
the extension node's `malformed` child for well-formedness checks and the
domain operators below for cross-extension dependencies.

### SCT (Signed Certificate Timestamps)
```
certificate.signedCertificateTimestamps  # SCT list node (count = number of SCTs)
```

### SAN (Subject Alternative Name)
```
certificate.subjectAltName.entries              # All GeneralNames in source order
certificate.subjectAltName.dNSName              # DNS-name collection
certificate.subjectAltName.rfc822Name           # Email-address collection
certificate.subjectAltName.uniformResourceIdentifier  # URI collection
certificate.subjectAltName.iPAddress            # IP-address collection
certificate.subjectAltName.dNSName.0.tag        # GeneralName tag (2)
certificate.subjectAltName.dNSName.0.raw         # Complete GeneralName DER
certificate.subjectAltName.dNSName.0.rawValue    # Implicit GeneralName content
certificate.issuerAltName                       # IAN uses the same structure
certificate.revocation.status                   # good, revoked, or unknown
certificate.revocation.evidenceCount            # Retained complete-CRL decision count
certificate.revocation.coveredReasons           # RFC 5280 reason-mask coverage
certificate.revocation.reasonCode               # Present only when revoked
certificate.revocation.revocationTime           # Present only when revoked
```

Each per-type GeneralName entry has a scalar value, so collection rules target
the per-type collection and use `every`. The raw entry, not a typed x509
fallback, is authoritative.

## CRL Target Paths

```
crl.issuer                    # CRL issuer DN
crl.thisUpdate                 # ThisUpdate time
crl.nextUpdate                 # Optional NextUpdate time; absent when omitted
crl.isCACRL                   # Boolean: CA signer or >10-day profile inference
crl.signatureAlgorithm         # Signature algorithm node
crl.signatureAlgorithm.oid     # Algorithm OID
crl.signatureAlgorithm.parameters      # Parameters node
crl.tbsSignatureAlgorithm      # TBSCertList signature algorithm
crl.crlNumber                  # CRL number (string)
crl.authorityKeyIdentifier     # AKI value
crl.deltaCRLIndicator          # Base CRL number with decimal/fitsInt metadata
crl.issuingDistributionPoint   # Scope, reasons, indirectCRL, and distribution point
crl.freshestCRL.distributionPoints  # Canonical Freshest CRL distribution points
crl.revokedCertificates        # Revoked certificates list
crl.revokedCertificates.0.serialNumber     # Serial number of revoked cert
crl.revokedCertificates.0.revocationDate   # Revocation time
crl.revokedCertificates.0.extensions       # Entry extensions
crl.revokedCertificates.0.extensions.cRLReason.value
crl.revokedCertificates.0.extensions.invalidityDate.value
crl.revokedCertificates.0.extensions.certificateIssuer.entries
crl.extensions.2.5.29.20       # crlNumber extension
crl.extensions.2.5.29.35       # authorityKeyIdentifier extension
```

## OCSP Target Paths

```
ocsp.status                    # Response status (Good, Revoked, Unknown)
ocsp.signatureAlgorithm        # Signature algorithm node
ocsp.signatureAlgorithm.oid    # Algorithm OID
ocsp.tbsSignatureAlgorithm     # Compatibility alias; OCSP has only one signatureAlgorithm
ocsp.responderID               # Responder ID node
ocsp.producedAt                # ProducedAt time
ocsp.thisUpdate                # ThisUpdate time
ocsp.nextUpdate                # Absent when omitted
ocsp.revokedAt                 # Present when revoked
ocsp.revocationReason          # Present when revoked
ocsp.nonce                     # nonce extension node
ocsp.nonce.present             # nonce presence (boolean)
ocsp.nonce.value               # Raw nonce bytes, when present
ocsp.nonce.length              # Nonce length in bytes, when present
ocsp.nonce.hexValue            # Nonce hex, when present
```

## Runtime decisions

| Path | Availability / meaning |
|---|---|
| `certificate.applicationPurpose` | Concrete `--purpose` input; absent when not supplied |
| `certificate.trustAnchor` | Whether the certificate is one of the explicit `--trust-anchor` inputs; absent without them |
| `certificate.pathValidation.valid` | Aggregate path decision with explicit trust anchors |
| `certificate.pathValidation.anchored` | Whether the constructed path reaches an explicit anchor |
| `certificate.pathValidation.findingCount` | Number of structured path findings |
| `certificate.pathValidation.failureSummary` | Present only on path failure |
| `certificate.pathValidation.findings.*` | Code, reference, status, certificate position, message, details |

Path validation is attached to the target certificate during lint evaluation.
A rule decided by the `pathValid` operator carries the structured findings in
its result; rules over these nodes see only the projected values.
`pcl inspect` shows profile projections; it does not accept the lint-only
`--trust-anchor`, `--max-path-length`, `--path-revocation`, or `--peer-name`
flags.

CRL `isCACRL` is a profile classification: a CA signer, or a window longer than
10 days when no CA signer is available. It does not prove signature validity.

## Critical-extension processing

The OID identity catalog and processed-extension registry serve different
purposes. `noUnknownCriticalExtensions` rejects duplicate OIDs before checking
criticality. A critical extension must be registered for its exact location
(certificate, CRL, or CRL entry) and have neither `malformed` nor `unprocessed`
set. Adding an OID alias does not authorize processing.

## Result format

Text output shows verdict, severity, rule ID, and reference. `--details` adds
wrapped explanations. JSON and YAML carry each displayed rule's findings;
verbosity still filters the rule list.

Unless `--show-meta=false`, the output starts with run metadata (`meta` in
JSON and YAML, summary lines in text) that makes a result reproducible:

| Field | Meaning |
|---|---|
| `checked_at` | When the run happened |
| `validation_time` | The evaluation time, `--validation-time` or the current time, in whole seconds |
| `policies` | Each loaded pack's `id`, `version`, and its metadata `title`, `standard`, `edition`, and `source` |
| `chain` | The evaluated certificate chain, target first, with `path_validated` (trust anchors were supplied), `anchored`, and `alternative` (a valid alternative path replaced the constructed one that failed validation) |
| `chain.certificates` | Each certificate's `cert_type`, `subject`, `issuer`, hex `serial`, `sha256` fingerprint, `cert_path`, and `trust_anchor` |
| `total_certs`, `total_rules`, `passed_rules`, `failed_rules`, `skipped_rules` | Result counts |

| Field | Meaning |
|---|---|
| `policy_id`, `cert_type`, `cert_path`, `source` | Policy and evaluated input |
| `verdict` | Policy `pass`, `fail`, or `not_applicable` when every rule was skipped; only failed error-severity rules fail the policy |
| `checked_at` | Result creation time |
| `rules` | Emitted rule results, filtered by verbosity |

Each rule result has `rule_id`, `reference`, `verdict`, `severity`, an optional
`message` from the policy or an evaluation error, and `findings` that explain
the verdict. Every finding has `code`, `status`, `certificate_index`, and
`message`; domain findings may add `reference`, `certificate_subject`, and
structured `details`.

| Finding code | Meaning |
|---|---|
| Operator name, such as `eq` or `dateDiff` | What the operator observed and required; `certificate_index` is `-1` |
| `path.*` | The path engine's findings, reported by `pathValid` |
| `rule.certificate-type` | Skipped: the rule's `certType` excludes the input |
| `rule.input-type` | Skipped: the rule does not apply to this input type |
| `rule.condition` | Skipped: the `when` condition was not met |
| `rule.input-unavailable` | Skipped: the target's input namespace was not supplied |

See [output controls](QUICKSTART.md#output-and-exit-status) for verbosity and
exit-status behavior.
