# RFC 5280 Policy Coverage

This document tracks the RFC 5280 requirements implemented by PCL's profile
policy. The policy is a certificate and CRL **linter**; it is not an
RFC-equivalent Section 6 certification-path validator. Its P3 CRL assessment
is deterministic and fail-closed, but remains partial until P4 supplies
same-trust-anchor signer paths and Section 7 name equivalence.

Implementation order, architectural ownership, and completion criteria are
tracked in the [RFC 5280 conformance roadmap](../docs/RFC5280_ROADMAP.md).

`Covered` means the active rule's stated profile check has executable positive
and negative behavior. `Partial` means the rule checks only part of the
normative requirement, usually because complete P4 path/name processing is
outside the profile-linter boundary. `Not active` means there is
no enabled `RFC5280.yaml` rule for the requirement. Parser behavior is credited
only where a dedicated malformed-DER test exists.

## Active rule classification

This ledger is exhaustive for the rules currently enabled in
[`RFC5280.yaml`](RFC5280.yaml). A grouped row gives every listed rule the same
classification; supplemental checks can be executable while still `Partial`
as RFC 5280 coverage.

| Area | Classification | Active rule IDs |
|------|----------------|-----------------|
| TBSCertificate boundary | Covered | `tbs-certificate-metadata-well-formed` |
| Version | Covered | `version-v3-when-extensions`, `version-v2-when-unique-id`, `version-v2-when-subject-unique-id` |
| Serial number | Covered | `serial-number-present`, `serial-number-positive`, `serial-number-length` |
| Signature AlgorithmIdentifier equality | Covered | `signature-algorithm-matches-tbs` |
| Certificate signature against supplied issuer evidence | Partial | `signature-valid` |
| Encoded certificate Names | Covered | `issuer-name-well-formed`, `subject-name-well-formed` |
| Required certificate Names | Covered | `issuer-not-empty`, `subject-not-empty-for-ca` |
| Root self-issuance heuristic | Partial | `issuer-matches-subject-for-root` |
| Certificate validity | Covered | `not-expired`, `not-yet-valid`, `validity-order-correct` |
| UniqueIdentifier profile | Covered | `issuer-unique-id-absent`, `subject-unique-id-absent` |
| Certificate critical-extension processing | Partial | `no-unknown-critical-extensions` |
| AKI profile | Covered | `authority-key-identifier-present`, `aki-not-critical` |
| AKI/SKI relationship in the supplied chain | Partial | `aki-matches-ski` |
| SKI profile | Covered | `subject-key-identifier-present`, `ski-not-critical` |
| Key Usage syntax and profile semantics | Covered | `key-usage-well-formed`, `key-usage-dependencies-valid`, `key-usage-present`, `key-usage-has-at-least-one-bit`, `key-usage-critical-for-ca`, `ca-key-cert-sign`, `leaf-key-usage-valid` |
| Certificate Policies structure | Covered | `certificate-policies-well-formed` |
| Policy Mappings profile semantics | Covered | `policy-mappings-well-formed`, `policy-mappings-dependencies-valid`, `policy-mappings-issuer-policies-present`, `policy-mappings-critical` |
| Subject Alternative Name structure/profile | Covered | `san-general-names-well-formed`, `san-required-if-empty-subject`, `san-critical-if-subject-empty` |
| Issuer Alternative Name structure/profile | Covered | `ian-general-names-well-formed`, `ian-not-critical` |
| Subject Directory Attributes criticality | Covered | `subject-directory-attributes-not-critical` |
| Basic Constraints structure/profile | Covered | `basic-constraints-well-formed`, `basic-constraints-dependencies-valid`, `basic-constraints-present`, `basic-constraints-critical-for-ca`, `ca-basic-constraints`, `leaf-not-ca` |
| Path-length counting over the supplied chain | Partial | `ca-path-len-valid` |
| Name Constraints structure/profile | Covered | `name-constraints-well-formed`, `name-constraints-dependencies-valid`, `name-constraints-distances-valid`, `name-constraints-critical` |
| Name Constraints matching | Partial | `name-constraints-valid` |
| Policy Constraints profile semantics | Covered | `policy-constraints-well-formed`, `policy-constraints-dependencies-valid`, `policy-constraints-critical` |
| Explicit application-purpose/EKU profile | Covered | `extended-key-usage-well-formed`, `extended-key-usage-allows-application-purpose`, `any-extended-key-usage-not-critical` |
| CRL Distribution Points certificate profile | Covered | `crl-distribution-points-well-formed`, `crl-distribution-points-dependencies-valid`, `crl-distribution-points-not-critical` |
| inhibitAnyPolicy profile semantics | Covered | `inhibit-any-policy-well-formed`, `inhibit-any-policy-dependencies-valid`, `inhibit-any-policy-critical` |
| Freshest CRL certificate structure/criticality | Covered | `freshest-crl-well-formed`, `freshest-crl-not-critical` |
| AIA criticality | Covered | `aia-not-critical` |
| Downloaded caIssuers representation | Partial | `ca-issuers-der-format` |
| SIA criticality | Covered | `sia-not-critical` |
| Encoded CRL issuer Name | Covered | `crl-issuer-name-well-formed` |
| CRL window, required nextUpdate, signature, and algorithms | Covered | `crl-valid`, `crl-next-update-present`, `crl-signed-by`, `crl-signature-algorithm-matches-tbs` |
| Certificate revocation conclusion | Partial | `cert-revocation-status-known`, `cert-not-revoked` |
| CRL AKI and CRL Number profile | Covered | `crl-aki-well-formed`, `crl-aki-not-critical`, `crl-authority-key-identifier-present`, `crl-number-well-formed`, `crl-number-not-critical`, `crl-number-present` |
| Delta CRL and IDP structure/profile | Covered | `crl-delta-indicator-well-formed`, `crl-delta-indicator-critical`, `crl-idp-well-formed`, `crl-idp-critical`, `crl-idp-excludes-attribute-certificates` |
| CRL Freshest structure/profile | Covered | `crl-freshest-well-formed`, `crl-freshest-not-critical`, `crl-delta-omits-freshest` |
| CRL critical-extension processing | Covered | `crl-no-unknown-critical-extensions` |
| CRL-entry extension structure/criticality | Covered | `crl-entry-reason-valid`, `crl-entry-reason-not-critical`, `crl-entry-invalidity-date-well-formed`, `crl-entry-invalidity-date-not-critical`, `crl-entry-certificate-issuer-well-formed`, `crl-entry-certificate-issuer-critical` |
| Appendix A subject lengths | Partial | `subject-cn-max-length`, `subject-org-max-length`, `subject-ou-max-length`, `subject-locality-max-length`, `subject-state-max-length`, `subject-country-length`, `subject-country-min-length`, `subject-serial-number-max-length`, `subject-givenname-max-length`, `subject-surname-max-length` |
| Subject email syntax | Partial | `subject-email-max-length`, `subject-email-format` |
| GeneralName mailbox shape | Partial | `san-rfc822-name-format`, `ian-rfc822-name-format` |
| Supplemental DNS/URI checks | Partial | `ian-dns-valid-label`, `san-uri-no-fragment`, `subject-dc-label-max-length` |
| Validity encoding choice | Covered | `validity-notbefore-utctime-through-2049`, `validity-notbefore-generalizedtime-from-2050`, `validity-notafter-utctime-through-2049`, `validity-notafter-generalizedtime-from-2050` |
| UTCTime wire requirements | Covered | `validity-utctime-has-seconds`, `validity-utctime-has-seconds-notafter`, `validity-utctime-has-zulu-notbefore`, `validity-utctime-has-zulu-notafter` |
| GeneralizedTime wire requirements | Covered | `validity-generalizedtime-has-seconds-notbefore`, `validity-generalizedtime-has-seconds-notafter`, `validity-generalizedtime-has-zulu-notbefore`, `validity-generalizedtime-has-zulu-notafter`, `validity-generalizedtime-no-fraction`, `validity-generalizedtime-no-fraction-notafter` |
| Subject attribute encoding | Partial | `subject-country-printable-string`, `subject-cn-valid-encoding` |
| Leaf SAN IA5 repertoire | Partial | `san-dnsname-valid-ia5string`, `san-uri-valid-ia5string`, `san-email-valid-ia5string` |
| IAN IA5 repertoire | Covered | `ian-dnsname-valid-ia5string`, `ian-uri-valid-ia5string`, `ian-email-valid-ia5string` |

## Executable evidence

- [`tests/vector_coverage_test.go`](../tests/vector_coverage_test.go) enforces
  that every active rule appears on a classified line above and exercises
  malformed critical-extension vectors.
- [`tests/deterministic_pki_test.go`](../tests/deterministic_pki_test.go)
  supplies deterministic application-purpose and path-length boundary vectors.
- [`internal/cert/zcrypto/extension_parser_test.go`](../internal/cert/zcrypto/extension_parser_test.go),
  [`key_extensions_test.go`](../internal/cert/zcrypto/key_extensions_test.go),
  [`extension_schema_test.go`](../internal/cert/zcrypto/extension_schema_test.go),
  and [`builder_test.go`](../internal/cert/zcrypto/builder_test.go) cover strict
  DER rejection, presence-preserving node schemas, and concrete-node
  `malformed` projection.
- [`internal/cert/extension_dependencies_test.go`](../internal/cert/extension_dependencies_test.go),
  [`purpose_test.go`](../internal/cert/purpose_test.go),
  [`path_constraints_test.go`](../internal/cert/path_constraints_test.go), and
  [`name_constraints_test.go`](../internal/cert/name_constraints_test.go) cover
  the owning profile-domain decisions.
- [`internal/oid/processed_extensions_test.go`](../internal/oid/processed_extensions_test.go)
  and [`internal/operator/constraints_test.go`](../internal/operator/constraints_test.go)
  lock the conservative location-specific processed set,
  known-but-unprocessed rejection, alias deduplication, duplicate-OID
  rejection, and malformed critical-extension failure.
- [`internal/x509ext/x509ext_test.go`](../internal/x509ext/x509ext_test.go) and
  [`internal/crl/zcrypto/extensions_test.go`](../internal/crl/zcrypto/extensions_test.go)
  cover the shared strict distribution-point, IDP, integer, Freshest CRL, and
  entry extension representations.
- [`internal/crl/status_assessment_test.go`](../internal/crl/status_assessment_test.go) covers the
  deterministic complete, scoped, reason-partitioned, indirect, and delta CRL
  decisions. [`internal/crl/acquisition_test.go`](../internal/crl/acquisition_test.go)
  covers cached, bounded, two-stage network acquisition.
- [`tests/cases_test.go`](../tests/cases_test.go) runs the scenarios in
  [`tests/cases`](../tests/cases) through the lint command, with generated DER
  vectors from [`tests/fixtures_test.go`](../tests/fixtures_test.go), and
  [`tests/pkits_test.go`](../tests/pkits_test.go) runs NIST PKITS. Existing operator owner tests cover comparison, date, encoding,
  collection, chain, CRL, and signature behavior used by the remaining rows.

## P3 boundary

P3 adds deterministic RFC 5280 Section 6.3 CRL processing without claiming the
complete Sections 6 or 7 path/name engines. `--purpose` supplies one concrete friendly EKU name or
dotted OID; `any`, `anyExtendedKeyUsage`, and `2.5.29.37.0` are rejected, and a
private OID fails closed when end-entity Key Usage is present. The active
purpose rule is conditional and is skipped when the input is absent. Name
Constraints matching is limited to the implemented DNS, email, URI, and IP
forms. It implements the
documented matching boundaries (including case-sensitive mailbox local parts
and the subject-DN emailAddress fallback when SAN is absent), but complete
Section 7 validation and normalization of constraint-base value forms remains
P4.
`pathLenConstraint` counts non-self-issued intermediates in an already ordered
leaf-to-root chain. Policy extension counters and mappings are preserved and
profile-checked but do not drive a policy state machine.

The processed-extension registry is deliberately separate from the identity
catalog and registers support at one exact signed-object location. A critical
extension passes only when its OID is registered there and its concrete node
has neither a `malformed` nor `unprocessed` marker. P3 registers the CRL and
entry extensions that its strict decoder and assessment actually consume;
known-but-unprocessed, wrong-location, malformed, duplicated, and unknown
critical extensions still fail closed.

CRL assessment checks exact distribution-point/issuer encodings, reason-mask
coverage, indirect entry issuer inheritance, compatible complete/delta pairs,
signatures, AKI, and `cRLSign` when Key Usage is present. It returns Good only
for full accepted reason coverage, Revoked only from an accepted matching
entry, and Unknown otherwise. Certification-path validation for a CRL signer
to the target path's trust anchor, CRL-signer revocation, attribute
certificates, and Section 7-equivalent name comparison remain P4 boundaries.

---

## Certificate Fields (Section 4.1)

Raw TBSCertificate metadata is parsed once and preserved for serial-number
octets, validity encodings, and optional UniqueIdentifiers. A malformed
metadata boundary is reported by `tbs-certificate-metadata-well-formed`
instead of silently disabling dependent rules.

### 4.1.2.1 Version
| Requirement | Level | Rule |
|-------------|-------|------|
| Version MUST be 3 when extensions present | MUST | `version-v3-when-extensions` |
| Version MUST be v2 or v3 when a UniqueIdentifier is present | MUST | `version-v2-when-unique-id`, `version-v2-when-subject-unique-id` |
| Version SHOULD be 1 when only basic fields | SHOULD | (not enforced - all versions valid) |

### 4.1.2.2 Serial Number
| Requirement | Level | Rule |
|-------------|-------|------|
| Serial number MUST be positive integer | MUST | `serial-number-positive` |
| Serial number MUST be unique per CA | MUST | External issuance-database requirement; not enforceable from one path |
| Encoded serial-number content MUST NOT exceed 20 octets | MUST | `serial-number-length` |

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
| Dates through 2049 use UTCTime; dates from 2050 use GeneralizedTime | MUST | `validity-*-utctime-through-2049`, `validity-*-generalizedtime-from-2050` |
| UTCTime MUST include seconds and use Z | MUST | `validity-utctime-has-seconds*`, `validity-utctime-has-zulu-*` |
| GeneralizedTime MUST include seconds, use Z, and omit fractional seconds | MUST | `validity-generalizedtime-has-seconds-*`, `validity-generalizedtime-has-zulu-*`, `validity-generalizedtime-no-fraction*` |

### 4.1.2.6 Subject
| Requirement | Level | Rule |
|-------------|-------|------|
| Subject MUST be non-empty for CA certs | MUST | `subject-not-empty-for-ca` |
| If subject empty, SAN MUST be present | MUST | `san-required-if-empty-subject` |

### 4.1.2.8 Unique Identifiers
| Requirement | Level | Rule |
|-------------|-------|------|
| Conforming CAs MUST NOT generate issuerUniqueID | MUST NOT | `issuer-unique-id-absent` |
| Conforming CAs MUST NOT generate subjectUniqueID | MUST NOT | `subject-unique-id-absent` |

### 4.1.2.9 Extensions
| Requirement | Level | Rule |
|-------------|-------|------|
| A certificate MUST NOT include more than one instance of an extension OID | MUST NOT | `no-unknown-critical-extensions` |

---

## Distinguished Names and Appendix A Attribute Syntax

PCL preserves the ordered RDN sequence, multi-valued RDN grouping, duplicate
attributes, raw DER, and the actual ASN.1 value tag for certificate subject and
issuer names and CRL issuer names. Subject attribute aliases are collections;
the rules below use `every` so each occurrence is checked rather than only the
first value. These representation and syntax checks do not claim RFC 5280
Section 7 internationalized-name comparison.

| Requirement | Status | Rule |
|-------------|--------|------|
| Reject a malformed DER certificate subject or issuer Name instead of skipping attribute rules | Covered | `subject-name-well-formed`, `issuer-name-well-formed` |
| Reject a malformed DER CRL issuer Name | Covered | `crl-issuer-name-well-formed` |
| Enforce Appendix A upper bounds for every commonName, organizationName, organizationalUnitName, localityName, stateOrProvinceName, serialNumber, givenName, and surname occurrence | Partial (leaf/intermediate subjects only) | `subject-cn-max-length`, `subject-org-max-length`, `subject-ou-max-length`, `subject-locality-max-length`, `subject-state-max-length`, `subject-serial-number-max-length`, `subject-givenname-max-length`, `subject-surname-max-length` |
| Enforce a two-character countryName for every occurrence | Partial (leaf/intermediate subjects only) | `subject-country-length`, `subject-country-min-length` |
| Enforce subject emailAddress length and basic mailbox shape for every occurrence | Partial | `subject-email-max-length`, `subject-email-format` |
| Enforce a 128-character businessCategory bound | Supplemental (`LOCAL-PROFILE.yaml`) | `subject-business-category-max-length` |
| Enforce the domainComponent label bound for every occurrence | Supplemental (RFC 5890) | `subject-dc-label-max-length` |
| Check each subject countryName's actual ASN.1 tag is PrintableString (tag 19) | Partial (warning; leaf/intermediate subjects only) | `subject-country-printable-string` |
| Check each subject commonName's actual ASN.1 tag is a DirectoryString alternative | Partial (warning; leaf subjects only) | `subject-cn-valid-encoding` |

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
| BIT STRING is well-formed and uses only defined, canonical bits | MUST | `key-usage-well-formed` |
| keyCertSign is asserted only by a CA certificate | MUST | `key-usage-dependencies-valid` |
| CA signing certificates MUST include Key Usage | MUST | `key-usage-present` (the policy treats root/intermediate inputs as certificate-signing roles) |
| When present, at least one bit MUST be set | MUST | `key-usage-has-at-least-one-bit` |
| CA Key Usage SHOULD be critical | SHOULD | `key-usage-critical-for-ca` |
| Certificate-signing keys MUST have keyCertSign | MUST | `ca-key-cert-sign` (root/intermediate role assumption) |
| Non-CA certs MUST NOT have keyCertSign | MUST NOT | `leaf-key-usage-valid` |

### 4.2.1.4 Certificate Policies
| Requirement | Level | Rule |
|-------------|-------|------|
| CertificatePolicies is well-formed and non-empty, policyIdentifier values are unique, and anyPolicy uses only defined qualifiers | MUST | `certificate-policies-well-formed` |

### 4.2.1.5 Policy Mappings
| Requirement | Level | Rule |
|-------------|-------|------|
| Structure is well-formed and non-empty | MUST | `policy-mappings-well-formed` |
| CA-only and neither mapping side is anyPolicy | MUST | `policy-mappings-dependencies-valid` |
| issuerDomainPolicy also appears in certificatePolicies | SHOULD | `policy-mappings-issuer-policies-present` |
| Policy Mappings SHOULD be critical | SHOULD | `policy-mappings-critical` |

### 4.2.1.6 Subject Alternative Name
| Requirement | Level | Rule |
|-------------|-------|------|
| GeneralNames and embedded directoryName values MUST be well-formed | MUST | `san-general-names-well-formed` |
| SAN MUST be present if subject empty | MUST | `san-required-if-empty-subject` |
| SAN MUST be critical if subject empty | MUST | `san-critical-if-subject-empty` |
| Every dNSName, URI, and rfc822Name contains IA5 characters | MUST | Partial (leaf certificates only): `san-dnsname-valid-ia5string`, `san-uri-valid-ia5string`, `san-email-valid-ia5string` |
| rfc822Name has a basic mailbox shape | Partial (leaf only; not full RFC 822 parsing) | `san-rfc822-name-format` |
| URI omits a fragment identifier | Partial (leaf-only warning) | `san-uri-no-fragment` |

### 4.2.1.7 Issuer Alternative Name
| Requirement | Level | Rule |
|-------------|-------|------|
| GeneralNames and embedded directoryName values MUST be well-formed | MUST | `ian-general-names-well-formed` |
| IAN SHOULD NOT be critical | SHOULD NOT | `ian-not-critical` |
| Every IAN dNSName, URI, and rfc822Name contains IA5 characters | MUST | `ian-dnsname-valid-ia5string`, `ian-uri-valid-ia5string`, `ian-email-valid-ia5string` |
| IAN rfc822Name has a basic mailbox shape | Partial (leaf/intermediate warning; not full RFC 822 parsing) | `ian-rfc822-name-format` |
| Every IAN dNSName has valid DNS labels | Supplemental (RFC 9549) | Partial (leaf/intermediate only): `ian-dns-valid-label` |

### 4.2.1.8 Subject Directory Attributes
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST NOT be critical | MUST NOT | `subject-directory-attributes-not-critical` |

### 4.2.1.9 Basic Constraints
| Requirement | Level | Rule |
|-------------|-------|------|
| Structure is well-formed and preserves DEFAULT/OPTIONAL presence | MUST | `basic-constraints-well-formed` |
| pathLenConstraint dependencies hold | MUST | `basic-constraints-dependencies-valid` |
| MUST be in CA certificates | MUST | `basic-constraints-present` |
| MUST be critical in CA certs | MUST | `basic-constraints-critical-for-ca` |
| cA MUST be TRUE for CA certs | MUST | `ca-basic-constraints` |
| pathLenConstraint enforced | MUST | Partial: `ca-path-len-valid` counts non-self-issued intermediates in the supplied ordered chain; complete Section 6 processing remains P4 |

### 4.2.1.10 Name Constraints
| Requirement | Level | Rule |
|-------------|-------|------|
| Structure and all GeneralSubtrees are well-formed | MUST | `name-constraints-well-formed` |
| Extension appears only in CA certificates | MUST | `name-constraints-dependencies-valid` |
| minimum is zero/default and maximum is absent | MUST | `name-constraints-distances-valid` |
| MUST be critical | MUST | `name-constraints-critical` |
| MUST be enforced in path validation | MUST | `name-constraints-valid` (partial: supported DNS/email/URI/IP matching only; unsupported name forms mark the critical value unprocessed; constraint-base value-form validation and complete §§6/7 processing remain P4) |

### 4.2.1.11 Policy Constraints
| Requirement | Level | Rule |
|-------------|-------|------|
| Structure is non-empty, ordered, and contains non-negative counters | MUST | `policy-constraints-well-formed` |
| Extension appears only in CA certificates | MUST | `policy-constraints-dependencies-valid` |
| MUST be critical | MUST | `policy-constraints-critical` |

### 4.2.1.12 Extended Key Usage
| Requirement | Level | Rule |
|-------------|-------|------|
| Structure is well-formed, non-empty, and preserves unknown OIDs | MUST | `extended-key-usage-well-formed` |
| Certificate permits the explicitly supplied application purpose | MUST | `extended-key-usage-allows-application-purpose`; conditional on `--purpose`; rejects `any`, `anyExtendedKeyUsage`, and `2.5.29.37.0`, and fails closed for private purposes when end-entity Key Usage is present |
| anyExtendedKeyUsage SHOULD NOT be critical | SHOULD NOT | `any-extended-key-usage-not-critical` |

### 4.2.1.13 CRL Distribution Points
| Requirement | Level | Rule |
|-------------|-------|------|
| Structure, names, and reason flags are well-formed | MUST | `crl-distribution-points-well-formed` |
| Profile dependencies hold without applying CRL scope | MUST | `crl-distribution-points-dependencies-valid` |
| SHOULD be non-critical | SHOULD | `crl-distribution-points-not-critical` |

### 4.2.1.14 Inhibit anyPolicy
| Requirement | Level | Rule |
|-------------|-------|------|
| SkipCerts is a well-formed non-negative INTEGER | MUST | `inhibit-any-policy-well-formed` |
| Extension appears only in CA certificates | MUST | `inhibit-any-policy-dependencies-valid` |
| MUST be critical | MUST | `inhibit-any-policy-critical` |

### 4.2.1.15 Freshest CRL
| Requirement | Level | Rule |
|-------------|-------|------|
| Distribution-point structure is well-formed | MUST | `freshest-crl-well-formed` |
| MUST NOT be critical | MUST NOT | `freshest-crl-not-critical` |

### 4.2.2.1 Authority Information Access
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST NOT be critical | MUST NOT | `aia-not-critical` |
| An HTTP/FTP caIssuers resource identifies DER certificate or PKCS#7 data | MUST | Partial (checks the observed download format is not PEM): `ca-issuers-der-format` |

### 4.2.2.2 Subject Information Access
| Requirement | Level | Rule |
|-------------|-------|------|
| MUST NOT be critical | MUST NOT | `sia-not-critical` |

---

## Path Validation (Section 6)

PCL implements the bounded CRL assessment described under Section 6.3 below.
The remaining checks are independent profile checks, not the complete RFC
5280 Section 6 certification-path state machine. PCL has an explicit
application-purpose input, but no explicit trust-anchor, initial-policy-set,
or policy-inhibition state.

| Requirement | Status | Rule |
|-------------|--------|------|
| Signature verification | Partial | `signature-valid` |
| Issuer/Subject DN chaining | Partial | `issuer-matches-subject-for-root` and internal chain heuristics |
| Validity period checking | Covered as profile lint | `not-expired`, `not-yet-valid` |
| Path length constraints | Partial | `ca-path-len-valid` |
| Name constraints processing | Partial | `name-constraints-valid` |
| Policy processing | Not active | `certificatePolicyValid` operator exists, but the policy rule is disabled |
| Unknown/unprocessed critical extensions rejection | Partial | `no-unknown-critical-extensions`; exact processed set and malformed or explicitly unprocessed values are fail-closed, but full Section 6 extension effects remain P4 |

---

## CRL Profile (Section 5)

### CRL Fields
| Requirement | Level | Rule |
|-------------|-------|------|
| Signature valid | MUST | `crl-signed-by` |
| Inner and outer signature algorithms match | MUST | `crl-signature-algorithm-matches-tbs` |
| thisUpdate not in future | MUST | `crl-valid` |
| nextUpdate present and current | MUST | `crl-next-update-present`, `crl-valid` |
| Certificate revocation status | Partial | `cert-revocation-status-known`, `cert-not-revoked`; complete, scoped, reason-partitioned, indirect, and delta evidence is processed, while insufficient evidence is explicitly Unknown. CRL-signer trust-path validation and Section 7 name equivalence remain P4. |

### CRL Extensions
| Requirement | Level | Rule |
|-------------|-------|------|
| AKI is well-formed and MUST NOT be critical | MUST | `crl-aki-well-formed`, `crl-aki-not-critical` |
| AKI keyIdentifier MUST be present | MUST | `crl-authority-key-identifier-present` |
| CRL Number is a well-formed non-negative INTEGER and MUST NOT be critical | MUST | `crl-number-well-formed`, `crl-number-not-critical` |
| CRL Number MUST be present | MUST | `crl-number-present` |
| Delta CRL Indicator is well-formed and MUST be critical | MUST | `crl-delta-indicator-well-formed`, `crl-delta-indicator-critical` |
| IDP is well-formed, MUST be critical, and excludes attribute-certificate scope | MUST | `crl-idp-well-formed`, `crl-idp-critical`, `crl-idp-excludes-attribute-certificates` |
| CRL Freshest is well-formed, MUST NOT be critical, and MUST be absent from delta CRLs | MUST | `crl-freshest-well-formed`, `crl-freshest-not-critical`, `crl-delta-omits-freshest` |
| Reject unknown, malformed, duplicated, or unprocessed critical CRL extensions | MUST | `crl-no-unknown-critical-extensions`; the location-specific P3 processed set includes only extensions decoded and consumed by CRL assessment |

### CRL Entry Extensions
| Requirement | Status | Rule |
|-------------|--------|------|
| reasonCode is a canonical defined ENUMERATED and non-critical | Covered | `crl-entry-reason-valid`, `crl-entry-reason-not-critical` |
| invalidityDate is a conforming GeneralizedTime and non-critical | Covered | `crl-entry-invalidity-date-well-formed`, `crl-entry-invalidity-date-not-critical` |
| certificateIssuer is a non-empty GeneralNames value and critical | Covered | `crl-entry-certificate-issuer-well-formed`, `crl-entry-certificate-issuer-critical` |
| Reject unknown, malformed, duplicated, or unprocessed critical entry extensions | Covered | `crl-no-unknown-critical-extensions`; any unsupported critical entry poisons the CRL for status use |

---

## OCSP (RFC 6960)

OCSP is a different standard and does not contribute to RFC 5280 coverage.
Its checks are shipped separately in `RFC6960.yaml`. That opt-in bundle runs
during leaf-certificate evaluation so the response can be bound to the
certificate and issuer chain; missing or unacceptable OCSP evidence fails
closed.

| Requirement | Rule |
|-------------|------|
| Response within validity window | `ocsp-valid` |
| Response signature valid | `ocsp-valid` |
| Certificate not revoked | `ocsp-not-revoked` |

---

## Supplemental Rules (Not RFC 5280 Coverage)

Rules whose references begin with `LOCAL-` are shipped in
`LOCAL-PROFILE.yaml`; RFC 6960 rules are shipped in `RFC6960.yaml`. RFC 9549,
PSL, CA/B Forum, and reasonable-size constraints are supplemental profile
checks and must not be counted as RFC 5280 requirements.

---

## Extension OID Reference

| Extension | OID | Path |
|-----------|-----|------|
| Subject Directory Attributes | 2.5.29.9 | `certificate.extensions.2.5.29.9.critical` |
| Authority Key Identifier | 2.5.29.35 | `certificate.extensions.2.5.29.35.critical` |
| Subject Key Identifier | 2.5.29.14 | `certificate.extensions.2.5.29.14.critical` |
| Key Usage | 2.5.29.15 | `certificate.extensions.2.5.29.15.critical` |
| Private Key Usage Period | 2.5.29.16 | `certificate.extensions.2.5.29.16.critical` |
| Subject Alternative Name | 2.5.29.17 | `certificate.extensions.2.5.29.17.critical` |
| Issuer Alternative Name | 2.5.29.18 | `certificate.extensions.2.5.29.18.critical` |
| Basic Constraints | 2.5.29.19 | `certificate.extensions.2.5.29.19.critical` |
| Name Constraints | 2.5.29.30 | `certificate.extensions.2.5.29.30.critical` |
| CRL Distribution Points | 2.5.29.31 | `certificate.extensions.2.5.29.31.critical` |
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
- ASN.1, time, URI, or name validation without explicit parser and policy evidence
