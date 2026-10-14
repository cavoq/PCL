# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `pcl inspect` prints the node tree that policies evaluate for each
  certificate, CRL and OCSP response, using the same inputs and projections
  as a lint run. `--paths` lists every rule target path with its value and
  type; `--output json|yaml` emits the tree or path list as data.
- JSON Schema for policy files (`schemas/policy.schema.json`, also printed by
  `pcl schema`) for editor completion and validation of fields, operator
  names and per-operator operands. Shipped policies reference it.
- `pcl test` runs policy test suites (`*.test.yaml`) that lint example inputs
  with a fixed evaluation time and check expected verdicts per input, policy
  and rule, or an expected error.

### Fixed
- Command errors are printed once, and runtime failures no longer print the
  full usage text; usage is still shown for flag and argument errors.

## [5.0.0] - 2026-10-14

### Breaking Changes
- ReasonFlags nodes share one shape in certificate and CRL trees
  (`cRLDistributionPoints` and `freshestCRL` `reasons`,
  `issuingDistributionPoint.onlySomeReasons`). Every defined flag is an
  explicit boolean, the node value is the reason mask, `present` is set, and
  `raw`/`value` are plain bytes. Certificate policies that tested a single
  flag with `present` or `absent` should use `eq: true` or `eq: false`.
- `in`, `notIn` and `contains` compare strictly: values of different kinds
  no longer match by their string form (`1` and `"1"`, `true` and `"true"`).
  Numbers of different Go types still compare numerically.

### Added
- BSI TR-03116 TLS server certificate profile
  (`policies/TR03116-TLS-SERVER.yaml`) with a coverage matrix for checks that
  need evidence outside a standalone certificate.
- `notRevokedByAvailableEvidence` operator combining the CRL and OCSP
  assessments: revoked evidence wins, otherwise at least one mechanism must
  establish good status.

### Changed
- Paths inside `every` and `dateDiff` operands resolve with the same rules as
  rule targets: dotted keys such as OIDs resolve at any segment, and empty
  segments (`a..b`) no longer collapse.
- CRL trees decode `otherName` and `ediPartyName` GeneralNames like
  certificate trees.
- `regex`, `anyComponentMatches`, `noComponentMatches`, the component length
  and regex operators and the CIDR operators traverse collection elements the
  same way as `every`, ignoring named metadata beside indexed elements.
- Input validation runs before any policy or input is loaded; `--issuer`
  without a certificate, CRL or OCSP input is rejected immediately.

### Fixed
- `--data-dir` is honored when loading the Public Suffix List.
- Policy-level `certType` classifies CA certificates with the strict
  basicConstraints decoding used for rule-level roles, so a malformed
  extension no longer makes a certificate a CA for policy selection only.
- Adding an OCSP nonce no longer overwrites bytes of the caller's request
  buffer.
- Running with `--crl` and `--ocsp` but no certificate now lints the OCSP
  responses as well; previously only the CRLs were evaluated.
- `certificatePolicyValid` now implements RFC 5280 Section 6.1 policy
  processing. Policy constraints were previously never decoded and the
  inhibitAnyPolicy and inhibitPolicyMapping skip counts were applied in the
  wrong direction. The self-signed chain top is treated as the trust anchor
  and its policies are no longer processed.

## [4.0.0] - 2026-09-20

### Breaking Changes
- Removed the arbitrary first-list `certificate.crl` projection. Certificate
  evaluation now exposes one domain-owned `certificate.revocation` assessment
  with an explicit `good`, `revoked`, or `unknown` status.
- RFC 5280 revocation policy now reports indeterminate status separately from
  a proven revocation. Custom policies should inspect
  `certificate.revocation.status` instead of treating every non-Good result as
  the same condition.

### Added
- Strict shared representations for CRL distribution points, Freshest CRL,
  Issuing Distribution Point, CRL and delta numbers, and RFC 5280 CRL-entry
  extensions, with exact location-specific critical-extension processing.
- Deterministic RFC 5280 Section 6.3 CRL assessment covering scope and reason
  accumulation, indirect CRLs, complete/delta combination, and
  `removeFromCRL`, while preserving Unknown for insufficient evidence.
- Evaluation-scoped CRL retrieval with bounded DER responses, cached failures,
  URL and signed-object deduplication, retained origins, and two-stage
  CRLDP/Freshest discovery.
- Bidirectional policy-coverage validation that rejects missing, duplicate, or
  stale rule classifications.

### Changed
- Automatic CRL acquisition is HTTP(S)-only and DER-only, uses the certificate
  fetch timeout (10 seconds by default), and follows complete-CRL Freshest
  locations in a bounded second stage. Explicit `--crl` inputs continue to
  accept PEM or DER.
- CRL signer evidence now requires `cRLSign` when the signer certificate has a
  Key Usage extension. Full same-trust-anchor signer-path validation remains
  the P4 boundary.
- P3 revocation processing is complete within its documented exact-name and
  supplied-signer boundaries; P4 certification-path and Section 7 name
  validation are next.

## [3.0.0] - 2026-07-19

### Breaking Changes
- `noUnknownCriticalExtensions` now uses an explicit, conservative
  certificate-only processed-extension registry. A catalog-known but
  unprocessed OID or value, non-certificate, P3-only, or malformed critical
  extension now fails closed, and repeated instances of an extension OID fail
  before criticality lookup.
- Strict P2 extension nodes distinguish omitted DEFAULT/OPTIONAL fields from
  encoded zero values with `*Present` facts. Custom policies that inferred
  absence from zero should migrate to those presence nodes.
- Removed the lossy root-level `certificate.ocspURL`, `certificate.caIssuersURL`, `certificate.cRLDistributionPoints`, and `certificate.certificatePolicies` projections. Use `certificate.extensions.authorityInfoAccess.accessDescriptions.*.accessLocation.value` (or its `containsOCSP` / `containsCaIssuers` facts), `certificate.extensions.cRLDistributionPoints.distributionPoints.*.distributionPoint.fullName.generalNames.*.value`, and `certificate.extensions.certificatePolicies.<policy OID>` respectively.
- Removed `certificate.subjectEmpty`; use `isEmpty` on `certificate.subject`. Validity endpoint `format` is now `rawValue`, while `isUTC` is represented by `encoding == 23` (`24` denotes GeneralizedTime).
- Removed the `utctimeHasZulu`, `utctimeHasSeconds`, `generalizedTimeHasZulu`, `generalizedTimeNoFraction`, `isUTCTime`, `isGeneralizedTime`, `noUniqueIdentifiers`, `keyUsageCA`, `keyUsageLeaf`, `sanRequiredIfEmptySubject`, and `componentTLDRegistered` operators. Compose the projected fields with `when`, `every`, and generic comparison/presence operators.
- `componentRegex` and `validIA5String` now accept one scalar value. Wrap collection targets in `every`.
- `isIA5String` and `isPrintableString` now require actual `encoding` metadata; use `validIA5String` or `validPrintableString` for character-set compatibility checks.
- DN attribute aliases are now collections of occurrence nodes rather than first-value scalars, and string length operators count Unicode code points rather than UTF-8 bytes. Custom policies must use `every` for all DN occurrences and review non-ASCII length expectations.

### Added
- `--purpose` application-purpose input and the
  `applicationPurposeValid` RFC 5280 profile rule for EKU plus compatible
  end-entity Key Usage; concrete friendly EKU names and dotted OIDs are
  matched exactly from extension DER, `any`, `anyExtendedKeyUsage`, and
  `2.5.29.37.0` are rejected, and
  private purposes fail closed when end-entity Key Usage is present because no
  RFC mapping exists
- Strict, lossless parsers and node schemas for Key Usage, Basic Constraints,
  Extended Key Usage, Certificate Policies, Name Constraints, Policy Mappings,
  Policy Constraints, `inhibitAnyPolicy`, and complete CRL Distribution Point
  structures
- Exact decimal and native-range metadata for unbounded extension counters, so
  large valid `(0..MAX)` INTEGER values remain well-formed
- Domain-owned P2 dependency operators for Basic Constraints/Key Usage, Name
  Constraints distances, CRL Distribution Points, Policy Mappings, Policy
  Constraints, and `inhibitAnyPolicy`
- A processed-extension registry separate from the RFC extension identity
  catalog, with a conservative certificate-only processed set and stable-set
  tests; critical CRL and CRL-entry extensions fail closed pending P3
- Deterministic P2 purpose/path vectors, malformed-DER vectors, and an
  executable invariant that every active RFC 5280 rule is classified in the
  coverage matrix
- Lossless X.501 Name projection for certificate subjects and issuers, CRL issuers, and raw `directoryName` values in SAN, IAN, AIA, and CRL distribution-point GeneralNames, including RDN grouping, duplicate attributes, raw DER, and ASN.1 value tags
- Canonical collection iteration that keeps indexed values ordered while excluding metadata and compatibility aliases
- Lossless TBSCertificate metadata for encoded serial numbers, validity time formats, and issuer/subject UniqueIdentifiers
- One RFC 5280 extension catalog for OIDs, stable aliases, and certificate, CRL, and CRL-entry locations
- Separate RFC 6960 and local-profile policy bundles
- Integration wiring for the opt-in RFC 6960 bundle, which requires valid, matching, good OCSP evidence for leaf certificates

### Changed
- RFC 5280 roadmap P2 is complete as bounded certificate-profile semantics;
  CRL scope/delta/indirect processing remains P3 and complete Sections 6/7
  validation remains P4
- `pathLenValid` counts non-self-issued intermediates below the current CA in
  the supplied leaf-to-root chain
- Name Constraints apply supported DNS, email, URI, and IP forms while
  constraining a subject-DN emailAddress when SAN is absent and remaining
  explicitly partial relative to the Sections 6/7 state machine
- RFC 5280 distinguished-name rules now evaluate every attribute occurrence and use actual wire tags for encoding checks
- SAN and IAN GeneralNames are projected from raw entries with their scalar value, tag, raw DER, and raw content
- Remaining multi-valued RFC 5280 rules compose scalar operators through `every`
- Time, Key Usage, SAN-presence, and UniqueIdentifier rules use generic policy operators over projected facts
- String length operators count Unicode code points instead of UTF-8 bytes

### Removed
- Redundant time, UniqueIdentifier, Key Usage, SAN-presence, and collection-wrapper operators superseded by generic policy composition

## [2.1.0] - 2026-06-22

### Changed
- Unified CA Issuers traversal and added AIA-based CRL-signer resolution.
- Improved CRL/OCSP signer resolution when issuer pools contain multiple certificates.

### Tests
- Expanded CRL, OCSP, AIA-resolution, and patch coverage.

## [2.0.0] - 2026-05-08

### Breaking Changes
- Policy YAML: `appliesTo` renamed to `certType` — existing policy files must be updated
- Node tree semantics for absent fields and `isNull` redesigned; policies relying on prior evaluation behavior of absent/null nodes may produce different results

### Added
- `--version` flag; GoReleaser injects the tag via ldflags
- Auto-validate mode: chain climbing via CA Issuers URLs, PKCS#7 bundle support, automatic OCSP/CRL fetching (`--auto-validate`, `--no-auto-chain`, `--no-auto-crl`, `--no-auto-ocsp`, `--max-chain-depth`)
- RFC 9654 OCSP nonce support (`--ocsp-nonce-length`, `--ocsp-nonce-value`, `--no-ocsp-nonce`)
- OCSP CertID hash algorithm selection (`--ocsp-hash sha1|sha256`)
- PSL-based TLD and domain validation operators (BR 4.2.2, 3.2.2.6)
- ASN.1 parsers for AIA, CRL Distribution Points, Certificate Policies, NameConstraints, IssuerAltName, and CABFOrganizationIdentifier extensions
- Policy-friendly names on `certificatePolicies` nodes (root-level and nested)
- `every` operator: wildcard paths and unified operands
- `noUnknownCriticalExtensions` operator extended to cover CRLs
- `ocspSigning` certificate type detection via EKU
- Enhanced certificate type detection and additional validation operators
- Dual CRL/OCSP evaluation with source tracking in auto-validate mode
- Rule-level auto-skip based on input type
- RFC 4055 compliance checking policy
- Integration test suite covering linter, AIA, CRL, OCSP, and chain flows
- Architecture overview document

### Fixed
- RFC 5280 §6.1.4(g) path validation
- OCSP responses must match certificate serial number
- OCSP issuer binding and response selection validated correctly
- Unknown OCSP status no longer treated as not-revoked
- Node tree semantics for absent fields and `isNull` operator
- `crlSignedBy` operator skips non-applicable CRLs
- Wildcard path resolver returns nil when nothing matches
- `certType` field renamed from `appliesTo` for consistency
- Cycle detection in chain climbing

### Changed
- Evaluation, linter, autofetching, OCSP, ASN.1, and AIA packages refactored for maintainability
- Unified format and source struct definitions
- CRL fetching extracted into dedicated module
- Policy writing guide rewritten against actual policy usage

### Migration from v1.x
Replace `appliesTo` with `certType` in all policy YAML files:
```yaml
# before
appliesTo: leaf

# after
certType: leaf
```

Review any policies using `isNull` or absent-field checks against the updated node tree semantics.

## [1.1.1] - 2026-01-10

- GoReleaser configuration added

## [1.1.0] - 2025-12-15

- See git history for earlier changes

[Unreleased]: https://github.com/cavoq/PCL/compare/v5.0.0...HEAD
[5.0.0]: https://github.com/cavoq/PCL/compare/v4.0.0...v5.0.0
[4.0.0]: https://github.com/cavoq/PCL/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/cavoq/PCL/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/cavoq/PCL/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/cavoq/PCL/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/cavoq/PCL/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cavoq/PCL/compare/v1.0.0...v1.1.0
