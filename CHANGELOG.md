# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes
- Removed the lossy root-level `certificate.ocspURL`, `certificate.caIssuersURL`, `certificate.cRLDistributionPoints`, and `certificate.certificatePolicies` projections. Use `certificate.extensions.authorityInfoAccess.accessDescriptions.*.accessLocation.value` (or its `containsOCSP` / `containsCaIssuers` facts), `certificate.extensions.cRLDistributionPoints.distributionPoints.*.distributionPoint.fullName.generalNames.*.value`, and `certificate.extensions.certificatePolicies.<policy OID>` respectively.
- Removed `certificate.subjectEmpty`; use `isEmpty` on `certificate.subject`. Validity endpoint `format` is now `rawValue`, while `isUTC` is represented by `encoding == 23` (`24` denotes GeneralizedTime).
- Removed the `utctimeHasZulu`, `utctimeHasSeconds`, `generalizedTimeHasZulu`, `generalizedTimeNoFraction`, `isUTCTime`, `isGeneralizedTime`, `noUniqueIdentifiers`, `keyUsageCA`, `keyUsageLeaf`, `sanRequiredIfEmptySubject`, and `componentTLDRegistered` operators. Compose the projected fields with `when`, `every`, and generic comparison/presence operators.
- `componentRegex` and `validIA5String` now accept one scalar value. Wrap collection targets in `every`.
- `isIA5String` and `isPrintableString` now require actual `encoding` metadata; use `validIA5String` or `validPrintableString` for character-set compatibility checks.
- DN attribute aliases are now collections of occurrence nodes rather than first-value scalars, and string length operators count Unicode code points rather than UTF-8 bytes. Custom policies must use `every` for all DN occurrences and review non-ASCII length expectations.

### Added
- Lossless X.501 Name projection for certificate subjects and issuers, CRL issuers, and raw `directoryName` values in SAN, IAN, AIA, and CRL distribution-point GeneralNames, including RDN grouping, duplicate attributes, raw DER, and ASN.1 value tags
- Canonical collection iteration that keeps indexed values ordered while excluding metadata and compatibility aliases
- Lossless TBSCertificate metadata for encoded serial numbers, validity time formats, and issuer/subject UniqueIdentifiers
- One RFC 5280 extension catalog for OIDs, stable aliases, and certificate, CRL, and CRL-entry locations
- Separate RFC 6960 and local-profile policy bundles
- Integration wiring for the opt-in RFC 6960 bundle, which requires valid, matching, good OCSP evidence for leaf certificates

### Changed
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

[Unreleased]: https://github.com/cavoq/PCL/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/cavoq/PCL/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/cavoq/PCL/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/cavoq/PCL/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cavoq/PCL/compare/v1.0.0...v1.1.0
