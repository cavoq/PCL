# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/cavoq/PCL/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/cavoq/PCL/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/cavoq/PCL/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cavoq/PCL/compare/v1.0.0...v1.1.0
