# 🏛️ RFC 5280 Coverage

[Documentation](../docs/POLICY_WRITING_GUIDE.md) · [Policy](RFC5280.yaml) · [PKITS](../tests/pkits/README.md)

## Scope

The pack combines certificate/CRL profile checks with conditional explicit-trust
path validation. Without `--trust-anchor`, the aggregate path rule skips.
Construction selects one bounded, deterministic path from supplied/acquired
candidates; validation checks that path against explicit runtime inputs.

`Covered` means the stated check has executable positive and negative behavior.
`Partial` means only part of the normative requirement, supported forms, or
profile context is checked. Coverage does not imply universal RFC completeness.

## Requirement matrix

| Requirement | Status | Implementation | Required input | Evidence |
|---|---|---|---|---|
| Certificate fields, Names, validity encodings (§4.1) | Covered for active checks | Strict TBSCertificate facts and profile rules | Certificate DER | [Node vectors](../internal/certnode/extension_parser_test.go), [policy suites](../tests/policy-suites/rfc5280.test.yaml) |
| Extension syntax and dependencies (§4.2) | Covered for active checks | Strict extension facts and certificate domain | Certificate DER | [Schema tests](../internal/certnode/extension_schema_test.go), [domain tests](../internal/cert/extension_dependencies_test.go) |
| Critical extensions and duplicate OIDs | Partial | Location-specific processed registry; unsupported critical semantics fail closed | Signed object | [Vectors](../tests/vector_coverage_test.go), [registry tests](../internal/oid/processed_extensions_test.go) |
| DN attributes, mailbox syntax, IA5 repertoire (Appendix A) | Partial | Per-occurrence rules; role/severity limits below | Encoded Names / GeneralNames | [Policy suites](../tests/policy-suites/rfc5280.test.yaml) |
| Trust termination, signatures, validity, CA and path length (§6) | Covered | Explicit path domain; anchor is excluded from ordinary certificate processing | Target, issuer candidates, explicit anchors, time | [Path tests](../internal/path/validate_test.go), [PKITS](../tests/pkits_test.go) |
| Name constraints and name chaining (§6–7) | Partial across all RFC forms | DNS, email, URI, IP, directoryName compared; other forms reject names of that form; dNSName subtrees must be empty or in the preferred name syntax; shared encoded-DN comparison | Constructed path | [Name constraints](../internal/cert/name_constraints_test.go), [DN matching](../internal/x509asn1/name_match_test.go) |
| Certificate-policy processing (§6.1) | Covered | Policy tree, mappings, counters and independent initial inputs | Path and optional initial policy inputs | [Policy processing](../internal/operator/policy_test.go), [PKITS](../tests/pkits_test.go) |
| Application purpose | Covered for supported mappings | EKU across chain plus end-entity Key Usage | Concrete purpose and chain | [Purpose tests](../internal/cert/purpose_test.go) |
| CRL profile and entries (§5) | Covered for active checks | Strict AKI, number, delta, IDP, Freshest and entry decoding | CRL DER, signer candidates | [Extension tests](../internal/x509ext/crl_extensions_test.go) |
| CRL revocation (§6.3) | Partial across all RFC contexts | Complete, scoped, reason-partitioned, indirect and delta assessment; insufficient evidence is Unknown | Current CRLs and authenticated signer path | [Status tests](../internal/crl/status_assessment_test.go) |
| Automatic acquisition | Partial | Bounded issuer / CRL / OCSP retrieval; no inferred trust | Network locations and acquisition flags | [Acquisition tests](../internal/crl/acquisition_test.go) |

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
| Certificate signature against supplied issuer evidence | Partial | `signature-valid` (inconclusive without the issuer) |
| Explicit-trust certification-path decision (conditional on `--trust-anchor`) | Covered | `certification-path-valid` |
| Encoded certificate Names | Covered | `issuer-name-well-formed`, `subject-name-well-formed` |
| Required certificate Names | Covered | `issuer-not-empty`, `subject-not-empty-for-ca` |
| Certificate validity | Covered | `not-expired`, `not-yet-valid`, `validity-order-correct` |
| UniqueIdentifier profile | Covered | `issuer-unique-id-absent`, `subject-unique-id-absent` |
| Certificate critical-extension processing | Partial | `no-unknown-critical-extensions` |
| AKI profile | Covered | `authority-key-identifier-present`, `aki-not-critical`, `aki-well-formed` (strict decoding; authorityCertIssuer and authorityCertSerialNumber together) |
| AKI/SKI relationship in the supplied chain | Partial | `aki-matches-ski` (inconclusive without the issuer) |
| SKI profile | Covered | `subject-key-identifier-present`, `subject-key-identifier-present-leaf`, `ski-not-critical` |
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
| Certificate revocation conclusion | Partial | `cert-not-revoked` |
| CRL AKI and CRL Number profile | Covered | `crl-aki-well-formed`, `crl-aki-not-critical`, `crl-authority-key-identifier-present`, `crl-number-well-formed`, `crl-number-not-critical`, `crl-number-present` |
| Delta CRL and IDP structure/profile | Covered | `crl-delta-indicator-well-formed`, `crl-delta-indicator-critical`, `crl-idp-well-formed`, `crl-idp-critical`, `crl-idp-excludes-attribute-certificates` |
| CRL Freshest structure/profile | Covered | `crl-freshest-well-formed`, `crl-freshest-not-critical`, `crl-delta-omits-freshest` |
| CRL critical-extension processing | Covered | `crl-no-unknown-critical-extensions` |
| CRL-entry extension structure/criticality | Covered | `crl-entry-reason-valid`, `crl-entry-reason-not-critical`, `crl-entry-reason-not-unspecified`, `crl-entry-invalidity-date-well-formed`, `crl-entry-invalidity-date-not-critical`, `crl-entry-certificate-issuer-well-formed`, `crl-entry-certificate-issuer-critical` |
| Appendix A subject lengths | Partial | `subject-cn-max-length`, `subject-org-max-length`, `subject-ou-max-length`, `subject-locality-max-length`, `subject-state-max-length`, `subject-country-length`, `subject-country-min-length`, `subject-serial-number-max-length`, `subject-givenname-max-length`, `subject-surname-max-length` |
| Subject email length | Covered | `subject-email-max-length` |
| GeneralName mailbox shape | Partial | `san-rfc822-name-format`, `ian-rfc822-name-format` |
| IAN dNSName syntax and domainComponent label length | Covered | `ian-dns-valid-label`, `subject-dc-label-max-length` |
| Validity encoding choice | Covered | `validity-notbefore-utctime-through-2049`, `validity-notbefore-generalizedtime-from-2050`, `validity-notafter-utctime-through-2049`, `validity-notafter-generalizedtime-from-2050` |
| UTCTime wire requirements | Covered | `validity-utctime-has-seconds`, `validity-utctime-has-seconds-notafter`, `validity-utctime-has-zulu-notbefore`, `validity-utctime-has-zulu-notafter` |
| GeneralizedTime wire requirements | Covered | `validity-generalizedtime-has-seconds-notbefore`, `validity-generalizedtime-has-seconds-notafter`, `validity-generalizedtime-has-zulu-notbefore`, `validity-generalizedtime-has-zulu-notafter`, `validity-generalizedtime-no-fraction`, `validity-generalizedtime-no-fraction-notafter` |
| Subject attribute encoding | Partial | `subject-country-printable-string`, `subject-cn-valid-encoding`, `subject-organization-valid-encoding`, `subject-ou-valid-encoding`, `subject-locality-valid-encoding`, `subject-state-valid-encoding` |
| Leaf SAN IA5 repertoire | Partial | `san-dnsname-valid-ia5string`, `san-uri-valid-ia5string`, `san-email-valid-ia5string` |
| SAN dNSName preferred name syntax | Covered | `san-dnsname-preferred-syntax` |
| IAN IA5 repertoire | Covered | `ian-dnsname-valid-ia5string`, `ian-uri-valid-ia5string`, `ian-email-valid-ia5string` |

## Executable evidence

- [`tests/vector_coverage_test.go`](../tests/vector_coverage_test.go) enforces
  that every active rule appears on a classified line above and exercises
  malformed critical-extension vectors.
- [`tests/deterministic_pki_test.go`](../tests/deterministic_pki_test.go)
  supplies deterministic application-purpose and path-length boundary vectors.
- [`internal/certnode/extension_parser_test.go`](../internal/certnode/extension_parser_test.go),
  [`key_extensions_test.go`](../internal/certnode/key_extensions_test.go),
  [`extension_schema_test.go`](../internal/certnode/extension_schema_test.go),
  and [`builder_test.go`](../internal/certnode/builder_test.go) cover strict
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
  [`internal/x509ext/crl_extensions_test.go`](../internal/x509ext/crl_extensions_test.go)
  cover the shared strict distribution-point, IDP, integer, Freshest CRL, and
  entry extension representations.
- [`internal/crl/status_assessment_test.go`](../internal/crl/status_assessment_test.go) covers the
  deterministic complete, scoped, reason-partitioned, indirect, and delta CRL
  decisions. [`internal/crl/acquisition_test.go`](../internal/crl/acquisition_test.go)
  covers cached, bounded, two-stage network acquisition.
- The [policy suites](../tests/policy-suites) run their scenarios through
  `pcl test`, with DER vectors generated by
  [`tests/fixturegen`](../tests/fixturegen), and
  [`tests/pkits_test.go`](../tests/pkits_test.go) runs all 247 expressible NIST
  PKITS decisions through the explicit-anchor path engine with required
  revocation. Existing operator owner tests cover comparison, date, encoding,
  collection, chain, CRL, and signature behavior used by the remaining rows.
- [`internal/path/validate_test.go`](../internal/path/validate_test.go) covers
  explicit trust, construction/validation separation, structured failures,
  maximum path length, malformed inputs, and revocation modes.

## Limits

| Area | Limit |
|---|---|
| Discovery and trust | No unbounded discovery, exhaustive alternative-path validation, platform trust-store selection, or out-of-band anchor constraints |
| Name constraints | Attribute certificates are outside scope. otherName, x400Address, ediPartyName and registeredID subtrees are not compared; a subsequent certificate presenting a name of a constrained form of these fails |
| Internationalized names | No complete Section 7 preparation claim beyond supported encoded DN, DNS, email, URI and IP forms |
| CA-wide uniqueness | A path cannot prove serial-number uniqueness across a CA issuance database |
| Version preference | The SHOULD preference for v1 when only basic fields exist is not enforced |
| Attribute bounds | Appendix A length and country checks target leaf/intermediate subjects; the PrintableString/UTF8String DirectoryString rule targets leaves, since a CA subject may keep the encoding of its issued certificates' issuer field (4.1.2.4 a) |
| SAN / IAN syntax | SAN repertoire and mailbox checks target leaves; mailbox shape is not full RFC 2821 Mailbox parsing |
| CA profile roles | Root/intermediate profile rules assume certificate-signing roles for Key Usage requirements |
| Download format | `ca-issuers-der-format` checks observed format, not every normative transport requirement |
| Purpose | Private EKUs fail closed with end-entity Key Usage present; wildcard purposes are rejected |
| Other standards | RFC 6960 evidence checks, RFC 9549 DNS checks, PSL, CA/B Forum and local size/profile rules are not RFC 5280 coverage |
| Parser credit | A known OID or successful library parse alone is not evidence of full semantic processing |
| CRL entries | removeFromCRL (8) outside delta CRLs is not checked: the rule needs both "not a delta CRL" and "entries present", and a rule takes one condition |
| CRL encodings | CRL version and thisUpdate/nextUpdate time encodings are not projected, so 5.1.2.1 and 5.1.2.4 encoding rules are absent |

Revocation follows the selected `--path-revocation` mode; separate profile
rules remain active. CRL signers must reach the same explicit trust set when
anchors are supplied. See [runtime inputs](../docs/QUICKSTART.md) and
[node contracts](../docs/NODE_MODEL.md) for operational and representation details.

## Requirement levels

Every rule states the RFC 2119 level of its clause (`requirement:`), and its
severity follows from it: `must` is an error, `should` a warning. Eight
rules implement SHOULD clauses: `key-usage-critical-for-ca`,
`policy-mappings-issuer-policies-present`, `policy-mappings-critical`,
`ian-not-critical`, `any-extended-key-usage-not-critical`,
`crl-distribution-points-not-critical`, `subject-key-identifier-present-leaf`
and `crl-entry-reason-not-unspecified`; every other rule implements a MUST.

Audit of 2026-10-16 against the RFC text:

| Change | Clause |
|---|---|
| `aki-matches-ski`, `ca-issuers-der-format`, `subject-country-printable-string`, `ian-rfc822-name-format`, `ian-dns-valid-label` were warnings for MUST clauses; now errors | 4.2.1.2 (SKI MUST equal issued AKI), 4.2.2.1 (DER or certs-only CMS), Appendix A `X520countryName ::= PrintableString`, 4.2.1.7 (IAN encoded as SAN) |
| `subject-cn-valid-encoding` accepted every DirectoryString type and was a warning; end-entity DirectoryString values must be PrintableString or UTF8String, now also checked for O, OU, L and ST | 4.1.2.4, 4.1.2.6 |
| `ian-dns-valid-label` used a label-only pattern; it now applies the SAN preferred-name-syntax pattern, to every role | 4.2.1.7, 4.2.1.6 |
| `cert-revocation-status-known` failed an undetermined status; merged into `cert-not-revoked`, which is inconclusive without an applicable CRL | 6.3.3 (UNDETERMINED) |
| `issuer-matches-subject-for-root` removed: a root is self-issued by definition, so it could not fail | — |
| `subject-email-format` and `san-uri-no-fragment` moved to the local profile: RFC 5280 states neither | 4.1.2.6, 4.2.1.6 |
| Added `subject-key-identifier-present-leaf` (SHOULD) and `crl-entry-reason-not-unspecified` (SHOULD) | 4.2.1.2, 5.3.1 |
