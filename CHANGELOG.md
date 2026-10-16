# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--validation-time` evaluates a lint or `pcl inspect` run at a fixed time
  (RFC 3339 or YYYY-MM-DD) instead of now, for repeatable and historical
  results.
- Run metadata records the validation time, each loaded policy pack's
  version, standard and edition, and the evaluated chain: every certificate's
  subject, issuer, serial and SHA-256 fingerprint, the trust anchor, and
  whether a valid alternative path replaced the constructed one. Text output
  prints them below the summary line; JSON and YAML add `validation_time`,
  `policies` and `chain` to `meta`.

## [6.0.0] - 2026-10-16

### Breaking changes
- Rule results explain their verdict only through `findings`; the `details`
  string is gone from JSON and YAML (see Changed and Migration notes).
- A `when` condition on an absent target skips the rule instead of failing,
  and `neq` and `notIn` pass on an absent target.
- A dNSName name constraint with an OpenSSL-style leading period
  (`.example.com`) is malformed and rejects the certificates below the CA.
- The RFC 5280 policy fails SAN dNSNames that are not in the preferred name
  syntax, such as names with an underscore.
- With `--trust-anchor`, rules about a certificate's relation to its issuer
  skip trust anchors, including self-signed ones, where they used to pass.
- When the constructed path fails validation, a valid alternative path may be
  evaluated, so the linted chain can differ from earlier versions.

### Added
- The shipped policy packs are embedded in the binary. `--policy rfc5280`
  (or `builtin:rfc5280`) selects one by id without the repository, policy
  suites accept the ids too, and `pcl policies` lists the packs and
  `pcl policies show <id>` prints one. A file of the same name takes
  precedence over a bare id.
- A Public Suffix List snapshot is embedded and used when neither
  `--psl-file` nor the data directory provides a list, so PSL and TLD rules
  work offline; `pcl update-data` still fetches a newer list.
- Policy test expectations accept `failed`, the exact list of rules that
  fail for an input (`[]` for none).
- Optional descriptive policy `metadata` with title, standard, edition, source,
  description, and relevant input names. The parser and editor schema validate
  it; it does not change evaluation or inherit through includes.
- Dedicated RFC 5280 certification-path construction and validation domain
  with explicit trust anchors, validation time, caller maximum path length,
  application purpose, certificate-policy inputs, and selectable revocation
  mode. The CLI adds `--trust-anchor`, `--max-path-length`, and
  `--path-revocation`.
- Structured path findings with stable codes, RFC references, certificate
  positions, and pass/fail/skip status. The shipped RFC 5280 policy exposes
  one conditional `certification-path-valid` aggregate decision through the
  new `pathValid` operator. A rule decided by `pathValid` carries the
  findings in its result, whatever its target; text `--details` lists the
  failed ones.
- CRL signer paths are validated to the same explicit trust anchors before
  their revocation evidence is accepted. Path validation reuses the existing
  CRL and OCSP assessment domains.
- RFC 5280 certificate-policy validation accepts independent initial policy
  set, explicit-policy, policy-mapping-inhibit and any-policy-inhibit inputs
  through the CLI, API and policy-test cases. All 247 NIST PKITS runs now
  execute through the explicit-anchor path engine and reach their expected
  result with no gaps or unsupported inputs.
- `--peer-name` path input (repeatable; `peerNames` in policy-test cases):
  the DNS name, IP address or email address the target certificate must
  present in its subjectAltName (RFC 9525). The path decision reports a
  `path.peer-name` finding per name; the common name is not consulted and a
  wildcard matches only as the whole leftmost label. Requires
  `--trust-anchor`. Policy metadata accepts `peerNames` as an input name.

### Fixed
- When the best-ranked certification path fails validation, evaluation tries
  up to 64 other anchored paths whose signatures verify, best-ranked first,
  and uses the first valid one for the path decision and the linted chain
  (RFC 4158). Previously a valid alternative, such as one avoiding a CA whose
  name constraints exclude the target, was never tried.
- The evaluation time is truncated to whole seconds, the granularity of
  certificate, CRL and OCSP times (RFC 5280 4.1.2.5), so a certificate stays
  valid through its entire notAfter second.
- Name constraint processing is bounded: a certificate whose names times
  the issuers' constraint subtrees exceed 250,000 comparisons fails the name
  constraint check instead of being checked quadratically.
- A wildcard SAN dNSName such as `*.example.com` violates an excluded
  dNSName subtree whose names it matches, such as `bar.example.com`
  (CVE-2025-61727). It was compared as a literal name and passed.
- A critical nameConstraints extension with an otherName, x400Address,
  ediPartyName or registeredID subtree is no longer rejected as
  unprocessed. As RFC 5280 4.2.1.10 requires, the path rejects only a
  subsequent certificate whose subjectAltName presents a name of that form.
- A dNSName name constraint must be empty or a domain name in the preferred
  name syntax (RFC 5280 4.2.1.10). An OpenSSL-style leading-period form such
  as `.example.com`, a trailing dot, a wildcard or an underscore makes the
  nameConstraints extension malformed: `name-constraints-well-formed` fails
  and the path decision rejects certificates below it. Previously a leading
  period was read as "subdomains only". The NC test fixtures now permit
  `example.test`.
- The RFC 5280 policy checks that SAN dNSNames are in the preferred name
  syntax (`san-dnsname-preferred-syntax`, RFC 5280 4.2.1.6). A wildcard is
  accepted only as the complete leftmost label.
- A trust anchor that is not self-signed no longer fails `signature-valid`
  because its own issuer is not supplied. Certificates project
  `certificate.trustAnchor` when explicit trust anchors are given, and the
  RFC 5280 `signature-valid` and `aki-matches-ski` and TR-03116
  `tls-cert-02-signature-valid` rules skip trust anchors, which RFC 5280
  6.1.1 takes as given. For a self-signed trust anchor these rules now skip
  instead of passing; without `--trust-anchor` nothing changes.
- The RFC 5280 policy no longer fails `leaf-not-ca` and
  `basic-constraints-critical-for-ca` for an end entity without a
  basicConstraints extension, where cA is false by default (RFC 5280
  4.2.1.9). This affected 167 PKITS end entities and 44 x509-limbo
  testcases.
- DSA public keys project `keySize` and `subgroupSize`. The projection
  expected Go's standard DSA key type, so parsed certificates exposed only an
  opaque value and key-size rules saw the size as absent. Sizes of keys whose
  parameters are inherited appear once the issuer's parameters are resolved.
- Path construction no longer enumerates every candidate path. It finds the
  same best anchored path in polynomial time, verifying each issuer signature
  once (a 3x4 cross-certified mesh: 1.9 s to 14 ms). The unanchored fallback
  stops at a work limit and the CLI warns when it does. CRL signer paths are
  constructed and validated once per signer instead of once per use.
- Certificate parsing now supports inherited DSA parameters and uncommon
  CRL distribution-point encodings while preserving strict DER validation,
  closing the final four expressible NIST PKITS gaps (244/244). The same
  parser now also reads certificates from CA Issuers responses (DER, PEM and
  PKCS#7) and embedded OCSP responder certificates. Inherited
  DSA parameters are resolved once while inputs are loaded, and only from an
  issuer whose key verifies the certificate's signature; a same-name issuer
  no longer supplies them.

### Changed
- A `when` condition whose target is absent is not met, so the rule is
  skipped instead of failing with a condition error.
- `neq` and `notIn` decide an absent target: an absent value is not equal to
  the operand and not in the set, so the rule passes instead of failing with
  "target not found".
- Consolidated documentation into CLI workflows, policy format, operator and
  node references, and policy testing. Coverage pages now separate implemented
  checks, executable evidence, and limits; the README is a short entry point.
- PCL is presented as a policy-driven PKI conformance engine to reflect its
  certificate, chain, CRL, OCSP, policy-testing, and standards-evidence scope.
- Rule results explain their verdict only through `findings`. The `details`
  string is gone: its text is now the message of a finding whose code names
  the operator, and skipped rules carry a `rule.*` finding stating why.
  Operators describe their own evaluations. Text `--details` is unchanged
  except that path decisions list failed findings or count passed ones.

### Migration notes
- JSON/YAML consumers that read a rule's `details` read
  `findings[].message` instead; codes are listed in the node model's result
  format section.
- Policies without metadata remain valid. Packs using the new `metadata`
  field require a binary/schema from this version or later; older strict
  parsers reject that field.
- Critical-extension acceptance requires strict processing registered for the
  exact certificate, CRL, or entry location. A known OID alone does not suffice.
- Use optional/default field presence nodes (`cAPresent`, `minimumPresent`,
  `requireExplicitPolicyPresent`, etc.) and check extension `malformed` facts;
  numeric zero does not imply absence.
- `pathLenValid` counts non-self-issued intermediates in the supplied chain.
  Use explicit `--trust-anchor` inputs and the conditional
  `certification-path-valid` rule for an aggregate path decision.
- Purpose-aware policies use `--purpose` and `applicationPurposeValid`.
  Wildcard purposes are rejected; private EKUs fail closed when end-entity
  Key Usage is present. Fixed-purpose `ekuContains` rules remain available.

### Development
- CLI golden tests over the vendored PKITS data pin the text, JSON and YAML
  output, `inspect`, `policies` and `test`, with the built-in policies and
  the embedded Public Suffix List; `make golden` accepts an intended change.
- A Makefile as the development entry point (`make check`, `cover`, `limbo`,
  `fuzz`, `lint`, `schema`, ...); CI runs the same targets. It replaces the
  limbo, fuzz and Let's Encrypt fixture scripts, pins golangci-lint and
  govulncheck, and coverage now includes the integration tests.
- `make fixtures` regenerates every certificate, CRL and OCSP test fixture
  with the Go program `tests/fixturegen`, replacing the OpenSSL scripts
  `mkcerts.sh` and `gen-nc-certs.sh`. The CRL and OCSP fixtures had no
  generator. `revoked-leaf.crl` now verifies against its issuer; the
  invalid-signature case uses the new `revoked-leaf-wrong-signature.crl`.
  The DER vectors that tests built in code are generated into
  `tests/vectors`.
- The integration scenarios in `tests/cases`, with their own format and
  per-role rule counts, are policy suites in `tests/policy-suites`, run by
  `pcl test`; expectations name the failing rules instead of counting them.
- x509-limbo conformance suite in the integration tests, including the
  BetterTLS name-constraint and path-building cases, run against the path
  engine and the shipped RFC 5280 profile with each testcase's expected peer
  names. `make limbo-fetch` downloads the pinned testcases;
  9753 of 9802 reach the limbo result, and the differences are listed by
  cause in `tests/limbo/known-gaps.yaml`.

## [5.2.0] - 2026-10-15

### Added
- Text results support `--details` to show wrapped explanations below failed
  and skipped verdicts and actual-versus-expected facts for passing checks.
  JSON and YAML rule results expose the same information as `details`.
- `--fail-on error|warning|info|none` makes `pcl` exit with status 1 after
  writing the results when a rule of that severity or higher failed. The
  default, `none`, keeps the exit status independent of the results.
- NIST PKITS 1.0.1 conformance suite in the integration tests (224 tests,
  247 runs); 240 of the 244 runs PCL can express reach the PKITS result.
- `nameConstraintsValid` enforces directoryName constraints on the subject
  and directoryName alternative names; such constraints are no longer
  reported as unprocessed critical extensions.
- `certificatePolicyValid` without operands applies the RFC 5280 default
  policy inputs: the path must satisfy its own requireExplicitPolicy,
  inhibitPolicyMapping and inhibitAnyPolicy constraints.

### Changed
- CRL, CA Issuers, OCSP and Public Suffix List downloads identify PCL with
  the user agent `pcl/<version>` instead of Go's default.
- Building PCL requires Go 1.26. golang.org/x/crypto, x/net and x/text are
  updated to versions that fix their published security advisories.

### Fixed
- A configured rule failure message is preserved when its target is absent;
  the internal `target not found` error no longer replaces the actionable
  policy explanation.
- The chain is built from the certificates passed with `--cert`. A
  certificate whose issuer was missing used to be skipped silently while a
  longer chain from the `--issuer` inputs was linted instead; it is now
  linted, and certificates left out of the chain are reported.
- Chain building prefers the issuer whose key verifies the signature, so key
  rollover and separate CRL-signing certificates with the same name no longer
  replace each other. A certificate is a root only when it is self-signed;
  self-issued rollover certificates are intermediates.
- Distinguished names are compared by the RFC 5280 Section 7.1 rules (case
  and insignificant whitespace, PrintableString and UTF8String) for name
  chaining, signature checks, CRL scope and issuer matching.
- Supplied certificates outside the chain, such as separate CRL-signing or
  indirect CRL issuer certificates, can sign CRLs. Such signers must be valid
  and not revoked under the same CRLs (RFC 5280 6.3.3).
- The `unused` ReasonFlags bit no longer makes a reason-partitioned CRL
  inapplicable.
- Load errors for certificates, CRLs and OCSP responses include the parse
  error.
- A delegated OCSP responder issued by an intermediate above the first one
  no longer shifts the chain positions of the certificates it shares with
  the certificate chain, which made `signatureValid`, `issuedBy` and
  `akiMatchesSki` check those certificates against the wrong issuer.
- PEM files with several certificates, CRLs or OCSP responses, such as an
  issuer bundle passed with `--issuer`, supply every item instead of only the
  first.
- A certificate supplied in two files, for example in a bundle and on its
  own, is no longer reported as left out of the evaluated chain.
- The issuer of a delegated OCSP responder can be any supplied certificate,
  as for CRL signers, not only one in the certificate chain.
- Files in a `--cert`, `--issuer`, `--crl` or `--ocsp` directory that cannot
  be read or parsed are reported as warnings instead of being skipped
  silently.
- Runs without `--auto-validate`, `pcl inspect` and `pcl test` no longer
  download certificates from CA Issuers URLs to find the signer of a CRL or
  the issuer of a delegated OCSP responder. `--no-auto-chain` disables those
  downloads as well.
- `pcl test` and `pcl inspect` load the Public Suffix List and accept
  `--psl-file`, `--use-psl` and `--data-dir`, so public suffix and TLD
  operators give the same verdicts as in a lint run.
- Without a Public Suffix List, the public suffix and TLD operators fail the
  rule with a message saying the list is not loaded, instead of judging every
  domain as unlisted; `tldNotRegistered` used to pass for every domain. Runs
  no longer warn about a missing list, and a `--psl-file` that cannot be
  loaded is an error instead of a warning.
- Downloaded OCSP responses and CA Issuers certificates are limited to 1 MiB,
  like CRLs are limited, instead of being read to any size. `pcl update-data`
  has a timeout, a size limit, and replaces the Public Suffix List only after
  a complete download.
- An unknown `--output` format is an error instead of falling back to text.
- An unknown `--ocsp-hash`, a `--ocsp-nonce-value` that is not hex, and a
  nonce outside 1-128 bytes are rejected before the run starts. `--ocsp-hash`
  used to fall back to SHA-256 for any value but `sha1`, and a negative nonce
  length to the default.
- Text results are colored only when written to a terminal, and never when
  `NO_COLOR` is set, so piped and redirected output no longer contains ANSI
  escape codes.
- ECDSA public keys project `subjectPublicKeyInfo.publicKey.keySize` and
  `curve` again. zcrypto wraps parsed ECDSA keys in its own type, which the
  projection did not recognize, so rules on those paths found no value.

## [5.1.0] - 2026-10-14

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
  Key Usage extension. At this release boundary, same-trust-anchor signer-path
  validation was not yet available.
- Revocation processing covers its documented exact-name and supplied-signer
  boundaries; certification-path and Section 7 name validation were still
  pending in this release.

## [3.0.0] - 2026-07-19

### Breaking Changes
- `noUnknownCriticalExtensions` now uses an explicit, conservative
  certificate-only processed-extension registry. A catalog-known but
  unprocessed OID or value, CRL/entry-only, or malformed critical
  extension now fails closed, and repeated instances of an extension OID fail
  before criticality lookup.
- Strict extension nodes distinguish omitted DEFAULT/OPTIONAL fields from
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
- Domain-owned dependency operators for Basic Constraints/Key Usage, Name
  Constraints distances, CRL Distribution Points, Policy Mappings, Policy
  Constraints, and `inhibitAnyPolicy`
- A processed-extension registry separate from the RFC extension identity
  catalog, with a conservative certificate-only processed set and stable-set
  tests; critical CRL and CRL-entry extensions fail closed until their strict
  handlers are available
- Deterministic purpose/path vectors, malformed-DER vectors, and an
  executable invariant that every active RFC 5280 rule is classified in the
  coverage matrix
- Lossless X.501 Name projection for certificate subjects and issuers, CRL issuers, and raw `directoryName` values in SAN, IAN, AIA, and CRL distribution-point GeneralNames, including RDN grouping, duplicate attributes, raw DER, and ASN.1 value tags
- Canonical collection iteration that keeps indexed values ordered while excluding metadata and compatibility aliases
- Lossless TBSCertificate metadata for encoded serial numbers, validity time formats, and issuer/subject UniqueIdentifiers
- One RFC 5280 extension catalog for OIDs, stable aliases, and certificate, CRL, and CRL-entry locations
- Separate RFC 6960 and local-profile policy bundles
- Integration wiring for the opt-in RFC 6960 bundle, which requires valid, matching, good OCSP evidence for leaf certificates

### Changed
- RFC 5280 certificate-profile semantics are bounded explicitly; CRL
  scope/delta/indirect processing and complete Sections 6/7 validation were
  not yet included in this release
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

[Unreleased]: https://github.com/cavoq/PCL/compare/v6.0.0...HEAD
[6.0.0]: https://github.com/cavoq/PCL/compare/v5.2.0...v6.0.0
[5.2.0]: https://github.com/cavoq/PCL/compare/v5.1.0...v5.2.0
[5.1.0]: https://github.com/cavoq/PCL/compare/v5.0.0...v5.1.0
[5.0.0]: https://github.com/cavoq/PCL/compare/v4.0.0...v5.0.0
[4.0.0]: https://github.com/cavoq/PCL/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/cavoq/PCL/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/cavoq/PCL/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/cavoq/PCL/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/cavoq/PCL/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cavoq/PCL/compare/v1.0.0...v1.1.0
