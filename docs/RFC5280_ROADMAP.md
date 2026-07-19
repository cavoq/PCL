# RFC 5280 Conformance Roadmap

PCL is currently an RFC 5280 certificate and CRL **profile linter**. It does
not yet claim to implement the certification-path validation state machine in
Section 6, the name comparison rules in Section 7, or complete revocation
processing.

This roadmap defines implementation order and completion criteria. The
clause-by-clause source of truth for current behavior is the
[RFC 5280 coverage matrix](../policies/RFC5280-COVERAGE.md). The
[architecture](../architecture.md) defines the system boundaries, and
[`RFC5280.yaml`](../policies/RFC5280.yaml) contains the active policy.

Status labels are intentionally date-free:

- **Done**: implemented with executable evidence in the current tree.
- **Next**: the next bounded body of work.
- **Planned**: sequenced after the current priority.
- **Continuous**: an invariant that applies to every priority.

## Responsibility boundaries

| Area | Responsibility |
|------|----------------|
| Format adapters (`internal/{cert,crl,ocsp}/zcrypto`) | Decode and project format-specific data, including raw DER and extension presence. |
| Representation helpers (`internal/zcrypto`, `internal/asn1`, `internal/oid`) | Reusable ASN.1, algorithm, extension, and OID mechanics; no policy decisions. |
| Domain packages (`internal/cert`, `internal/crl`, `internal/ocsp`, future `internal/path`) | Certificate, revocation, response, and path semantics with explicit status. |
| Acquisition and orchestration (`internal/aia`, `internal/evaluator`) | Bind the current object and gather, share, and cache external evidence. |
| Operators (`internal/operator`) | Thin policy adapters over representation or domain behavior; no duplicate domain algorithms. |
| Generic engine (`internal/node`, `internal/rule`, `internal/policy`) | Resolution, applicability, and evaluation without certificate-field exceptions. |
| Policies and documentation | Declarative claims, severity, references, coverage status, and user-facing scope. |

Each concept has one canonical representation helper and one owning domain
implementation. Rule-specific builder workarounds and duplicated operator
implementations are not accepted as conformance progress.

## P0 — Fail-closed correctness foundation

**Status: Done**

- Project complete `AlgorithmIdentifier` DER through one shared certificate,
  CRL, and OCSP representation, and compare inner and outer identifiers where
  RFC 5280 requires equality.
- Distinguish extension absence from a decoded zero value for Key Usage, SAN,
  and IAN; project every supported `GeneralName` form and reject malformed
  values.
- Treat certificate validity boundaries as inclusive and fail applicable
  rules whose required target is absent.
- Use correct extension OIDs and aliases, and evaluate critical-extension
  support against the object currently being linted.
- Bind one current CRL per evaluation; require issuer identity and a valid
  signature; share issuer evidence; and preserve Good, Revoked, and Unknown
  as distinct outcomes.
- Allow only a current, complete, direct, unscoped CRL without unsupported
  critical extensions to prove a certificate Good.
- Evaluate the CRL profile once per CRL instead of duplicating CRL findings on
  every certificate.
- Keep rule severity, references, required fields, and the coverage matrix
  aligned with executable behavior.

Exit evidence lives with the owning unit tests and in the normal integration
and linter suites. Milestone-only test files such as `*_p0_test.go` are not
part of the permanent test structure.

## P1 — Lossless representation and policy integrity

**Status: Done**

Completed work units:

- **P1.1 — Lossless distinguished names (Done):** certificate subjects and
  issuers, CRL issuers, and raw `directoryName` values decoded from SAN, IAN,
  AIA, and CRL distribution-point GeneralNames share one `Name`/`RDNSequence`
  projection. It preserves RDN grouping and order, duplicate and previously
  missing attributes, raw DER, and actual ASN.1 value tags. DN rules iterate
  every occurrence through the canonical collection contract documented in
  the policy-writing guide. P2 subsequently added strict Name Constraints and
  relative CRL distribution-point name structures on that representation.
- **P1.2 — Raw TBSCertificate metadata (Done):** one certificate adapter
  preserves the encoded serial-number octets, both validity encodings, and
  exact issuer/subject UniqueIdentifier presence and bit metadata. Time and
  UniqueIdentifier policy checks use those facts through generic operators;
  malformed metadata fails a dedicated policy rule.
- **P1.3 — GeneralName and collection boundaries (Done):** SAN and IAN
  collections are built from raw GeneralName entries with scalar values, tags,
  and owned DER. Multi-valued policy rules compose scalar `componentRegex` and
  `validIA5String` checks through `every`, and redundant collection/time/
  constraint wrappers were removed. Older collection-aware operators retain
  their documented behavior until a separately scoped migration.
- **P1.4 — Extension identity catalog (Done):** RFC 5280 extension OIDs,
  stable aliases, and certificate/CRL/entry locations have one catalog in
  `internal/oid`. Format adapters still own decoded extension values. P2 added
  a separate, location-specific registry for extensions PCL can process.
- **P1.5 — Policy integrity (Done):** RFC 6960 and local-profile rules ship as
  separate policies. All shipped policies are schema-checked, and a small
  scope-purity invariant prevents RFC 6960 or `LOCAL-*` rules from returning
  to `RFC5280.yaml`.

Exit evidence is boundary-focused: changed parsers and projections cover
positive, absent, malformed, and representation edge cases; existing
integration and linter suites prove the affected policy composition. P1 does
not maintain an exhaustive one-fixture-per-rule wiring manifest.

## P2 — Certificate and extension profile semantics

**Status: Done**

Completed work units:

- Extended Key Usage is strictly decoded and evaluated against the explicit
  `--purpose` input (a supported friendly name or dotted OID), together with
  compatible end-entity Key Usage. Dotted identifiers are matched exactly
  from extension DER, including usages recognized by the certificate library
  but outside PCL's friendly-name catalog. With no purpose input, the
  conditional purpose rule is skipped.
- Strict, presence-preserving projections cover Key Usage, Basic Constraints,
  Extended Key Usage, CRL Distribution Points, Name Constraints, Policy
  Mappings, Policy Constraints, and `inhibitAnyPolicy`. Malformed DER is
  surfaced on the concrete extension node and cannot satisfy critical-
  extension processing.
- Domain predicates own the bounded certificate-profile dependencies: CA-only
  extensions, Key Usage/Basic Constraints relationships, GeneralSubtree
  distances, CRL distribution-point structural dependencies, policy-mapping
  restrictions, and `pathLenConstraint` counting over an already ordered
  chain.
- `noUnknownCriticalExtensions` now uses a location-specific processed-
  extension registry, distinct from the RFC identity catalog. Known but
  unprocessed, wrong-location, malformed, and P3-only critical extensions
  fail closed; OID/friendly-name aliases are deduplicated, and repeated OID
  instances fail before criticality lookup.
- Deterministic purpose/path vectors, strict-parser malformed-DER vectors,
  owner tests, and a coverage invariant provide executable evidence for every
  active `RFC5280.yaml` rule.

This is deliberately bounded profile semantics. Name Constraints cover the
implemented DNS, email, URI, and IP matching forms, including the required
subject-DN emailAddress fallback when SAN is absent, but do not claim complete
constraint-base value-form validation or the Section 6/7 state machine. Path
length relies on the supplied leaf-to-root order and exact-name self-issued
detection. Policy counters and mappings are decoded and checked for profile
dependencies but do not run the Section 6 policy state machine.
CRL distribution-point decoding does not apply CRL scope, reasons, indirect
CRLs, or deltas. Those remain P3/P4 work.

Exit evidence is indexed in the coverage matrix, which classifies every active
rule as Covered, Partial, or Not active and links the parser, domain,
integration, deterministic-vector, and coverage-invariant tests.

## P3 — Revocation processing

**Status: Next**

- Implement CRL Distribution Point and Issuing Distribution Point scope,
  reason masks, indirect CRLs and `certificateIssuer`, delta/base CRL
  combination, Freshest CRL, and processed CRL-entry extension semantics.
- Implement the RFC 5280 Section 6.3 revocation-processing semantics while
  retaining Unknown unless accepted evidence proves Good or Revoked.
- Keep retrieval and caching in acquisition/orchestration packages and keep
  deterministic status decisions in `internal/crl`.
- Integrate CRL-signer path validation when the P4 path engine is available.

Exit criteria: standards-based vectors cover complete, scoped, indirect,
delta, stale, unrelated, unsupported, and conflicting revocation evidence
without operators duplicating CRL semantics.

## P4 — Certification-path validation

**Status: Planned**

- Introduce a dedicated path domain with explicit trust anchors, validation
  time, initial policy set and inhibition flags, maximum path length, and
  application purpose.
- Implement the Section 6 state transitions and Section 7 name comparison
  rules as domain logic rather than a collection of loosely coupled YAML
  operators.
- Separate path construction and issuer acquisition from deterministic path
  validation.
- Return structured findings that policies and output formatters can report.
- Connect validated certificate and CRL-signer paths to the P3 revocation
  engine.

Exit criteria: published standards vectors exercise deterministic success and
failure decisions for path construction inputs, policy processing, name
constraints, critical extensions, and revocation integration.

## PX — Conformance assurance and maintenance

**Status: Continuous**

- Maintain standards vectors, deterministic offline fixtures, DER/name/
  extension fuzzing, and performance budgets.
- Generate or validate coverage reports from executable policy evidence.
- Preserve the node schema by default. Breaking removals require a documented
  migration and a major release; use a deprecation cycle when retaining the
  old representation does not perpetuate ambiguous or lossy data.
- Differentially test parser and cryptographic dependency upgrades.
- Change the product claim from profile linter only after Sections 6 and 7 and
  the required revocation criteria are independently executable and tested.

## Definition of done for every priority

- One owning package makes each semantic decision; shared helpers contain
  representation mechanics only.
- Positive, negative, absent, malformed, and boundary behavior is tested in
  the existing owner, integration, or linter suites as applicable.
- `RFC5280.yaml` and the coverage matrix change together when a claim changes.
- The full test suite, `go vet`, formatting, and diff checks pass.
- Tests are organized by stable behavior, not by temporary roadmap priority.
