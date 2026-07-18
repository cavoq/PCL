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

**Status: Next**

- Preserve the complete `Name`/`RDNSequence`: RDN grouping and order,
  duplicate attributes, raw DER, and the actual ASN.1 string tag.
- Project currently missing name attributes, including `givenName`,
  `surname`, `emailAddress`, and `domainComponent`.
- Base encoding, time, and unique-identifier checks on parsed metadata rather
  than inferred values.
- Move multi-valued requirements to collection-aware `every`/`any`
  composition.
- Centralize extension identity and aliases while leaving decoded values in
  the owning format adapter.
- Remove compatibility and one-off operators when generic composition or an
  existing domain method expresses the same rule.
- Split RFC 6960 and `LOCAL-*` checks from the RFC 5280 compatibility bundle.
- Add automated policy/coverage consistency checks and wiring tests for every
  active rule.

Exit criteria: every active claim has an observable input for every relevant
value; positive, negative, absent, and malformed cases exist; and no active
rule depends on a dead projection or compatibility-only path.

## P2 — Certificate and extension profile semantics

**Status: Planned**

- Evaluate Extended Key Usage against an explicit application-purpose input.
- Complete the structures and dependencies for CRL Distribution Points,
  policy mappings, policy constraints, `inhibitAnyPolicy`, Name Constraints,
  Basic Constraints, Key Usage, and `pathLenConstraint`.
- Replace "known OID" critical-extension handling with an explicit registry
  of extensions the implementation can actually process.
- Add malformed-DER fixtures for every claim that relies on parser behavior.
- Keep semantic decisions in domain packages; YAML selects and reports their
  outcomes.

Exit criteria: the coverage matrix classifies every active profile claim as
Covered, Partial, or Not active and links that classification to executable
evidence.

## P3 — Revocation processing

**Status: Planned**

- Implement CRL Distribution Point and Issuing Distribution Point scope,
  reason masks, indirect CRLs and `certificateIssuer`, delta/base CRL
  combination, Freshest CRL, and entry critical-extension handling.
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
- Preserve the node schema through documented compatibility and deprecation
  rules.
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
