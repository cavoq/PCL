# 📝 Policy Format

[Documentation](POLICY_WRITING_GUIDE.md) · [Operators](OPERATORS.md) · [Node model](NODE_MODEL.md) · [Tests](TESTING.md)

Policies define checks over evidence. Runtime inputs select trust, validation
time, application purpose, and available evidence; see [running PCL](QUICKSTART.md).

## Minimal policy

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cavoq/PCL/master/schemas/policy.schema.json
id: example-profile
version: "1.0"
appliesTo: [cert]
metadata:
  title: Example certificate profile
  description: Require v3 encoding when extensions are present.
  inputs: [certificate]
rules:
  - id: version-v3-when-extensions
    reference: RFC5280 4.1.2.1
    target: certificate.version
    operator: eq
    operands: [3]
    severity: error
    when:
      target: certificate.extensions
      operator: present
```

The editor schema offers field/operator completion. `pcl schema` prints the
schema matching the installed binary; the published `master` schema may lag
unreleased features. Execution validates semantic operand constraints as well.

## Policy fields

| Field | Required | Meaning |
|---|---|---|
| `id` | Yes | Nonempty policy identifier |
| `version` | No | Policy pack version; quote strings for stable YAML representation |
| `metadata` | No | Descriptive information; see below |
| `includes` | No | Policy file paths, relative to this file |
| `appliesTo` | No | Input types: `cert`, `crl`, `ocsp`; `tst`, `sct`, `attrCert` are reserved |
| `certType` | No | Whole-policy filter: `leaf`, `intermediate`, `root`, `ca`, friendly EKUs, or EKU OIDs |
| `crlType` | No | CRL filter: `completeCRL`, `indirectCRL`, `deltaCRLIndicator`, or `2.5.29.27` |
| `tstType`, `sctType` | No | Reserved subtype filters; no CLI loaders yet |
| `rules` | No | Rule sequence; include-only packs are allowed |
| `profiles` | No | Kinds of input the policy distinguishes; see [Profiles](#profiles) |
| `groups` | No | Rule groups, evaluated after `rules`; see [Groups](#groups) |

Includes merge rules before the parent's own rules. Cycles and duplicate rule
IDs fail loading. Shared included files are loaded once. Metadata and
execution filters belong to the including policy and are not inherited.

An explicit `appliesTo` selects execution inputs. Otherwise PCL infers them
from all primary target namespaces (`certificate`, `crl`, `ocsp`, etc.).
`when` targets are dependencies and do not change that selection. Unqualified
primary targets are input-agnostic. `metadata.inputs` never selects execution.

## Descriptive metadata

```yaml
metadata:
  title: X.509 certificate and path checks
  standard: RFC 5280
  edition: "2008"
  source: https://www.rfc-editor.org/rfc/rfc5280
  description: Profile checks and conditional explicit-trust path validation.
  inputs: [certificate, issuers, trustAnchors, crl, ocsp]
```

| Field | Meaning |
|---|---|
| `title` | Human-readable pack name |
| `standard` | Standard or profile identifier(s) |
| `edition` | Source edition; distinct from the pack's `version` |
| `source` | Reference text or URL; never fetched by the engine |
| `description` | Short scope statement, not a completeness claim |
| `inputs` | Relevant evidence/runtime input names, not mandatory requirements |

All fields are optional. Input names are `certificate`, `issuers`,
`trustAnchors`, `crl`, `ocsp`, `purpose`, `peerNames`, `validationTime`, and
`psl`; duplicates
and unknown names are rejected. Unknown metadata keys are also rejected.

Metadata is available on the parsed policy for documentation and tooling. It
does not change verdicts, appear as rule operands, configure acquisition, or
set trust. Reusable executable constants and operand substitution are not
part of this format.

## Rule fields

| Field | Required | Meaning |
|---|---|---|
| `id` | Yes | Nonempty identifier, unique across merged rules |
| `target` | Yes | Dotted path in the node tree |
| `operator` | Yes | Registered operator name |
| `operands` | Depends on operator | Sequence, scalar, or supported structured mapping |
| `requirement` | One of these two | RFC 2119 level of the source clause: `must` (MUST, SHALL), `should` (SHOULD, RECOMMENDED), or `may` (MAY, OPTIONAL) |
| `severity` | One of these two | `error`, `warning`, or `info`; defaults from `requirement` to `error`, `warning`, or `info` |
| `reference` | No | Requirement reference |
| `message` | No | Human-readable failure message |
| `certType` | No | Rule role filter; nonmatching roles skip |
| `profile` | No | Evaluate only for inputs under one of these [profiles](#profiles) |
| `when` | No | Precondition: `target`, `operator` and optional `operands`, or a [compound condition](#compound-conditions) |
| `effective` | No | Window `{basis, from, until}` in which the rule is in effect; see [Effective dates](#effective-dates) |

State `requirement` for rules that implement a normative source, so a SHOULD
does not read as a MUST: with only `requirement`, a failed SHOULD is a
warning and leaves the policy verdict alone. An explicit `severity` overrides
the default, for a profile that deliberately tightens a recommendation. Each
rule result reports its `requirement`, and text output adds a REQUIREMENT
column when any rule states one.

Rule roles are `leaf`, `intermediate`, `root`, `ocspSigning`, `crl`, `ocsp`,
and reserved `tst`, `sct`, `attrCert`. Omit `certType` to allow all roles.
`appliesTo` is a policy field; placing it on a rule is a load error.

Unknown fields/operators, invalid operands, and multiple YAML documents are
load errors. Validation includes `when` and nested `every` invocations.

## Groups

A group collects the rules of one source section and states what they
share once:

```yaml
groups:
  - id: subscriber-certificate-policies
    title: Subscriber Certificate Policies (7.1.2.7.9)
    reference: CABF-BR 7.1.2.7.9
    certType: [leaf]
    effective: {basis: issuance, from: 2023-09-15}
    rules:
      - id: br-subscriber-reserved-policy-exactly-one
        target: certificate.extensions.certificatePolicies
        operator: oneOf
        operands: [...]
        requirement: must
```

| Field | Meaning |
|---|---|
| `id` | Required, unique among the policy's groups |
| `title` | Section title, for readers and tools |
| `reference`, `requirement`, `certType`, `profile`, `effective` | Defaults: a rule that states its own value keeps it |
| `when` | Applies to every rule: it must hold as well as the rule's own `when` |
| `rules` | Required, at least one rule |

Groups are expanded when the policy is loaded: their rules follow the
policy's own `rules`, in group order, and behave exactly like ungrouped rules
with the inherited fields written out. Rule IDs stay unique across groups. A
rule inherits the group's `requirement` even when it states a `severity`.

## Profiles

Standards set different requirements for different kinds of one input: the
CA/B Forum Baseline Requirements have a profile for subscriber certificates,
TLS subordinate CAs, technically constrained CAs, cross-certified CAs and
more. A policy names them once and rules state which they apply to:

```yaml
profiles:
  - id: technically-constrained-tls-subordinate
    title: Technically Constrained TLS Subordinate CA (7.1.2.5)
    role: intermediate
    when:
      allOf:
        - {target: certificate.extKeyUsage.serverAuth, operator: eq, operands: [true]}
        - {target: certificate.nameConstraints, operator: present}
  - id: tls-subordinate
    role: intermediate
    when: {target: certificate.extKeyUsage.serverAuth, operator: eq, operands: [true]}
  - id: cross-certified-subordinate
    role: intermediate
    assumeOnly: true
rules:
  - id: tls-ca-policies
    profile: [technically-constrained-tls-subordinate, tls-subordinate]
    ...
```

| Field | Meaning |
|---|---|
| `id` | Required, unique among the policy's profiles |
| `title`, `reference` | The source's name and section for the profile |
| `role` | Required input role: `leaf`, `intermediate`, `root`, `ocspSigning`, `crl` or `ocsp` |
| `when` | Condition the input must meet; omit it for the fallback profile of a role |
| `assumeOnly` | Never inferred: selected only when the user assumes it, for facts the input cannot show |

Each input is evaluated under at most one profile per policy. A profile of
its role that the user assumed comes first; otherwise the first profile of
its role, in policy order, whose `when` holds. List the most specific
profile of a role first. A rule with `profile` runs only for inputs under one
of its profiles and is skipped with `rule.profile` otherwise; rules without
`profile` run for every input as before. Results report the profile and
whether it was `inferred` or `assumed` (`profile`, `profile_basis`; text
shows `Cert: intermediate (tls-subordinate, inferred)`). Rules may name
profiles of included policies.

## Compound conditions

A condition is one target check, or exactly one of `allOf`, `anyOf` and `not`,
which nest:

```yaml
when:
  allOf:
    - {target: certificate.extensions.certificatePolicies, operator: present}
    - not: {target: certificate.extKeyUsage.serverAuth, operator: eq, operands: [true]}
```

`allOf` and `anyOf` take at least two conditions. A check on an absent target
does not hold, so `not` of it does: use `absent` when absence is the point.
A skipped rule names the first unmet condition of an `allOf`, every condition
of an `anyOf`, or the condition a `not` found to hold.

## Effective dates

Requirements change over time: a rule may apply only to certificates issued
from a date, or only from a date on. `effective` limits a rule to a
half-open window `[from, until)`; outside it the rule is skipped with
`rule.not-effective`. Successive versions of one requirement are separate
rules with adjacent windows:

```yaml
- id: leaf-validity-max-398-days
  target: certificate.validity
  operator: dateDiff
  operands: [{start: notBefore, end: notAfter, maxDays: 398}]
  severity: error
  effective: {basis: issuance, until: 2026-03-15}
- id: leaf-validity-max-200-days
  target: certificate.validity
  operator: dateDiff
  operands: [{start: notBefore, end: notAfter, maxDays: 200}]
  severity: error
  effective: {basis: issuance, from: 2026-03-15, until: 2027-03-15}
```

| Field | Meaning |
|---|---|
| `basis` | Required. `issuance` compares the input's issuance time: a certificate's `notBefore`, a CRL's `thisUpdate`, or an OCSP response's `producedAt`. `validation` compares the evaluation time (`--validation-time` or now) |
| `from` | First instant in effect, inclusive |
| `until` | First instant no longer in effect, exclusive |

At least one bound is required; dates are RFC 3339 or `YYYY-MM-DD` (UTC
midnight). Certificates do not record when they were issued, so `notBefore`
stands in for the issuance date; a backdated `notBefore` places a
certificate under an earlier requirement.

## Conditions and verdicts

A false `when` precondition skips the rule; so does a precondition whose
target is absent. Use conditions for applicability, not to hide evidence that
a requirement says must exist. Ordinary rule operators fail on missing
targets; `present`, `absent`, `isEmpty`, `isNull`, `neq` and `notIn` decide
absence explicitly (an absent value equals no operand and is in no set).

| Rule result | Policy effect |
|---|---|
| `pass` | Requirement satisfied |
| `fail` with `error` severity | Policy verdict becomes `fail` |
| `fail` with `warning` or `info` | Reported; policy verdict remains unchanged |
| `skip` | Not evaluated for this input/condition |
| `inconclusive` with `error` severity | Policy verdict becomes `inconclusive` unless an error rule failed |

A rule is `inconclusive` when it applies but its operator found no
applicable evidence to decide it, such as no CRL or OCSP response for the
certificate ([revocation operators](OPERATORS.md#ocsp-operators)). It is not a
failure: the input is not shown non-compliant, but compliance is not
established either.

A policy whose rules were all skipped decided nothing for the input, such as
a leaf-only pack on a CA certificate; its verdict is `not_applicable` (`N/A`
in text), not `pass`. There is no `warn` policy verdict. CLI exit status is controlled separately by
[`--fail-on`](QUICKSTART.md#output-and-exit-status).

## Authoring checklist

1. Inspect actual inputs with `pcl inspect --paths` and use canonical paths.
2. Give each rule one requirement, a stable ID, and a source reference.
3. Check optional-field presence and malformed encodings explicitly; numeric
   zero does not mean absent. See [strict extension schemas](NODE_MODEL.md#strict-profile-extension-schemas).
4. Use `every` to check every DN or GeneralName occurrence.
5. Add passing, failing, missing-evidence, and not-applicable [policy tests](TESTING.md).
6. Document the implemented scope and required evidence in the pack's coverage matrix.
