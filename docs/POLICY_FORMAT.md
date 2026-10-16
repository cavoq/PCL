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
| `when` | No | Precondition with `target`, `operator`, and optional `operands` |

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
