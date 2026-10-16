# 🏛️ RFC 4055 Coverage

[Documentation](../docs/POLICY_WRITING_GUIDE.md) · [Policy](RFC4055.yaml)

## Scope

RSA AlgorithmIdentifier checks for certificates and CRLs. The pack validates
parameter profiles; it does not select an application's acceptable security
algorithms. Source and edition are recorded in the policy metadata.

## Requirement matrix

| Requirement | Status | Implementation | Required input | Evidence |
|---|---|---|---|---|
| rsaEncryption SPKI NULL parameters (§1.2) | Covered | `cert-spki-rsa-params-null` | Certificate | [Chain case](../tests/policy-suites/standards.test.yaml) |
| RSA signature NULL parameters (§5) | Covered | `cert-tbs-signature-rsa-params-null`, `cert-signature-algorithm-rsa-params-null`, CRL equivalents | Certificate or CRL | [Chain case](../tests/policy-suites/standards.test.yaml), [parameter parsing](../internal/x509asn1/parser_test.go) |
| PSS hash, MGF1 and MGF hash (§2.2, §3.1) | Covered | `*-pss-hash-algorithm-valid`, `*-pss-mgf-algorithm-valid`, `*-pss-mgf-hash-valid` for outer/TBS certificate and CRL algorithms | PSS AlgorithmIdentifier | [Nested MGF projection](../internal/x509node/algorithm_test.go), [RFC 4055 suite](../tests/policy-suites/rfc4055.test.yaml) |
| PSS salt length and trailer (§3.1) | Covered | `*-pss-salt-length-valid` requires nonnegative salt; `*-pss-trailer-field-valid` requires 1 | PSS AlgorithmIdentifier | [Parser vectors](../internal/x509asn1/parser_test.go), [RFC 4055 suite](../tests/policy-suites/rfc4055.test.yaml) |
| OAEP hash, MGF1, MGF hash and pSource (§4.1), when parameters are present | Implemented; partial end-to-end evidence | `cert-spki-oaep-*` rules | OAEP SPKI parameters | [Parser](../internal/x509asn1/parser.go), [policy](RFC4055.yaml) |
| PSS parameters present in signature algorithm identifiers (§3) | Covered | `*-pss-params-present`; the field rules above apply only when parameters are present | Certificate or CRL | [RFC 4055 suite](../tests/policy-suites/rfc4055.test.yaml) |
| Signers omit default PSS fields (§3.1) | Covered | `*-pss-hash-default-omitted`, `*-pss-mgf-default-omitted`, `*-pss-trailer-field-omitted` | Certificate or CRL | [RFC 4055 suite](../tests/policy-suites/rfc4055.test.yaml) |
| MGF1 hash recommended to be the message hash (§3.1, SHOULD) | Covered | `*-pss-mgf-hash-matches-hash` | Certificate or CRL | [RFC 4055 suite](../tests/policy-suites/rfc4055.test.yaml) |
| keyUsage of RSASSA-PSS and RSAES-OAEP keys (§1.2) | Covered | `cert-pss-key-end-entity-key-usage`, `cert-pss-key-ca-key-usage`, `cert-oaep-key-usage-encipherment-only`, `cert-oaep-key-usage-not-both-encipherments` (SHOULD NOT) | Certificate | [RFC 4055 suite](../tests/policy-suites/rfc4055.test.yaml) |
| Sequence/default parameter representation | Implemented; parser evidence varies by form | Shared strict parser and node projection | AlgorithmIdentifier DER | [Parser vectors](../internal/x509asn1/parser_test.go), [projection tests](../internal/x509node/algorithm_test.go) |

The NULL-parameter rules cover the RSA OIDs listed in the YAML, including
historical signature algorithms. Passing an encoding check does not endorse
using that algorithm. PSS/OAEP hash lists include SHA-1 and the listed SHA-2
variants; combine this pack with a stricter application profile when needed.

## Executable evidence

| Evidence | What it establishes |
|---|---|
| [RFC 4055 chain case](../tests/policy-suites/standards.test.yaml) | Full pack execution on a conventional RSA chain |
| [Algorithm parser tests](../internal/x509asn1/parser_test.go) | NULL/absent distinctions and selected malformed AlgorithmIdentifier/PSS vectors |
| [Algorithm node tests](../internal/x509node/algorithm_test.go) | Absent and malformed projections, nested MGF1 identity |
| [Schema tests](../internal/policy/schema_test.go) | Shipped policy syntax and operand contracts |

`Implemented` rows identify active checks without claiming a complete positive/
negative integration suite for every parameter combination.

## Limits

| Area | Limit |
|---|---|
| Algorithm strength | Key-size, exponent and weak-algorithm restrictions belong to a selected application/local profile |
| Signature trust | Parameter checks alone do not verify a trusted certification path |
| PSS salt length | The RECOMMENDED salt length equal to the hash length (§3.1) is not checked |
| PSS signature against key parameters | When a PSS key carries parameters, the signature parameters must match them (§3.3); not checked |
| OCSP | OCSP signature verification accepts only MGF1 with the message hash, and SHA-256, SHA-384 or SHA-512 |
| OAEP label semantics | No complete pSpecified label-validation claim |
| Nonstandard hash OIDs | Only the pack's enumerated identifiers are accepted |

PSS/OAEP parameters are already projected under `parameters.pss` and
`parameters.oaep`; absent parameters omit the node. Use `absent` for omitted
parameters and `isNull` for explicit NULL. See the [node model](../docs/NODE_MODEL.md)
and [operators](../docs/OPERATORS.md).

## Requirement levels

Every rule states the RFC 2119 level of its clause. All rules implement MUST
clauses except `*-pss-mgf-hash-matches-hash` and
`cert-oaep-key-usage-not-both-encipherments`, which implement a "strongly
RECOMMENDED" and a SHOULD NOT and are warnings.

Audit of 2026-10-16 against the RFC text: the references named sections that
do not exist (3.2–3.4 for PSS fields, 4.2–4.3 for OAEP fields) and now cite
§2.2, §3.1 and §4.1. PSS and OAEP field rules applied whenever the algorithm
was PSS or OAEP and failed on absent parameters, which RFC 4055 permits in a
subject public key; they now apply when parameters are present, and
`*-pss-params-present` requires parameters in signature algorithm
identifiers. The PSS default-omission, MGF1 consistency and key usage rules
were added.
