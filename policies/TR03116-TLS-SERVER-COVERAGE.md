# 🏛️ TR-03116 TLS Server Coverage

[Documentation](../docs/POLICY_WRITING_GUIDE.md) · [Policy](TR03116-TLS-SERVER.yaml)

## Scope

TLS server certificate checklist from TR-03116-TS v1.1 §6.1.1 Table 24, with
the TR-03116-4 (2025) cryptographic profile. Source editions are recorded in
policy metadata. Evaluate the complete leaf-to-root chain.

DSA keys and signatures are accepted for validation times through 2029 and
rejected from 2030 (Table 29, "Verwendung bis 2029"), with `effective`
windows on the validation time. The RSASSA-PKCS1-v1_5 transition (Table 31)
applies only to justified exceptions until 2025 and is not accepted.

## Requirement matrix

| Requirement | Status | Implementation | Required input | Evidence |
|---|---|---|---|---|
| TLS_CERT_01: public keys | Covered | RSA/ECDSA server keys (TR-03116-4 2.2.1.2); RSA/DSA/ECDSA chain keys, DSA through 2029; CA RSA/DSA keys ≥3072 bits (Table 29); server RSA key ≥3000 bits (TR-02102-2 Table 14); Table 30 curves | Complete chain | [TR-03116 suite](../tests/policy-suites/tr03116.test.yaml) |
| TLS_CERT_02: signatures | Covered | ECDSA SHA-256+, DSA SHA-256 through 2029, or PSS SHA-256+; signature verification | Chain and issuers | [TR-03116 suite](../tests/policy-suites/tr03116.test.yaml); combine with [RFC 4055](RFC4055-COVERAGE.md) |
| TLS_CERT_03: wildcards | Partial | Rejects `*` in every CN and SAN dNSName | Certificate Names | Pack rules |
| TLS_CERT_04: revocation information | Partial | Requires CRLDP or OCSP AIA; acquisition can attempt retrieval | Certificate; live service evidence for availability | Pack rules and acquisition tests |
| TLS_CERT_05: revocation status | Implemented with evidence | Requires accepted current CRL or authenticated OCSP Good; Revoked wins; inconclusive without applicable evidence | Chain, CRL/OCSP, time | [CRL assessment](../internal/crl/status_assessment_test.go), [OCSP assessment](../internal/ocsp/evidence_test.go) |
| TLS_CERT_06: leaf Key Usage | Covered | Critical; digitalSignature true, keyCertSign/cRLSign false | Leaf | Pack rules |
| TLS_CERT_07: CA Key Usage | Covered | Critical; keyCertSign and cRLSign true | CA certificates | Pack rules |
| TLS_CERT_08: EKU | Covered | EKU present (TR-03116-4 6.1.2, SHOULD); when present, serverAuth (MUST) | Leaf | [TR-03116 suite](../tests/policy-suites/tr03116.test.yaml) |
| TLS_CERT_09: service names | External evidence | `--peer-name` with `--trust-anchor` checks one name per run; TLS acquisition does not verify names | All intended application names | Acquisition result and external assessment |
| TLS_CERT_10: CA constraints | Partial | Critical CA Basic Constraints, explicit pathLenConstraint, supplied-chain check | Chain and application constraints | Pack rules; smallness remains external |
| TLS_CERT_11: lifetime | Covered | Calendar bounds: 3 years leaf, 5 intermediate (MUST), 6 root (SHOULD) | Chain validity dates | [TR-03116 suite](../tests/policy-suites/tr03116.test.yaml) |
| TLS_CERT_12: current validity | Covered | Inclusive notBefore / notAfter checks | Chain and evaluation time | Pack rules |

## Executable evidence

The [schema tests](../internal/policy/schema_test.go) validate the shipped pack.
Shared [CRL](../internal/crl/status_assessment_test.go) and
[OCSP](../internal/ocsp/evidence_test.go) tests cover accepted revocation evidence;
[acquisition tests](../internal/crl/acquisition_test.go) cover bounded CRL retrieval.
The [TR-03116 suite](../tests/policy-suites/tr03116.test.yaml) runs a conforming ECDSA P-256 chain with CRLs and variants for
the EKU, key size, lifetime, DSA period and missing-evidence rules.

## Limits

| Area | Limit |
|---|---|
| Service names | Local certificates do not identify the application's intended names; test all declared names separately |
| Availability | A successful retrieval does not establish continuing revocation-service availability |
| Path length | Whether a constraint is reasonably small is application-specific |
| GeneralNames | DNS wildcard checks apply to CN/dNSName, not unrelated name forms |
| Trust | This profile's signature/chain checks do not replace explicit-anchor path validation |

For explicit trust, also load `RFC5280.yaml` and supply `--trust-anchor`.
See [automatic evidence acquisition](../docs/QUICKSTART.md#acquire-evidence-automatically)
for commands.

## Requirement levels

Each rule states the level of its source: `müssen`, `dürfen nicht` and the
TS checklist are MUST; `sollten` is SHOULD. TR-03116-4 (2025) is the
normative text; the TS v1.1 (2023) checklist tests two items that
TR-03116-4 now only recommends:

| Item | TS v1.1 Table 24 | TR-03116-4 (2025) 6.1.2 | Pack |
|---|---|---|---|
| Root lifetime ≤ 6 years | Checked (TLS_CERT_11) | "sollten" | `tls-cert-11-root-validity-max-six-years`: SHOULD (warning) |
| End-entity EKU | serverAuth checked (TLS_CERT_08) | EKU "sollten" | `tls-cert-08-eku-present`: SHOULD; `tls-cert-08-server-auth-eku`: MUST when an EKU is present |

For TS conformity testing, raise these with a local policy that sets
`severity: error`.

Audit of 2026-10-16 against TR-03116-4 (Stand 2025, 3 July 2025),
TR-03116-TS v1.1 and TR-02102-2: the root lifetime was an error for a
"sollten" clause; Table 29, which bounds keys that sign certificates, was
applied to the server's own RSA key, which TR-02102-2 Table 14 bounds at
3000 bits; DSA was accepted without its 2029 end; and serverAuth was
required of a leaf without EKU. The pack is versioned 2025.1.
