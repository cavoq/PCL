# 🏛️ TR-03116 TLS Server Coverage

[Documentation](../docs/POLICY_WRITING_GUIDE.md) · [Policy](TR03116-TLS-SERVER.yaml)

## Scope

TLS server certificate checklist from TR-03116-TS v1.1 §6.1.1 Table 24, with
the TR-03116-4 (2025) cryptographic profile. Source editions are recorded in
policy metadata. Evaluate the complete leaf-to-root chain.

The static profile permits DSA through its stated 2029 period and rejects the
RSASSA-PKCS1-v1_5 transition whose permitted period ended in 2025. It is not an
automatic selector for future editions or dates.

## Requirement matrix

| Requirement | Status | Implementation | Required input | Evidence |
|---|---|---|---|---|
| TLS_CERT_01: public keys | Implemented | RSA/ECDSA server keys; RSA/DSA/ECDSA chain keys; RSA/DSA ≥3072 bits; listed EC curves | Complete chain | Pack rules |
| TLS_CERT_02: signatures | Implemented | ECDSA SHA-256+, DSA SHA-256, or PSS SHA-256+; signature verification | Chain and issuers | Pack rules; combine with [RFC 4055](RFC4055-COVERAGE.md) |
| TLS_CERT_03: wildcards | Partial | Rejects `*` in every CN and SAN dNSName | Certificate Names | Pack rules |
| TLS_CERT_04: revocation information | Partial | Requires CRLDP or OCSP AIA; acquisition can attempt retrieval | Certificate; live service evidence for availability | Pack rules and acquisition tests |
| TLS_CERT_05: revocation status | Implemented with evidence | Requires accepted current CRL or authenticated OCSP Good; Revoked wins | Chain, CRL/OCSP, time | [CRL assessment](../internal/crl/status_assessment_test.go), [OCSP assessment](../internal/ocsp/evidence_test.go) |
| TLS_CERT_06: leaf Key Usage | Implemented | Critical; digitalSignature true, keyCertSign/cRLSign false | Leaf | Pack rules |
| TLS_CERT_07: CA Key Usage | Implemented | Critical; keyCertSign and cRLSign true | CA certificates | Pack rules |
| TLS_CERT_08: EKU | Implemented | Requires serverAuth on leaf | Leaf | Pack rules |
| TLS_CERT_09: service names | External evidence | TLS URL acquisition verifies requested hostname | All intended application names | Acquisition result and external assessment |
| TLS_CERT_10: CA constraints | Partial | Critical CA Basic Constraints, explicit pathLenConstraint, supplied-chain check | Chain and application constraints | Pack rules; smallness remains external |
| TLS_CERT_11: lifetime | Implemented | Calendar bounds: 3 years leaf, 5 intermediate, 6 root | Chain validity dates | Pack rules |
| TLS_CERT_12: current validity | Implemented | Inclusive notBefore / notAfter checks | Chain and evaluation time | Pack rules |

## Executable evidence

The [schema tests](../internal/policy/schema_test.go) validate the shipped pack.
Shared [CRL](../internal/crl/status_assessment_test.go) and
[OCSP](../internal/ocsp/evidence_test.go) tests cover accepted revocation evidence;
[acquisition tests](../internal/crl/acquisition_test.go) cover bounded CRL retrieval.
Rows marked `Implemented` describe active rules, not a dedicated end-to-end
positive/negative test for every TLS_CERT requirement.

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
