# 🏛️ RFC 6960 Coverage

[Documentation](../docs/POLICY_WRITING_GUIDE.md) · [Policy](RFC6960.yaml)

## Scope

OCSP evidence for leaf certificates, the validity window and nonce of each
supplied response, and delegated responder certificates embedded in
responses. RFC 8954 updates the nonce rules. Signature, issuer binding,
responder authorization and currency are decided by the OCSP evidence
assessment that `ocspValid` reports; the response node tree carries times,
status, nonce and algorithms.

## Requirement matrix

| Requirement | Status | Implementation | Required input | Evidence |
|---|---|---|---|---|
| Response acceptance: certificate and issuer, signature, authorized signer, currency (§3.2 items 1–6, SHALL) | Covered | `ocsp-valid`; inconclusive without a response for the certificate | Leaf, issuer, OCSP response, time | [RFC 6960 suite](../tests/policy-suites/rfc6960.test.yaml), [OCSP suite](../tests/policy-suites/ocsp.test.yaml), [evidence tests](../internal/ocsp/evidence_test.go) |
| Certificate status Good (§2.2) | Covered | `ocsp-not-revoked`; inconclusive without a response | Leaf, issuer, OCSP response, time | [RFC 6960 suite](../tests/policy-suites/rfc6960.test.yaml), [OCSP suite](../tests/policy-suites/ocsp.test.yaml) |
| Authorized delegated responders (§4.2.2.2) | Covered within `ocsp-valid` | id-kp-OCSPSigning responder issued by the CA that issued the certificate | Embedded responder certificate | [RFC 6960 suite](../tests/policy-suites/rfc6960.test.yaml), [evidence tests](../internal/ocsp/evidence_test.go) |
| nextUpdate not before the validation time (§3.2 item 6, SHALL; §4.2.2.1) | Covered | `ocsp-response-next-update-not-past` | OCSP response, time | [RFC 6960 suite](../tests/policy-suites/rfc6960.test.yaml) |
| thisUpdate not after the validation time (§4.2.2.1, SHOULD) | Covered | `ocsp-response-this-update-not-future` | OCSP response, time | [RFC 6960 suite](../tests/policy-suites/rfc6960.test.yaml) |
| Nonce of 1 to 32 octets (RFC 8954 §2.1) | Covered | `ocsp-response-nonce-not-empty`, `ocsp-response-nonce-max-length` | OCSP response | [RFC 6960 suite](../tests/policy-suites/rfc6960.test.yaml) |
| id-pkix-ocsp-nocheck non-critical (SHOULD) and NULL (SHALL) (§4.2.2.2.1) | Covered | `ocsp-responder-nocheck-not-critical`, `ocsp-responder-nocheck-null` | Embedded responder certificate | [RFC 6960 suite](../tests/policy-suites/rfc6960.test.yaml) |
| RSASSA-PSS response signatures | Covered within `ocsp-valid` | SHA-256/384/512 with MGF1 over the same hash | OCSP response | [PSS tests](../internal/ocsp/pss_test.go) |

## Requirement levels

Every rule states the RFC 2119 level of its clause.
`ocsp-response-this-update-not-future` and
`ocsp-responder-nocheck-not-critical` implement SHOULD clauses and are
warnings; the others implement MUST or SHALL clauses.

Audit of 2026-10-16: the pack held two leaf rules citing "RFC6960" without a
section. It now cites §3.2 and §2.2, and adds the response window, nonce and
nocheck rules above.

## Limits

| Area | Limit |
|---|---|
| Response status | Only successful responses with a BasicOCSPResponse are parsed; responseStatus values are not checked |
| Request binding | The nonce is not compared with a request nonce, and a response is matched to the certificate by CertID, not to a request |
| Multiple SingleResponses | Only the first SingleResponse of a response is evaluated |
| Responder certificate profile | Only id-pkix-ocsp-nocheck is checked; responder key usage and validity follow the evidence assessment |
| ResponderID | Whether byKey holds the SHA-1 hash of the signer's key is not checked |
| Extensions | Extended Revoked Definition (§4.4.8), archive cutoff, CRL references and preferred signature algorithms (§4.4.7) are not checked |
| Recency | §3.2 item 5 asks that thisUpdate be "sufficiently recent"; no maximum age is enforced |
