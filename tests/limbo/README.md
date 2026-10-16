# x509-limbo

This directory runs the [x509-limbo](https://github.com/C2SP/x509-limbo)
testcases (C2SP) through `pcl`'s lint entry point (`tests/limbo_test.go`).
Limbo bundles its own path validation cases with the BetterTLS
`nameconstraints` and `pathbuilding` suites and a few real-world chains.

| File | Contents |
|------|----------|
| `limbo.json` | Limbo testcases; not committed, see below |
| `path-policy.yaml` | The `pathValid` aggregate decision of the path engine |
| `known-gaps.yaml` | Testcases PCL does not pass yet, grouped by cause |
| `pin` | The pinned limbo commit and SHA-256 of `limbo.json` |

## Source

`limbo.json` is about 40 MB, so it is downloaded instead of vendored:

```bash
make limbo-fetch   # or make limbo to fetch and run
```

`pin` names the limbo commit and the file's SHA-256, which the download is
checked against; CI caches the file per pin. To move to a newer limbo, update
`pin` and reconcile `known-gaps.yaml` with the new results.
x509-limbo is licensed under the Apache License 2.0.

`TestLimbo` skips when `limbo.json` is missing or under `go test -short`.
`PCL_REQUIRE_LIMBO=1` turns a missing file into a failure; CI sets it.

## How a limbo testcase maps to PCL

| Limbo field | PCL input |
|-------------|-----------|
| `peer_certificate` | `--cert` |
| `untrusted_intermediates` | `--issuer` |
| `trusted_certs` | `--trust-anchor` |
| `crls` | `--crl`, with path revocation `if-present` |
| `validation_time` | evaluation time; 2026-07-01 when absent, inside the validity of the pinned BetterTLS data |
| `extended_key_usage` | application purpose |
| `max_chain_depth` | `--max-path-length` |
| `expected_peer_name(s)` | `--peer-name` |

Each testcase is linted with `path-policy.yaml` and the shipped
`policies/RFC5280.yaml`. It succeeds when no error rule fails for any
certificate of the chain, so limbo checks the path engine and the RFC 5280
profile together.

PCL infers a peer name's kind from its syntax; the harness fails if it
differs from the kind limbo states.

Every testcase must reach the limbo result or be listed in
`known-gaps.yaml` with its cause. The list only shrinks: a listed testcase
that starts to conform fails the test until it is removed.
