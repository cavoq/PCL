# NIST PKITS

This directory vendors the certificates and CRLs of the NIST Public Key
Interoperability Test Suite (PKITS) 1.0.1, the reference conformance suite for
RFC 5280 certification path validation, and runs every test through `pcl`'s
lint entry point (`tests/pkits_test.go`).

| File | Contents |
|------|----------|
| `certs/`, `crls/` | PKITS data, unchanged |
| `manifest.json` | One entry per PKITS Section 4 test: end entity, issuers, CRLs and one run per input setting with the expected result |
| `known-gaps.yaml` | Runs PCL cannot pass yet, grouped by cause |

## Source

- Data: <https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip>
  (SHA-256 `592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665`)
- Description: <https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf>
  (SHA-256 `506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea`)

PKITS was produced by NIST, a U.S. Government agency; its test data is not
subject to copyright protection in the United States.

`manifest.json` is generated from the description:

```bash
pdftotext -layout PKITS.pdf PKITS.txt
python3 -I tests/scripts/pkits-manifest.py PKITS.txt tests/pkits > tests/pkits/manifest.json
```

## How a PKITS run maps to PCL

Each run lints the end entity with `--issuer` set to the path's certificates,
`--crl` to its CRLs, `--trust-anchor` to the PKITS trust anchor, required
path revocation and an evaluation time of 2020-01-01 (inside the 2010-2030
validity of the data). The run passes the path engine's aggregate decision
in the shared `tests/policies/path-valid.yaml`, which also processes
certificate policies with the run's initial policy set, explicit-policy,
policy-mapping-inhibit and any-policy-inhibit inputs.

All 247 runs reach the PKITS result. `known-gaps.yaml` is retained as an empty
ratchet: any future exception must be explicit and documented there.
