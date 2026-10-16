# 🧪 Test Policies

[Documentation](POLICY_WRITING_GUIDE.md) · [Policy format](POLICY_FORMAT.md) · [Run PCL](QUICKSTART.md)

Purpose: check a policy's behavior against repeatable fixtures using the same
acquisition and evaluation pipeline as a lint run.

Inputs: a `*.test.yaml` suite, policy files, and certificate/revocation fixtures.
All paths are relative to the suite file.

## Suite format

```yaml
policy: ../policies/my-profile.yaml
time: 2026-10-01
tests:
  - name: compliant certificate
    cert: certs/good-leaf.pem
    issuers: [certs/intermediate.pem]
    trustAnchors: [certs/root.pem]
    expect:
      - input: leaf
        policy: my-profile
        verdict: pass
        rules:
          san-present: pass

  - name: required SAN missing
    cert: certs/no-san.pem
    expect:
      - input: leaf
        rules:
          san-present: fail

  - name: unreadable input
    cert: certs/missing.pem
    error: failed to load certificates
```

| Field | Meaning |
|---|---|
| Suite `policy` | One policy path or a list |
| Suite `time` | Shared evaluation time; fixes fixture aging |
| Case `name` | Required description |
| `cert`, `crl`, `ocsp` | Input file/directory paths |
| `issuers`, `trustAnchors` | Lists of certificate paths |
| `purpose`, `time` | Case-specific runtime inputs |
| `maximumPathLength`, `pathRevocation` | Explicit path-validation controls |
| `peerNames` | Reference identities the target must present (`--peer-name`) |
| `certificatePolicyInputs` | Initial RFC 5280 policy-processing parameters |
| `expect` | Expected policy and/or rule verdicts |
| `error` | Expected run-error substring, instead of verdict expectations |

An expectation selects `input` (`leaf`, `intermediate`, `root`, `ocspSigning`,
`crl`, or `ocsp`) and optionally a policy ID. `verdict` checks the overall
result; `rules` checks named rule verdicts; `failed` lists exactly the rules
that fail, `[]` for none, so a new failing rule is caught while new passing or
skipped rules are not. At least one of them is required.

Additional case inputs:

```yaml
trustAnchors: [certs/root.pem]
maximumPathLength: 2
pathRevocation: required
certificatePolicyInputs:
  initialPolicySet: [1.2.3.4]
  initialExplicitPolicy: true
  initialPolicyMappingInhibit: true
  initialAnyPolicyInhibit: true
```

## Run a suite

```bash
pcl test tests/policy-suites
```

Result: one `PASS` or `FAIL` per case, mismatch details, and a summary.

Failure behavior: a malformed suite, run error, or unmet expectation exits
nonzero. A deliberately failing policy rule is a successful test when the
expected verdict is `fail`.

See [repository suites](../tests/policy-suites) for runnable examples,
[PKITS](../tests/pkits/README.md) for the NIST suite mapping and
[x509-limbo](../tests/limbo/README.md) for the limbo mapping. Limbo's
testcases are downloaded with `make limbo-fetch`; without them `TestLimbo`
skips.

## Development checks

The Makefile is the entry point; CI runs the same targets.

| Target | Runs |
|---|---|
| `make check` | `tidy-check`, `schema-check`, `lint` and `race`: the checks before pushing |
| `make test` / `make race` | All tests, without or with the race detector |
| `make cover` | All tests with race detection and coverage over every package |
| `make limbo` | Fetches the pinned x509-limbo testcases and runs `TestLimbo` |
| `make fuzz FUZZTIME=30s` | Every fuzz target for the given time |
| `make lint` / `make vuln` | golangci-lint and govulncheck at pinned versions |
| `make schema` | Regenerates `schemas/policy.schema.json` |
| `make fixtures` | Regenerates the certificate, CRL and OCSP fixtures with `tests/fixturegen` |
| `make psl-snapshot` | Refreshes the Public Suffix List snapshot embedded in the binary |

Changes to policy fields or operator contracts must also regenerate
`schemas/policy.schema.json` with `make schema`. The policy tests
check the committed schema and parser agreement. Add executable evidence for
new coverage claims; retain known gaps in the coverage matrix.
