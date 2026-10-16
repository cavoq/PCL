# 🔐 PCL — Policy-driven PKI Conformance Engine

[![CI](https://github.com/cavoq/PCL/actions/workflows/ci.yml/badge.svg)](https://github.com/cavoq/PCL/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cavoq/PCL/branch/master/graph/badge.svg)](https://codecov.io/gh/cavoq/PCL)
[![Go Report Card](https://goreportcard.com/badge/github.com/cavoq/PCL)](https://goreportcard.com/report/github.com/cavoq/PCL)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)

PCL evaluates X.509 certificates, certification paths, CRLs, and OCSP evidence
against versioned YAML policy packs. It provides structured pass/fail/skip
results, explicit-trust path validation, and tests for custom policies.

## 📦 Install

Install the CLI with Go 1.26 or newer:

```bash
go install github.com/cavoq/PCL/cmd/pcl@latest
```

Policy packs are separate YAML files in [policies/](policies). Use packs from
the same release as your binary. The examples below assume a repository
checkout; for unreleased features, build it and use `./pcl` in place of `pcl`:

```bash
go build -o pcl ./cmd/pcl
./pcl --help
```

---

## 🚀 Quick Start

**Start with just a leaf certificate** — automatically acquire issuers and
revocation evidence:

```bash
pcl --policy policies/RFC5280.yaml --cert leaf.pem --auto-validate
```

No `--issuer` is needed when the certificates advertise reachable CA Issuers
URLs. If an issuer cannot be acquired, supply it locally.

**Use a chain directory** containing the leaf, intermediates, and root:

```bash
pcl --policy policies/RFC5280.yaml --cert chain/ --details
```

Add `--auto-validate` to acquire missing issuers and revocation evidence.
The directory supplies one chain, not a batch of unrelated leaf certificates.

**Keep the leaf and issuers separate** for a run using local inputs:

```bash
pcl --policy policies/RFC5280.yaml --cert leaf.pem --issuer issuers/ --details
```

**Check a live TLS endpoint** — replace the example URL with your server:

```bash
pcl --policy policies/RFC5280.yaml --cert-url https://example.test --auto-validate
```

**Validate against explicit trust** while acquiring issuers and revocation evidence:

```bash
pcl --policy policies/RFC5280.yaml --cert leaf.pem --auto-validate \
  --trust-anchor roots/ --path-revocation required --fail-on error
```

**Save structured results**, including passed and skipped rules:

```bash
pcl --policy policies/RFC5280.yaml --cert chain/ --output json -vv > results.json
```

**Discover paths for writing a policy**, using a local chain or automatic acquisition:

```bash
pcl inspect --cert chain/ --paths
pcl inspect --cert leaf.pem --auto-validate --paths
```

`--cert`, `--issuer`, and `--trust-anchor` accept files or directories.
Issuer candidates supply chain data; trust anchors state what you trust.
A root supplied only as an issuer is not automatically trusted.
See [Run PCL](docs/QUICKSTART.md) for combined policies, local CRL/OCSP evidence,
and acquisition controls.

---

## ✅ Read the Results

| Option | Effect |
|---|---|
| Default | Show failed rules |
| `-v` / `-vv` | Include passed / passed and skipped rules |
| `--details` | Show explanations beneath text rows |
| `--output json` or `yaml` | Structured findings for displayed rules |
| `--fail-on error` | Exit nonzero on failed error-severity rules |

Run errors always exit nonzero. Completed runs default to `--fail-on none`,
so rule failures alone do not change the exit status.
See [output and exit status](docs/QUICKSTART.md#output-and-exit-status).

---

## 🏛️ Policy Packs

| Pack | Scope |
|---|---|
| [RFC 5280](policies/RFC5280.yaml) | Certificate/CRL profiles and conditional explicit-trust path validation; [coverage](policies/RFC5280-COVERAGE.md) |
| [RFC 4055](policies/RFC4055.yaml) | RSA algorithm-identifier parameters; [coverage](policies/RFC4055-COVERAGE.md) |
| [RFC 6960](policies/RFC6960.yaml) | Leaf-bound, authenticated OCSP evidence; missing or unacceptable evidence fails |
| [TR-03116 TLS server](policies/TR03116-TLS-SERVER.yaml) | BSI certificate checklist and 2025 cryptographic profile; [coverage](policies/TR03116-TLS-SERVER-COVERAGE.md) |
| [Local profile](policies/LOCAL-PROFILE.yaml) | Supplemental local and WebPKI checks |

Repeat `--policy` to combine packs. Pack metadata describes source editions
and relevant inputs; the coverage matrices state the implemented scope.

### 🧪 Conformance Evidence

The integration suite reaches the expected result for all **247 NIST PKITS
runs** through the explicit-anchor path engine. This is test-suite evidence,
not a claim of universal RFC coverage. See [PKITS](tests/pkits/README.md).

The [x509-limbo](tests/limbo/README.md) suite, including BetterTLS, runs
against the path engine and the RFC 5280 profile: **9737 of 9802 testcases**
reach the limbo result. The rest are listed with their cause in
[known gaps](tests/limbo/known-gaps.yaml), most of them CA/B Forum
requirements outside RFC 5280.

---

## 📚 Documentation

| Task | Reference |
|---|---|
| 🚀 Choose inputs, acquire evidence, control output | [Run PCL](docs/QUICKSTART.md) |
| 📝 Write YAML policies and metadata | [Policy format](docs/POLICY_FORMAT.md) |
| ➕ Choose an operator | [Operator reference](docs/OPERATORS.md) |
| 🌳 Understand target paths and parsing contracts | [Node model](docs/NODE_MODEL.md) |
| 🧪 Test a policy against fixtures | [Policy testing](docs/TESTING.md) |
| 🏗️ Understand package ownership and data flow | [Architecture](architecture.md) |
| 📋 Upgrade from a previous release | [Changelog](CHANGELOG.md) |

---

## 🔧 Development

```bash
go test -race ./...
go vet ./...
golangci-lint run ./...
```

Run repository policy examples with `pcl test tests/policy-suites`.
Documentation conventions are in the [documentation index](docs/POLICY_WRITING_GUIDE.md).
