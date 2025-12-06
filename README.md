# 🔐 PCL - Policy-based Certificate Linter

[![CI](https://github.com/cavoq/PCL/actions/workflows/ci.yml/badge.svg)](https://github.com/cavoq/PCL/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cavoq/PCL/branch/master/graph/badge.svg)](https://codecov.io/gh/cavoq/PCL)
[![Go Report Card](https://goreportcard.com/badge/github.com/cavoq/PCL)](https://goreportcard.com/report/github.com/cavoq/PCL)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)

A flexible X.509 certificate linter that validates TLS certificates against configurable YAML-based policies. Ensure compliance with organizational standards, regulatory requirements, or industry best practices.

## ✨ Features

- 📋 **Policy-driven validation** — Define custom rules in YAML
- 🔗 **Certificate chain support** — Different policies for leaf, intermediate, and root
- 📊 **Multiple outputs** — Human-readable text or JSON for CI/CD
- 🔍 **Comprehensive checks** — Algorithms, key sizes, validity, extensions
- 📁 **Flexible input** — PEM/DER formats, files or directories

## 🚀 Quick Start

```bash
# Install
go install github.com/cavoq/PCL/cmd/pcl@latest

# Run
pcl --policy policies/BSI-TR-03116-TS --cert /path/to/cert.pem
```

## 📖 Usage

```
pcl --policy <path> --cert <path> [--output text|json]
```

| Flag | Description |
|------|-------------|
| `--policy` | Path to policy YAML file or directory |
| `--cert` | Path to certificate file or directory (PEM/DER) |
| `--output` | Output format: `text` (default) or `json` |

## 📝 Policy Configuration

Policies are YAML files defining validation rules. A JSON schema is available at [`policy-schema.json`](policy-schema.json) for IDE support.

```yaml
name: Leaf Certificate Policy
cert_order: 0  # 0=leaf, 1=intermediate, 2+=root

validity:
  min_days: 1
  max_days: 365

crypto:
  subjectPublicKeyInfo:
    allowed_algorithms:
      RSA:
        min_size: 3072
      EC:
        min_size: 256
        allowed_curves: [P-256, P-384]
  signatureAlgorithm:
    allowed_algorithms: [SHA256-RSA, ECDSA-SHA256]

extensions:
  keyUsage:
    critical: true
    digitalSignature: true
```

## ✅ Validation Rules

| Rule | Description |
|------|-------------|
| Validity | Certificate validity period (min/max days) |
| Subject/Issuer | Name patterns, wildcard detection |
| Signature Algorithm | Allowed algorithms list |
| Signature Validation | Cryptographic verification |
| Public Key Info | Key type, size, curves |
| Key Usage | digitalSignature, keyCertSign, cRLSign |
| Extended Key Usage | serverAuth, clientAuth |
| Basic Constraints | CA flag, pathLenConstraint |

## 🏛️ Included Policies

### BSI TR-03116-TS

Implements the German Federal Office for Information Security (BSI) Technical Guideline [TR-03116-4](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03116/tr-03116.html) for TLS certificates.

| Requirement | Value |
|-------------|-------|
| Min RSA key size | 3072 bits |
| Min EC key size | 256 bits |
| Allowed curves | P-256, P-384, P-521, brainpoolP* |
| Signature algorithms | SHA-256+, RSA-PSS, ECDSA, Ed25519 |

## 🔧 Development

```bash
# Build
go build -o pcl ./cmd/pcl

# Test
go test ./...

# Lint
golangci-lint run ./...
```

## 📄 License

[GPL-3.0](LICENSE)
