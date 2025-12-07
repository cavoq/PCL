# 🔐 PCL - Policy-based Certificate Linter

[![CI](https://github.com/cavoq/PCL/actions/workflows/ci.yml/badge.svg)](https://github.com/cavoq/PCL/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cavoq/PCL/branch/master/graph/badge.svg)](https://codecov.io/gh/cavoq/PCL)
[![Go Report Card](https://goreportcard.com/badge/github.com/cavoq/PCL)](https://goreportcard.com/report/github.com/cavoq/PCL)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)

A flexible X.509 certificate linter that validates certificates against configurable YAML-based policies. Ensure compliance with organizational standards, regulatory requirements, or industry best practices.

## 🚀 Quick Start

```bash
go install github.com/cavoq/PCL/cmd/pcl@latest
pcl --policy <path> --cert <path> [--output text|json]
```

## 📝 Policy Configuration

Policies are YAML files defining validation rules. A JSON schema is available at [`policy-schema.json`](policy-schema.json).

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

## 🏛️ Supported Policies

### BSI TR-03116-TS

The requirements for TLS certificates used in governmental IT systems in Germany are based on the RFC 5280 standard with additional constraints defined by the BSI technical guideline [TR-03116-4](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03116/tr-03116.html).

## 🔧 Development

```bash
go build -o pcl ./cmd/pcl
go test ./...
golangci-lint run ./...
```
