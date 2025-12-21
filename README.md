# 🔐 PCL - Policy-based Certificate Linter

[![CI](https://github.com/cavoq/PCL/actions/workflows/ci.yml/badge.svg)](https://github.com/cavoq/PCL/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cavoq/PCL/branch/master/graph/badge.svg)](https://codecov.io/gh/cavoq/PCL)
[![Go Report Card](https://goreportcard.com/badge/github.com/cavoq/PCL)](https://goreportcard.com/report/github.com/cavoq/PCL)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)

A flexible X.509 certificate linter that validates certificates against configurable YAML-based policies. Ensure compliance with RFC 5280, organizational standards, or industry best practices.

## 🚀 Quick Start

```bash
go install github.com/cavoq/PCL/cmd/pcl@latest
pcl --policy <path> --cert <path> [--output text|json]
```

## 📝 Policy Configuration

Policies are YAML files defining validation rules with a simple declarative syntax.

```yaml
id: rfc5280
rules:
  - id: version-v3
    target: certificate.version
    operator: eq
    operands: [3]
    severity: error

  - id: signature-algorithm-secure
    target: certificate.signatureAlgorithm.algorithm
    operator: in
    operands:
      - SHA256-RSA
      - SHA384-RSA
      - ECDSA-SHA256
    severity: error

  - id: rsa-key-size-minimum
    target: certificate.subjectPublicKeyInfo.publicKey.keySize
    operator: gte
    operands: [2048]
    severity: error

  - id: ca-basic-constraints
    target: certificate.basicConstraints.cA
    operator: eq
    operands: [true]
    severity: error
    appliesTo: [root, intermediate]
```

## 🏛️ Supported Policies

- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile


## ➕ Supported Operators

| Operator | Description |
|----------|-------------|
| `eq` | Equality check |
| `neq` | Not equal check |
| `present` | Field existence check |
| `gt`, `gte` | Greater than (or equal) |
| `lt`, `lte` | Less than (or equal) |
| `in` | Value in allowed list |
| `notIn` | Value not in disallowed list |
| `contains` | String/array contains value |
| `before` | Date is before current time |
| `after` | Date is after current time |

## Certificate Chain Support

PCL automatically builds and validates certificate chains, applying rules based on certificate position:

- `leaf`: End-entity certificates
- `intermediate`: CA certificates in the chain
- `root`: Self-signed root CA certificates

Use `appliesTo` in rules to target specific certificate types.

## 🔧 Development

```bash
go build -o pcl ./cmd/pcl
go test -v -race ./...
golangci-lint run ./...
```
