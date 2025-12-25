# 🔐 PCL - Policy-based Certificate Linter

[![CI](https://github.com/cavoq/PCL/actions/workflows/ci.yml/badge.svg)](https://github.com/cavoq/PCL/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/cavoq/PCL/branch/master/graph/badge.svg)](https://codecov.io/gh/cavoq/PCL)
[![Go Report Card](https://goreportcard.com/badge/github.com/cavoq/PCL)](https://goreportcard.com/report/github.com/cavoq/PCL)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)

A flexible X.509 certificate linter that validates certificates against configurable YAML-based policies. Ensure compliance with RFC 5280, organizational standards, or industry best practices.

## 🚀 Quick Start

```bash
go install github.com/cavoq/PCL/cmd/pcl@latest
pcl --policy <path> --cert <path> [--crl <path>] [--output text|json|yaml]
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

  # Conditional rule using "when" clause
  - id: rsa-key-size-minimum
    when:
      target: certificate.subjectPublicKeyInfo.algorithm
      operator: eq
      operands: [RSA]
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

### Comparison Operators

| Operator | Description |
|----------|-------------|
| `eq` | Equality check |
| `neq` | Not equal check |
| `gt`, `gte` | Greater than (or equal) |
| `lt`, `lte` | Less than (or equal) |
| `in` | Value in allowed list |
| `notIn` | Value not in disallowed list |
| `contains` | String/array contains value |
| `matches` | Compare two field paths for equality |

### Presence & Value Operators

| Operator | Description |
|----------|-------------|
| `present` | Field existence check |
| `absent` | Field does not exist |
| `isEmpty`, `notEmpty` | Value emptiness check |
| `positive` | Value is a positive number |
| `odd` | Value is an odd number (for RSA exponent validation) |
| `maxLength`, `minLength` | String/array length constraints |
| `regex`, `notRegex` | Regular expression pattern matching |

### Date Operators

| Operator | Description |
|----------|-------------|
| `before` | Date is before current time |
| `after` | Date is after current time |
| `validityOrderCorrect` | Validates notBefore < notAfter |
| `validityDays` | Certificate validity period check |

### Extension Operators

| Operator | Description |
|----------|-------------|
| `isCritical`, `notCritical` | Extension criticality check |
| `noUnknownCriticalExtensions` | No unhandled critical extensions |

### Certificate Chain Operators

| Operator | Description |
|----------|-------------|
| `signedBy` | Cryptographic signature verification |
| `signatureAlgorithmMatchesTBS` | Signature algorithm matches TBS certificate |
| `issuedBy` | Issuer DN matches issuer's subject DN |
| `akiMatchesSki` | Authority Key ID matches issuer's Subject Key ID |
| `pathLenValid` | Path length constraint validation |
| `serialNumberUnique` | Serial number uniqueness in chain |

### Key Usage & Constraints Operators

| Operator | Description |
|----------|-------------|
| `sanRequiredIfEmptySubject` | SAN required when subject is empty |
| `keyUsageCA`, `keyUsageLeaf` | Key usage validation by cert type |
| `ekuContains`, `ekuNotContains` | Extended key usage checks |
| `ekuServerAuth`, `ekuClientAuth` | TLS authentication EKU checks |
| `noUniqueIdentifiers` | Absence of issuer/subject unique IDs |

### CRL Operators

| Operator | Description |
|----------|-------------|
| `crlValid` | CRL is within thisUpdate/nextUpdate window |
| `crlNotExpired` | CRL nextUpdate is in the future |
| `crlSignedBy` | CRL signature verification against chain |
| `notRevoked` | Certificate not in CRL revoked list |

## 🔀 Conditional Rules

Rules can include a `when` clause to apply only when certain conditions are met:

```yaml
- id: rsa-exponent-valid
  when:
    target: certificate.subjectPublicKeyInfo.algorithm
    operator: eq
    operands: [RSA]
  target: certificate.subjectPublicKeyInfo.publicKey.exponent
  operator: odd
  severity: error
```

This rule only validates RSA exponent when the certificate uses RSA. If the condition is not met, the rule is skipped.

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
