# PCL - Policy-based Certificate Linter

A flexible X.509 certificate linter that validates TLS certificates against configurable YAML-based policies. PCL helps ensure your certificates comply with organizational standards, regulatory requirements, or industry best practices.

## Features

- **Policy-driven validation** - Define custom rules in YAML format
- **Certificate chain support** - Validate leaf, intermediate, and root certificates with different policies
- **Multiple output formats** - Human-readable text or JSON for CI/CD integration
- **Comprehensive checks** - Signature algorithms, key sizes, validity periods, extensions, and more
- **Flexible input** - Accepts PEM and DER formats, single files or directories

## Installation

### From Source

```bash
go install github.com/cavoq/PCL/cmd/pcl@latest
```

### Build Locally

```bash
git clone https://github.com/cavoq/PCL.git
cd PCL
go build -o pcl ./cmd/pcl
```

## Quick Start

```bash
# Validate a certificate against a policy
pcl --policy policies/BSI-TR-03116-TS --cert /path/to/certificate.pem

# Validate with JSON output
pcl --policy policies/BSI-TR-03116-TS --cert /path/to/certs/ --output json
```

## Usage

```
pcl --policy <path> --cert <path> [--output <format>]

Flags:
  --policy    Path to policy YAML file or directory (required)
  --cert      Path to certificate file or directory - PEM/DER (required)
  --output    Output format: text or json (default: text)
```

## Policy Configuration

Policies are defined in YAML format. Each policy specifies validation rules for a certificate at a specific position in the chain.

### Policy Schema

A JSON schema is available at [`policy-schema.json`](policy-schema.json) for IDE autocompletion and validation.

### Basic Policy Structure

```yaml
name: My Custom Policy
cert_order: 0  # 0=leaf, 1=intermediate, 2=root
description: Policy for end-entity certificates

validity:
  min_days: 1
  max_days: 365

crypto:
  subjectPublicKeyInfo:
    allowed_algorithms:
      RSA:
        min_size: 2048
      EC:
        min_size: 256
        allowed_curves:
          - P-256
          - P-384
  signatureAlgorithm:
    allowed_algorithms:
      - SHA256-RSA
      - ECDSA-SHA256

extensions:
  keyUsage:
    critical: true
    digitalSignature: true
  basicConstraints:
    critical: true
    isCA: false
```

### Supported Signature Algorithms

The following signature algorithms are supported (values match Go's `x509.SignatureAlgorithm.String()` output):

| Algorithm | Description |
|-----------|-------------|
| `MD5-RSA` | RSA with MD5 (legacy, insecure) |
| `SHA1-RSA` | RSA with SHA-1 (legacy) |
| `SHA256-RSA` | RSA PKCS#1 v1.5 with SHA-256 |
| `SHA384-RSA` | RSA PKCS#1 v1.5 with SHA-384 |
| `SHA512-RSA` | RSA PKCS#1 v1.5 with SHA-512 |
| `SHA256-RSAPSS` | RSA-PSS with SHA-256 |
| `SHA384-RSAPSS` | RSA-PSS with SHA-384 |
| `SHA512-RSAPSS` | RSA-PSS with SHA-512 |
| `DSA-SHA1` | DSA with SHA-1 (legacy) |
| `DSA-SHA256` | DSA with SHA-256 |
| `ECDSA-SHA1` | ECDSA with SHA-1 (legacy) |
| `ECDSA-SHA256` | ECDSA with SHA-256 |
| `ECDSA-SHA384` | ECDSA with SHA-384 |
| `ECDSA-SHA512` | ECDSA with SHA-512 |
| `Ed25519` | EdDSA with Curve25519 |

### Supported Elliptic Curves

| Curve | Description |
|-------|-------------|
| `P-256` | NIST P-256 (secp256r1) |
| `P-384` | NIST P-384 (secp384r1) |
| `P-521` | NIST P-521 (secp521r1) |
| `brainpoolP256r1` | Brainpool 256-bit |
| `brainpoolP384r1` | Brainpool 384-bit |
| `brainpoolP512r1` | Brainpool 512-bit |

### Public Key Algorithms

The following key types can be specified in `allowed_algorithms`:

| Key | Description |
|-----|-------------|
| `RSA` | RSA keys (specify `min_size` in bits) |
| `EC` | Elliptic Curve keys (specify `min_size` and `allowed_curves`) |
| `Ed25519` | Ed25519 keys |
| `DSA` | DSA keys (legacy, specify `min_size`) |

## Validation Rules

PCL performs the following checks:

| Rule | Description |
|------|-------------|
| **Validity** | Certificate validity period (min/max days) |
| **Subject/Issuer** | Name pattern matching, wildcard detection |
| **Signature Algorithm** | Allowed signature algorithms |
| **Signature Validation** | Cryptographic signature verification |
| **Public Key Info** | Key algorithm, size, and curve validation |
| **Key Usage** | Digital signature, cert signing, CRL signing |
| **Extended Key Usage** | Server/client authentication |
| **Basic Constraints** | CA flag and path length constraints |

## Example Output

### Text Output

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Certificate: example.com                                                      │
│ Policy: BSI-TR-03116-TS Leaf-Policy                                          │
├──────────────────────────────────────────────────────────────────────────────┤
│ [PASS] validity.not_after: Certificate is currently valid                    │
│ [PASS] validity.period: Validity period acceptable: 365 days                 │
│ [PASS] crypto.signature_algorithm: Signature algorithm allowed: SHA256-RSA   │
│ [PASS] crypto.signature_validity: Signature is valid                         │
│ [PASS] crypto.subject_public_key_info.RSA: RSA key size acceptable: 4096 bits│
│ [PASS] extensions.key_usage: Key usage requirements met                      │
└──────────────────────────────────────────────────────────────────────────────┘
```

### JSON Output

```json
{
  "certificate": "example.com",
  "policy": "BSI-TR-03116-TS Leaf-Policy",
  "results": [
    {
      "rule": "validity.not_after",
      "status": "PASS",
      "message": "Certificate is currently valid"
    }
  ]
}
```

## Included Policies

### BSI-TR-03116-TS

Policy set implementing the German Federal Office for Information Security (BSI) Technical Guideline [TR-03116-TS](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03116/BSI-TR-03116-4.html) for TLS certificates.

This guideline specifies cryptographic requirements for TLS implementations in the German federal administration and is widely adopted as a security baseline.

**Included policies:**
- `leaf.yaml` - End-entity certificate requirements
- `intermediate.yaml` - Intermediate CA requirements
- `root.yaml` - Root CA requirements

**Key requirements:**
- Minimum RSA key size: 3072 bits
- Minimum EC key size: 256 bits
- Allowed curves: P-256, P-384, P-521, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
- Modern signature algorithms (SHA-256+, RSA-PSS, ECDSA, Ed25519)
- Maximum validity: 3 years (leaf), 5 years (intermediate), 6 years (root)

## Creating Custom Policies

1. Create a new YAML file based on the policy structure above
2. Set `cert_order` to specify which certificate in the chain this policy applies to
3. Define your validation rules
4. Use the JSON schema for validation: `policy-schema.json`

**Example: Strict leaf certificate policy**

```yaml
name: Strict Leaf Policy
cert_order: 0
description: Strict requirements for production certificates

validity:
  max_days: 90  # Short-lived certificates

crypto:
  subjectPublicKeyInfo:
    allowed_algorithms:
      EC:
        min_size: 256
        allowed_curves:
          - P-256
          - P-384
  signatureAlgorithm:
    allowed_algorithms:
      - ECDSA-SHA256
      - ECDSA-SHA384

subject:
  no_wildcards: true

extensions:
  keyUsage:
    critical: true
    digitalSignature: true
  extendedKeyUsage:
    serverAuth: true
```

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.
