# 🚀 Run PCL

[Documentation](POLICY_WRITING_GUIDE.md) · [Policy format](POLICY_FORMAT.md) · [Policy tests](TESTING.md)

Examples assume a repository checkout, so `policies/` is available. Replace
certificate and evidence paths with your own files. `pcl --help` lists all
flags for the installed version.

## Inputs

| Flag | Meaning | File or directory? |
|---|---|---|
| `--policy` | YAML rules to execute; repeatable | Both |
| `--cert` | Target certificate and supplied chain certificates | Both, PEM/DER |
| `--issuer` | Issuer candidates; repeatable | Both, PEM/DER |
| `--trust-anchor` | Explicitly trusted certificates; repeatable | Both, PEM/DER |
| `--crl` | CRL evidence | Both, PEM/DER |
| `--ocsp` | OCSP response evidence | Both, DER/PEM |
| `--purpose` | Application EKU, such as `serverAuth` | Friendly name or OID |

The flag is `--cert`, singular. A directory can supply a chain, but a run
constructs one selected path; it is not a batch of unrelated leaf certificates.
Providing a root in `--cert` or `--issuer` does not make it trusted. Supply it
with `--trust-anchor` to select explicit path validation. An anchor need not
be self-signed.

## Check a certificate profile

Purpose: apply certificate and CRL profile rules without an explicit trust decision.

Inputs: a certificate and policy; provide the chain together or supply issuers separately.

Leaf and chain certificates in one directory:

```bash
pcl --policy policies/RFC5280.yaml --cert chain/ --details
```

Leaf and issuer candidates in separate locations:

```bash
pcl --policy policies/RFC5280.yaml --cert leaf.pem --issuer issuers/ --details
```

Result: per-rule verdicts for the selected chain. The explicit path rule skips
when no trust anchor is supplied.

Failure behavior: missing or invalid evidence can fail dependent rules. Use
`--fail-on error` when those failures must also produce a nonzero exit status.

## Validate a path with explicit trust

Purpose: validate one constructed path against a caller-selected trust set.

Inputs: a target, issuer candidates, trusted certificates, and revocation evidence.

Acquire issuers and revocation evidence automatically; only the target and
explicit trust anchors need to be local:

```bash
pcl --policy policies/RFC5280.yaml --cert leaf.pem --trust-anchor roots/ \
  --auto-validate --path-revocation required --fail-on error --details
```

Use local chain and CRL evidence instead:

```bash
pcl --policy policies/RFC5280.yaml \
  --cert leaf.pem --issuer intermediates/ --trust-anchor roots/ \
  --crl crls/ --path-revocation required --purpose serverAuth \
  --peer-name www.example.com --fail-on error --details
```

Result: the target's `certification-path-valid` rule reports an aggregate
decision with structured findings. Path construction is deterministic and
bounded; validation is separate from construction.

Failure behavior: a missing anchor, invalid path, or insufficient required
revocation evidence fails the path decision. PCL does not search every possible
alternative path. Trust anchors are never downloaded or inferred.

| Option | Meaning |
|---|---|
| `--max-path-length N` | Maximum non-self-issued intermediates; zero is meaningful; requires an anchor |
| `--peer-name NAME` | DNS name, IP address or email address the target must present in its subjectAltName (repeatable); requires an anchor |
| `--path-revocation none` | Disable revocation in the aggregate path decision |
| `--path-revocation if-present` | Assess available evidence; default |
| `--path-revocation required` | Require acceptable evidence for each non-anchor certificate |

The revocation mode controls the path decision. Separately selected CRL/OCSP
policy rules still apply. CRL signer paths must reach the same explicit trust set.

## Acquire evidence automatically

Purpose: retrieve missing issuers, CRLs, and OCSP responses before evaluation.

Inputs: a target certificate, policies, network access, and local trust anchors
if an explicit path decision is wanted.

Start with just the leaf:

```bash
pcl --policy policies/RFC5280.yaml --cert leaf.pem --auto-validate
```

`--issuer` is optional: PCL follows advertised CA Issuers URLs. If those URLs
are absent or unreachable, add `--issuer issuers/` or supply the available
chain with `--cert chain/`. Automatic acquisition also works with that directory:

```bash
pcl --policy policies/RFC5280.yaml --cert chain/ --auto-validate -v --details
```

Combine policies for a TLS server profile:

```bash
pcl --policy policies/TR03116-TLS-SERVER.yaml \
  --policy policies/RFC4055.yaml --cert server.pem --auto-validate -v --details
```

Result: rules consume the acquired evidence. The TR profile's external
requirements are listed in its [coverage matrix](../policies/TR03116-TLS-SERVER-COVERAGE.md).

Failure behavior: retrieval does not prove trust or service availability over
time. Missing, stale, malformed, or unrelated evidence cannot establish Good status.

| Option | Effect |
|---|---|
| `--no-auto-chain`, `--no-auto-crl`, `--no-auto-ocsp` | Disable a specific automatic acquisition step |
| `--max-chain-depth N` | Bound automatic issuer climbing; distinct from path-length validation |
| `--cert-url-timeout 10s` | Retrieval timeout, including automatic CRL retrieval |
| `--ocsp-url-timeout 5s` | OCSP request timeout; default 5 seconds |
| `--ocsp-hash sha256` | Default CertID hash; `sha1` is also supported |
| `--ocsp-nonce-length 32` | Default nonce length |
| `--ocsp-nonce-value HEX` | Fixed nonce bytes for diagnostics |
| `--no-ocsp-nonce` | Disable the request nonce |

CA Issuers retrieval requires `--auto-validate` without `--no-auto-chain`.
It supports PKCS#7 certificate bundles. Automatic CRLs use bounded HTTP(S)
DER retrieval from CRLDP and Freshest CRL; PEM CRLs are local-input only.
`-vv` includes OCSP request/response diagnostics.

To acquire a live TLS chain instead of loading a local target:

```bash
pcl --policy policies/TR03116-TLS-SERVER.yaml \
  --cert-url https://example.test --cert-url-save-dir downloads/ --auto-validate
```

TLS acquisition verifies the requested hostname. It does not establish that
all service names declared by an application have been tested.

## Inspect rule targets

Purpose: discover the exact paths and values available to profile rules.

Inputs: the same profile inputs as a lint run; no policy is needed.

```bash
pcl inspect --cert chain/ --paths
pcl inspect --cert leaf.pem --auto-validate --paths
pcl inspect --crl list.crl --output json
```

Result: a tree or path list, with bytes shown as hex and times in RFC 3339 UTC.

Failure behavior: acquisition or parsing errors stop inspection. The lint-only
path flags (`--trust-anchor`, `--max-path-length`, `--path-revocation`,
`--peer-name`) are not accepted. See the [node model](NODE_MODEL.md) for
representation contracts.

## Output and exit status

| Option | Display |
|---|---|
| Default | Failed rules |
| `-v` | Failed and passed rules |
| `-vv` | Failed, passed, and skipped rules; acquisition diagnostics |
| `--details` | Wrapped explanations under displayed text rows |
| `--output json` / `--output yaml` | Structured results, including findings for displayed rules |

Verbosity also filters JSON/YAML rule lists. Use `-v` for passing path findings
or `-vv` for the complete rule list. `--details` affects text formatting only.

| Condition | Exit status |
|---|---|
| Acquisition, policy-load, or other run error | 1 |
| Rule failures with default `--fail-on none` | 0 after a completed run |
| Failed rules at/above `--fail-on error`, `warning`, or `info` | 1 after results are written |

The policy verdict is separate: failed `error` rules make it `fail`; warning
and info failures remain visible but do not change that verdict.

## Validation parameters

The lint CLI uses the current time. For repeatable historical evaluation,
set `time` in a [policy test suite](TESTING.md) or supply the API evaluation time.

`--purpose` accepts `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`,
`timeStamping`, `ocspSigning`, or a concrete EKU OID. Wildcards (`any`,
`anyExtendedKeyUsage`, `2.5.29.37.0`) are rejected. Private purposes fail closed
when end-entity Key Usage is present because no standard mapping is defined.
Omitting the purpose skips the conditional purpose rule.

`--peer-name` takes the reference identity an application expects of its peer
(RFC 9525). PCL reads an IP address as an iPAddress, a value with `@` as an
rfc822Name, and anything else as a dNSName; give internationalized names in
A-label (punycode) form. The path decision fails with `path.peer-name` unless
the target's subjectAltName presents every requested name. The subject common
name is not consulted, and a wildcard matches only as the whole leftmost label,
for exactly one label.

Certificate-policy processing accepts independent initial inputs:

```bash
pcl --policy policies/RFC5280.yaml --cert leaf.pem --issuer issuers/ \
  --trust-anchor root.pem --initial-policy-set 1.2.3.4,1.2.3.5 \
  --initial-explicit-policy --initial-policy-mapping-inhibit --initial-any-policy-inhibit
```

The initial set defaults to `anyPolicy`; OIDs can be repeated or comma-separated.
Supplying any `--initial-*` input overrides legacy `certificatePolicyValid`
operands. Without explicit inputs, that adapter retains its operand behavior.

## Public Suffix List

```bash
pcl update-data
pcl --policy policies/LOCAL-PROFILE.yaml --cert leaf.pem --psl-file data/public_suffix_list.dat
```

Default lookup uses `./data/public_suffix_list.dat` or `~/.pcl/data/`.
`--use-psl=false` disables loading. A missing list fails PSL/TLD-dependent
rules; an explicitly selected unreadable file is a run error. `inspect` and
`test` accept the same PSL options. `update-data --data-dir PATH` selects the
download destination.
