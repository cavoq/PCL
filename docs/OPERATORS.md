# ➕ Operators

[Documentation](POLICY_WRITING_GUIDE.md) · [Policy format](POLICY_FORMAT.md) · [Node model](NODE_MODEL.md)

Operands below are YAML sequences unless a mapping is shown. A single scalar
is also accepted where one operand is required. `pcl schema` exposes the
installed registry’s complete operand contracts; execution also validates
semantic constraints such as OIDs, regexes, and CIDRs.

## Presence Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `present` | None | Returns true if target exists in the tree |
| `absent` | None | Returns true if target does NOT exist in the tree |
| `isEmpty` | None | Returns true if target value is empty |
| `notEmpty` | None | Returns true if target value is NOT empty |
| `isNull` | None | Returns true if node exists with `null=true` child (explicit NULL encoding) |

## Equality Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `eq` | [value] | Returns true if target equals operand |
| `neq` | [value] | Returns true if target does NOT equal operand; an absent target is not equal |
| `in` | [value1, value2, ...] | Returns true if target is in the list |
| `notIn` | [value1, value2, ...] | Returns true if target is NOT in the list; an absent target is in no list |
| `contains` | [value, ...] | Target contains at least one specified value |
| `matches` | [fieldPath] | Returns true if target equals the value at another field path |

## Comparison Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `gte` | [number] | Returns true if target >= operand (numeric comparison) |
| `gt` | [number] | Returns true if target > operand |
| `lte` | [number] | Returns true if target <= operand |
| `lt` | [number] | Returns true if target < operand |
| `positive` | None | Returns true if target is a positive number |
| `odd` | None | Returns true if target is an odd number |
| `multipleOf` | [divisor] | Returns true if the target integer is a multiple of the positive integer divisor |

## String Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `regex` | [pattern] | Returns true if target matches regex pattern |
| `notRegex` | [pattern] | Returns true if target does NOT match regex pattern |
| `minLength` | [count] | Returns true if node has at least N children/values |
| `maxLength` | [count] | Returns true if node has at most N children/values |

## Date Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `before` | [date] (optional) | Returns true if target date is before the specified date, or current time if omitted |
| `after` | [date] (optional) | Returns true if target date is after the specified date, or current time if omitted |
| `onOrBefore` | [date] (optional) | Returns true if target date is before or equal to the specified date, or current time if omitted |
| `onOrAfter` | [date] (optional) | Returns true if target date is after or equal to the specified date, or current time if omitted |
| `validityOrderCorrect` | None | Returns true if notBefore < notAfter |
| `validityDays` | [minDays, maxDays] | Returns true if the validity period is within the inclusive day range |
| `dateDiff` | {start, end?, minDays?, maxDays?, minHours?, maxHours?, maxMonths?, inclusive?} | Returns true if the date difference is within every supplied bound; `inclusive: true` counts the end second, as an RFC 5280 validity period does |

## Extension Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `isCritical` | None | Returns true if the extension is marked critical |
| `notCritical` | None | Returns true if the extension is NOT marked critical |
| `noUnknownCriticalExtensions` | None | Rejects duplicate extension OIDs; otherwise accepts a critical extension only when registered as processable at its exact signed-object location and its concrete node has neither a `malformed` nor `unprocessed` marker |

## EKU Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `ekuContains` | [ekuName] | Returns true if extKeyUsage contains the specified EKU |
| `ekuNotContains` | [ekuName] | Returns true if extKeyUsage does NOT contain the specified EKU |
| `ekuServerAuth` | None | Returns true if extKeyUsage contains serverAuth |
| `ekuClientAuth` | None | Returns true if extKeyUsage contains clientAuth |

## Certificate Profile Operators

These operators take no operands.

| Operator | Description |
|----------|-------------|
| `applicationPurposeValid` | Applies a concrete `--purpose` to EKU and compatible end-entity Key Usage; rejects anyExtendedKeyUsage requests and fails closed for private purposes when end-entity Key Usage is present |
| `anyExtendedKeyUsageNotCritical` | Enforces non-critical anyExtendedKeyUsage |
| `basicConstraintsDependenciesValid` | Requires pathLenConstraint to accompany CA Basic Constraints and keyCertSign |
| `keyUsageDependenciesValid` | Enforces the keyCertSign => CA dependency; RFC 5280 leaves encipherOnly/decipherOnly meaning undefined when keyAgreement is absent rather than forbidding the bit combination |
| `nameConstraintsDependenciesValid` | Restricts Name Constraints to CA certificates |
| `nameConstraintsDistancesValid` | Requires GeneralSubtree minimum zero/default and absent maximum |
| `crlDistributionPointsDependenciesValid` | Checks certificate-profile CRLDP dependencies without applying CRL scope |
| `policyMappingsDependenciesValid` | Restricts mappings to CAs and rejects anyPolicy on either side |
| `policyMappingsIssuerPoliciesPresent` | Requires issuerDomainPolicy values to occur in certificatePolicies |
| `policyConstraintsDependenciesValid` | Restricts Policy Constraints to CA certificates |
| `inhibitAnyPolicyDependenciesValid` | Restricts inhibitAnyPolicy to CA certificates |

## Certificate Chain Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `signatureValid` | None | Returns true if certificate signature is valid |
| `signatureAlgorithmMatchesTBS` | None | Returns true if signatureAlgorithm matches tbsSignatureAlgorithm |
| `issuedBy` | None | Returns true if certificate's issuer DN matches issuer's subject DN |
| `akiMatchesSki` | None | Returns true if AKI matches issuer's SKI |
| `pathLenValid` | None | Counts non-self-issued intermediates below the current CA in the supplied leaf-to-root chain |
| `pathValid` | None | Aggregate decision of the explicit-anchor path engine for the target certificate; the rule result carries its structured findings |
| `serialNumberUnique` | None | Detects a duplicate issuer/serial pair within the supplied chain; it cannot prove CA-wide uniqueness |

## CRL Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `crlValid` | None | Returns true if CRL has a present, ordered `nextUpdate` and the evaluation time is within its inclusive window |
| `crlNotExpired` | None | Compatibility deadline check; rejects missing or elapsed `nextUpdate` but does not check `thisUpdate` |
| `crlSignedBy` | None | Returns true only when the CRL signature verifies against a resolved issuer certificate |
| `notRevoked` | None | Returns true only when an applicable CRL exists and does not list the certificate; inconclusive without an applicable CRL |
| `notRevokedByAvailableEvidence` | None | Combines prepared CRL and OCSP decisions; Revoked wins, otherwise at least one mechanism must establish Good; inconclusive without any applicable CRL or OCSP response |

## OCSP Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `ocspValid` | None | True when at least one response is certificate/issuer-bound, current, and authenticated |
| `notRevokedOCSP` | None | True only when accepted aggregate status is Good; an Unknown status fails |
| `ocspGood` | None | True when at least one accepted response explicitly reports Good |

The revocation operators decide `inconclusive` when no supplied CRL or OCSP
response applies to the certificate: an OCSP response must name the
certificate's serial and a known issuer, a CRL must cover the certificate's
issuer and distribution point. Missing evidence leaves compliance
unestablished rather than proving a violation. Applicable evidence that is
stale, unauthenticated, from an unauthorized signer, or Unknown still fails.

## Composite Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `every` | [{path, operator, operands, skipMissing}] | Iterates array elements and checks each |
| `anyOf` | [{path?, operator, operands?}, ...] (two or more) | True when at least one condition holds on the target; a condition whose path does not resolve holds only for `absent`, `neq` and other operators that decide absence |

## Path Validation Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `nameConstraintsValid` | None | Applies DNS, email, URI, IP and directoryName constraints across the supplied chain; directory names are compared by the RFC 5280 Section 7.1 rules. A dNSName subtree other than an empty one or a preferred-syntax domain name (for example `.example.com`) is malformed and fails. A certificate whose names times the issuers' subtrees exceed 250,000 comparisons fails without being checked. A wildcard SAN dNSName violates an excluded subtree it matches (`*.example.com` and `bar.example.com`). A constraint on another name form (otherName, x400Address, ediPartyName, registeredID) fails a certificate only when its subjectAltName presents a name of that form |
| `certificatePolicyValid` | [oid, ...] or none | RFC 5280 6.1 policy processing (mappings, requireExplicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy) from the trust anchor to the certificate. The `--initial-*` inputs take precedence when supplied. Otherwise operands preserve the legacy initial-policy-set plus explicit-policy behavior, and no operands select RFC defaults. The self-signed chain top is the trust anchor and is not processed. The explicit path engine also performs policy processing; no standalone `RFC5280.yaml` rule invokes this adapter |

## Component Operators (Multi-Valued Fields)

| Operator | Operands | Description |
|----------|----------|-------------|
| `componentMaxLength` | [length, separator?] | Each component has at most N characters; separator defaults to `.` |
| `componentMinLength` | [length, separator?] | Each component has at least N characters; separator defaults to `.` |
| `componentRegex` | [pattern, separator?] | Each component of one delimited string matches regex; separator defaults to `.` |
| `componentNotRegex` | [pattern, separator?] | Each component does NOT match regex; separator defaults to `.` |
| `anyComponentMatches` | [pattern] | ANY component matches regex |
| `noComponentMatches` | [pattern] | NO component matches regex |

## CIDR Operators (IP Address)

| Operator | Operands | Description |
|----------|----------|-------------|
| `componentInCIDR` | [cidr1, cidr2, ...] | At least one child IP, or the scalar IP, is in a CIDR range |
| `componentNotInCIDR` | [cidr1, cidr2, ...] | Every child IP, or the scalar IP, is outside all CIDR ranges |

## PSL/TLD Operators (Domain Validation)

| Operator | Operands | Description |
|----------|----------|-------------|
| `tldRegistered` | None | TLD is in IANA Root Zone Database |
| `tldNotRegistered` | None | TLD is NOT registered |
| `isPublicSuffix` | None | Domain is a public suffix |
| `isNotPublicSuffix` | None | Domain is NOT a public suffix |
| `componentTLDNotRegistered` | None | At least one domain's TLD is not registered |
| `componentIsPublicSuffix` | None | Any domain is a public suffix |
| `componentNotPublicSuffix` | None | All domains are NOT public suffixes |

## ASN.1 String Type Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `isIA5String` | None | Field uses IA5String encoding (ASCII) |
| `isPrintableString` | None | Field uses PrintableString encoding |
| `isUTF8String` | None | Field uses UTF8String encoding |
| `validIA5String` | None | String contains only valid IA5String chars (ASCII, 0-127) |
| `validPrintableString` | None | String contains only valid PrintableString chars (A-Z, a-z, 0-9, + specific specials) |
| `utf8NoBom` | None | UTF-8 string has no BOM |
| `containsBom` | None | String contains BOM |

## Unique Value Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `uniqueValues` | None | All values in array are unique |
| `uniqueChildren` | None | All children have unique content |

## DER Encoding Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `derEqualsHex` | [hexString] | DER encoding matches expected hex bytes |

## Subject DN Operators

| Operator | Operands | Description |
|----------|----------|-------------|
| `noDuplicateAttributes` | None | CABF single-instance subject attribute OIDs do not repeat |

## Alternatives

`anyOf` states requirements with alternatives, such as a key usage that
must contain one of two bits, or an extension that is either absent or
restricted. Each condition has an optional `path` below the target, an
`operator` and its `operands`; on a path that does not resolve, only
operators that decide absence, such as `absent`, can hold:

```yaml
- id: pss-end-entity-key-usage
  target: certificate.extensions.keyUsage
  operator: anyOf
  operands:
    - {path: digitalSignature, operator: eq, operands: [true]}
    - {path: nonRepudiation, operator: eq, operands: [true]}
```

`oneOf` uses the same condition syntax as `anyOf`, but exactly one condition
must hold. It counts successful conditions, not distinct nodes; overlapping
or duplicate predicates can therefore make it fail. Missing paths follow
the same absence-aware behavior as `anyOf`. For example:

```yaml
- id: exactly-one-certificate-type
  target: certificate.extensions.certificatePolicies
  operator: oneOf
  operands:
    - {path: dvPolicy, operator: present}
    - {path: ovPolicy, operator: present}
    - {path: ivPolicy, operator: present}
    - {path: evPolicy, operator: present}
```

## HTTP URL syntax

`httpURL` takes no operands and checks a scalar string for an absolute ASCII
HTTP or HTTPS URL with a nonempty host. It rejects whitespace, invalid URL
escapes, relative/opaque references and other schemes; schemes are
case-insensitive. It does not fetch the URL, check availability, or verify
that the resource belongs to the CA. Compose it with `every` for collections.

## Collection traversal

`every` accepts a mapping with `path` (relative to each element, supports
`*`), `operator`, `operands`, and `skipMissing` (default false). Numeric
children are visited in integer order; aliases and metadata are excluded.
Use it with scalar operators to cover every DN or GeneralName occurrence:

```yaml
- id: san-dns-ia5
  target: certificate.subjectAltName.dNSName
  operator: every
  operands:
    operator: validIA5String
  severity: error
  when:
    target: certificate.subjectAltName.dNSName
    operator: present
```

## Decision boundaries

| Check | Boundary |
|---|---|
| Profile dependency operators | Certificate semantics owned by `internal/cert` |
| `pathLenValid`, `nameConstraintsValid` | Checks over the supplied ordered chain; do not establish trust |
| `certificatePolicyValid` | Compatibility adapter; `--initial-*` inputs override legacy operands |
| `pathValid` | Full aggregate decision from the explicit-anchor path engine, with its findings |
| CRL / OCSP operators | Consume prepared evidence; no network access during evaluation |
| PSL/TLD operators | Require a loaded Public Suffix List; missing data fails the check |

Key Usage bits and ASN.1 time metadata are ordinary nodes: use `eq`, `when`,
and `certType` rather than dedicated operators. Presence and critical-extension
contracts are described in the [node model](NODE_MODEL.md#critical-extension-processing).
