# 🏛️ CA/B Forum TLS Baseline Requirements Coverage

[Documentation](../docs/POLICY_WRITING_GUIDE.md) · [Policy](CABF-TLS-BR.yaml)

## Scope

Certificate-profile conformance against the Baseline Requirements for the
Issuance and Management of Publicly-Trusted TLS Server Certificates, version
2.3.1 (2026-10-04): the Subscriber Certificate profile (7.1.2.7), partial
root/subordinate CA and delegated OCSP responder profiles, and selected CRL
and OCSP response requirements. Shared key, algorithm and name-encoding
rules also apply to extracted OCSP signing certificates. This is an
artifact-level lint pack, not a complete BR compliance assessment: domain
and identity validation (3.2), CA operations, audits, Certificate
Transparency and CAA checking need evidence beyond these inputs.

Load the pack together with `rfc5280`: the Baseline Requirements apply
RFC 5280 except where they say otherwise, and this pack states only what
they add. Use `rfc6960` for the underlying OCSP requirements. Requirement
levels follow the BR text: MUST and MUST NOT are errors, SHOULD, SHOULD NOT
and NOT RECOMMENDED are warnings. Combining packs does not override an RFC
rule with a BR exception; see the conflicts below.

CA and responder profile rules apply from 2023-09-15 by certificate
notBefore, and the CRL profile additions from 2024-03-15 by thisUpdate.
These cutoffs avoid retroactively imposing the new profiles; they do not
implement every historical BR edition. Shared key, algorithm and name
rules describe the current requirements, subject to the historical limits
below.

## Requirement matrix

| Requirement | Status | Rules | Evidence |
|---|---|---|---|
| Key types and sizes (6.1.5), RSA exponent (6.1.6) | Covered | `br-rsa-key-size`, `br-rsa-key-size-multiple-of-8`, `br-rsa-exponent-odd`, `br-rsa-exponent-min`, `br-rsa-exponent-range` (SHOULD) | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| SubjectPublicKeyInfo encodings (7.1.3.1) | Covered | `br-spki-algorithm-encoding`: byte-for-byte rsaEncryption/NULL or P-256/P-384/P-521 | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Signature AlgorithmIdentifier encodings (7.1.3.2) | Covered | `br-signature-algorithm-encoding`: the nine permitted encodings | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Name encoding (7.1.4.1, 7.1.4.2) | Partial | `br-name-one-attribute-per-rdn`, `br-name-no-duplicate-attributes`, `br-subject-*-encoding`, `br-subject-*-length` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Subscriber Validity Period by issuance date (6.3.2) | Covered | `br-subscriber-validity-max-{398,200,100,47}-days` (MUST), `-{397,199,99,46}-days` (SHOULD), inclusive of notAfter | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Subscriber version (7.1.2.7) | Covered | `br-subscriber-version-3` | Conforming chain |
| Authority Information Access (7.1.2.7.7) | Covered | `br-subscriber-aia-present` (SHOULD), `br-subscriber-aia-access-methods`, `br-subscriber-aia-http-uri`, `br-subscriber-aia-ca-issuers` (SHOULD) | Conforming chain |
| Subscriber Certificate Policies (7.1.2.7.9) | Covered for observable content | Presence, criticality, exactly one DV/OV/IV/EV identifier, no anyPolicy, recommended first position, strict DER and CPS-only qualifiers with HTTP(S) URLs | [Policy-content suite](../tests/policy-suites/cabf-policies.test.yaml) |
| Shared Certificate Policies content (7.1.2.2.6, 7.1.2.3.2, 7.1.2.8.8, 7.1.2.10.5) | Partial | `br-certificate-policies-*`: strict parsing including IA5String CPS encoding, optional but discouraged qualifiers, CPS-only qualifier IDs and HTTP(S) URL syntax; `br-ca-any-policy-alone`; recommended first reserved identifier on policy-restricted TLS subordinates | [Policy-content suite](../tests/policy-suites/cabf-policies.test.yaml): subscriber, CA, root, responder and issuance-cutoff fixtures |
| Extended Key Usage (7.1.2.7.10) | Covered | `br-subscriber-eku-present`, `-not-critical`, `-server-auth`, `-prohibited`, `-only-tls` (NOT RECOMMENDED) | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Subject Alternative Name (7.1.2.7.12) | Covered | `br-subscriber-san-*`; dNSName root label, wildcard position, LDH and reserved LDH labels, Internal Names, reverse zones (from 2026-03-15); Reserved IP Addresses | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Wildcard Domain Validation (3.2.2.6) | Partial | `br-subscriber-wildcard-not-public-suffix`: the domain a wildcard covers is not a public suffix in the PSL's ICANN section (the PRIVATE section is not consulted, as the BR recommends) | [Wildcard suite](../tests/policy-suites/cabf-wildcard.test.yaml) |
| Key Usage (7.1.2.7.11) | Covered | `br-subscriber-key-usage-*`, `br-subscriber-rsa-key-usage*`, `br-subscriber-ecc-key-usage*` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Basic Constraints, Name Constraints, SKI (7.1.2.7.6, 7.1.2.7.8) | Covered | `br-subscriber-basic-constraints-critical`, `br-subscriber-no-name-constraints`, `br-subscriber-no-subject-key-identifier` (NOT RECOMMENDED); cA and pathLenConstraint by `rfc5280` | Conforming chain |
| CRL Distribution Points (7.1.2.11.2) | Covered | `br-subscriber-crl-distribution-points-required*` (short-lived 10 days, 7 days from 2026-03-15), `br-crl-distribution-points-*` | Conforming chain |
| Authority Key Identifier (7.1.2.11.1, 7.1.2.1.3) | Covered for observable content | `br-aki-present` (subscriber, subordinate), `br-aki-not-critical` (every certificate); from 2023-09-15 `br-aki-well-formed`, `br-aki-key-identifier`, `br-aki-no-authority-cert-issuer`, `br-aki-no-authority-cert-serial-number`; presence for roots (recommended) and responders in their profiles | [AKI suite](../tests/policy-suites/cabf-aki.test.yaml) |
| Subject by certificate type (7.1.2.7.2–7.1.2.7.4) | Covered for DV, OV, IV | `br-subscriber-dv-subject-attributes`, `br-subscriber-ov-*`, `br-subscriber-iv-*`, `br-subscriber-subject-not-metadata` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Common Name (7.1.4.3) | Partial | `br-subscriber-common-name-not-recommended`, `br-subscriber-common-name-from-san` | [CA/B suite](../tests/policy-suites/cabf.test.yaml) |
| Common CA fields (7.1.2.10) | Partial | `br-ca-version-3`, `br-ca-key-usage-*`, `br-ca-aia-*`, `br-ca-name-constraints-critical` (SHOULD); required C/O/CN checked for roots only because cross-certificates may retain historical subjects | Conforming CA chain, bad subordinate and cross-subject vectors |
| Root CA profile (7.1.2.1) | Partial | `br-root-validity` (2922–9132 days), `br-root-no-eku`, `br-root-no-organizational-unit`; recommended AKI, absence of policies, path length and CRLDP | Conforming and bad roots |
| Subordinate CA profiles (7.1.2.2–7.1.2.6) | Partial | CRLDP presence, recommended AIA/EKU, EKU criticality, anyEKU alone; serverAuth selects shared TLS EKU/policy checks; no new Precertificate Signing CAs from 2026-03-15 | Bad subordinate, cross-subject and non-TLS private-policy vectors |
| OCSP responder profile (7.1.2.8) | Partial | `br-ocsp-responder-*`: version, AKI presence, sole OCSPSigning EKU, nocheck presence/DER/criticality, KU, BC DER/criticality, no SAN/NC/CRLDP, AIA methods/URLs, required C/O/CN and extension recommendations | Conforming responder, bad responder and weak responder key |
| CRL signature encoding (7.1.3.2) | Covered | `br-crl-signature-algorithm-encoding` | Conforming CRL |
| CRL validity (7.2) | Partial | `br-crl-next-update-12-months`, `br-crl-subscriber-next-update-10-days` when IDP asserts onlyContainsUserCerts | Conforming CRL, 11-day subscriber CRL and 400-day root CRL |
| CRL Authority Key Identifier (7.2.2) | Covered for observable content | `br-crl-aki-present`, `-not-critical`, `-well-formed`, `-key-identifier`, `-no-authority-cert-issuer`, `-no-authority-cert-serial-number` from 2024-03-15 | [AKI suite](../tests/policy-suites/cabf-aki.test.yaml) |
| CRL reasons and IDP (7.2.2) | Partial | Allowed reason codes, no indirect/attribute-certificate CRLs, named partitions, URI-only fullName, recommendation against reason partitions | Bad CRLs and an explicit unspecified reason requiring certificate context |
| OCSP response profile (7.1.3.2, 7.3) | Partial | `br-ocsp-signature-algorithm-encoding`, `br-ocsp-no-reason-code-extension`, `br-ocsp-revocation-reason` | SHA-1 response, forbidden singleExtension and certificateHold vectors |

## Limits

| Area | Limit |
|---|---|
| Subordinate profile selection | PCL's `intermediate` role does not identify cross-certification, affiliation or the selected constrained/unconstrained profile. EKU presence is checked at the common SHOULD level, not the MUST required for some profiles. Strict TLS-only naming, required C/O/CN, technical constraints and profile-specific EKU prohibitions need explicit profile context. An OU is therefore a warning, not a blanket failure. The pack does not prove eligibility for a cross-signing or affiliation exception |
| Historical cross-certificates | Cross-certificates may retain compliant historical subject encodings. Shared current name-encoding checks do not implement that exception; findings require review against the original certificate and its issuance-era requirements |
| Precertificates | The precertificate content/poison/SCT profile (7.1.2.9) is not implemented; only the Precertificate Signing CA EKU and issuance cutoff are checked |
| Wildcards over public suffixes | A registry or gTLD registrant that proves control of the whole namespace may receive such a wildcard (3.2.2.6); the pack cannot see that evidence and reports an error. The verdict depends on the loaded PSL version |
| Duplicate CRL serial numbers | Neither BR 2.3.1 nor RFC 5280 forbids listing a serial number twice; the prohibition is proposed in [servercert#589](https://github.com/cabforum/servercert/issues/589). Revocation status already treats a duplicated entry for the checked certificate as invalid |
| Extended Validation | EV subjects follow the EV Guidelines, which this pack does not implement |
| Issuance date | Certificates do not record signing time; notBefore is a proxy. The CA profiles normally allow one day's backdating and the subscriber profile 48 hours. Cross-certificates may use an older certificate's notBefore, so a new cross-certificate can fall outside a profile's effective window |
| Certificate Policies | Exactly-one cardinality is enforced for subscribers from 2023-09-15. It is not imposed on every CA: some cross-certificates may carry multiple reserved identifiers, and constrained non-TLS CAs may use private identifiers. CA profile, affiliation and direct/transitive subscriber issuance must be established before stricter cardinality/identifier checks can apply. Private identifiers' CP/CPS documentation, the truth of the asserted validation type, and CPS URL ownership/content are external evidence, not established by syntax checks |
| ECDSA signature hash | Matching the hash to the signing key's curve (7.1.3.2.2) needs the issuer's key and is not checked |
| Historical signature exceptions | Shared current signature allowlists do not implement the SHA-1 exception for reissued CA certificates before 2026-09-15 |
| Authority Key Identifier | That keyIdentifier equals the issuer's subjectKeyIdentifier (7.1.2.11.1) needs the issuer certificate; the pack leaves it to rfc5280 `aki-matches-ski`, which is inconclusive without the issuer and passes when the issuer has no SKI |
| Serial numbers | 64 bits of CSPRNG output and non-sequential issuance are not observable in one certificate |
| Names | RDN order (7.1.4.2), byte-identical CA subject encodings across certificates (7.1.4.1), the IPv4/IPv6 text forms of a commonName, and Punycode validity of P-Labels are not checked |
| Internal Names | Top-level domains come from the Public Suffix List ICANN section, embedded or loaded with `--psl-file` |
| Reserved IP Addresses | The IANA special-purpose registries as of October 2026 |
| SCT list | The content of the Signed Certificate Timestamp List (7.1.2.11.3) is not checked |
| CRL profile | The CRL parser accepts only v2 CRLs (7.2.1); time encodings are checked by rfc5280. The 10-day limit cannot be selected reliably without subscriber scope; an IDP-less CRL only receives the 12-month check. The pack cannot establish missing IDP on an otherwise unmarked partition, CRL number progression, issuer-name byte identity, publication frequency, entry completeness or matching certificate/IDP URIs |
| Revocation reasons | Revoked certificates and their issuance histories are not available per entry. Explicit unspecified (0) remains allowed because it is required in some CA entries; omission/presence requirements and legacy non-BR certificateHold exceptions need this context. Applying the pack to mixed BR/non-BR CRLs can flag legacy non-BR entries |
| OCSP profile | Subscriber response validity bounds and the required explicit revocationReason for revoked CAs need the checked certificate's role and lossless field-presence information, not currently exposed to these rules. Refresh cadence and service availability require operational evidence |
| RFC 5280 conflicts | `rfc5280` recommends SKI in end-entity certificates; the BR discourage it in subscribers, so the packs warn in opposite directions. RFC 5280 requires critical nameConstraints while the BR allow a noncritical extension for legacy clients; the RFC pack still reports an error for that BR exception |
