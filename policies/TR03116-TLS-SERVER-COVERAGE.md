# TR-03116 TLS Server Certificate Policy Coverage

`TR03116-TLS-SERVER.yaml` implements the X.509 checklist in
TR-03116-TS v1.1, Section 6.1.1, Table 24. The algorithm values are from
TR-03116-4, edition 2025, Sections 2.2.1.2 and 6.1.2-6.1.4.

The policy is intentionally a TLS **server** profile. Run it over the complete
leaf-to-root chain. Its static 2025 algorithm profile permits DSA through 2029
and rejects the RSASSA-PKCS1-v1_5 transition, whose permitted period ended in
2025.

| Check | Coverage | Implementation / required evidence |
|---|---|---|
| TLS_CERT_01 | Automated | Restricts server keys to RSA/ECDSA, chain keys to RSA/DSA/ECDSA, RSA/DSA to at least 3072 bits, and ECDSA to the named curves in TR-03116-4 Table 30. |
| TLS_CERT_02 | Automated | Permits ECDSA with SHA-256 or stronger, DSA with SHA-256, or RSASSA-PSS with SHA-256 or stronger. It also verifies each certificate signature. Use `RFC4055.yaml` alongside this policy for the full PSS parameter profile. |
| TLS_CERT_03 | Automated for CN and SAN dNSName | Rejects `*` in every Subject commonName and SAN dNSName. Other GeneralName forms have no DNS wildcard semantics. |
| TLS_CERT_04 | Partly automated | Requires CRL Distribution Points or OCSP in AIA. PCL can retrieve and validate evidence with `--auto-validate`; operational URL availability is an external service check and cannot be proven from certificate syntax alone. |
| TLS_CERT_05 | Automated with evidence | Fails closed unless an applicable current CRL or authenticated OCSP `Good` result is supplied; an accepted `Revoked` result from either mechanism takes precedence. |
| TLS_CERT_06 | Automated | Requires critical Key Usage on the leaf with `digitalSignature=true`, `keyCertSign=false`, and `cRLSign=false`. |
| TLS_CERT_07 | Automated | Requires critical Key Usage on CA certificates with `keyCertSign=true` and `cRLSign=true`. |
| TLS_CERT_08 | Automated | Requires `id-kp-serverAuth` EKU on the leaf. |
| TLS_CERT_09 | External input required | A standalone certificate does not identify the intended service names. `--cert-url https://host` performs TLS hostname verification while retrieving the chain; for local files, compare all declared service names separately. |
| TLS_CERT_10 | Automated except application-specific smallness | Requires critical CA Basic Constraints, `cA=true`, an explicit `pathLenConstraint`, and verifies it against the supplied chain. Whether the value is “reasonably small” is application-specific and remains an auditor decision. |
| TLS_CERT_11 | Automated | Enforces 3 years for the leaf, 5 years for intermediates, and 6 years for roots using calendar-month bounds. |
| TLS_CERT_12 | Automated | Checks `notBefore <= now <= notAfter`. |

Example with automatic chain and revocation acquisition:

```bash
pcl \
  --policy policies/TR03116-TLS-SERVER.yaml \
  --policy policies/RFC4055.yaml \
  --cert server.pem \
  --issuer issuer-chain.pem \
  --auto-validate
```

For a live public endpoint, `--cert-url https://example.test` additionally
binds acquisition to the requested hostname. A TR-03116 assessment still needs
an auditor to confirm that every domain declared for the application was
tested and that revocation services are operational.
