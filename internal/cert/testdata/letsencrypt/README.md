# Let's Encrypt AIA fixtures (cert package)

Pinned for `ClimbChain` / `FetchParentViaCAIssuers` integration tests. Refresh:

```bash
curl -sSL http://letsencrypt.org/certs/2024/e9.der -o e9.der
curl -sS http://x2.i.lencr.org/ -o isrg-root-x2.der
```

`e9.der` is also kept under `internal/crl/testdata/letsencrypt/`; tests read either path.
