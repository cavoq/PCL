# Let's Encrypt official fixtures

Pinned from [Let's Encrypt certificates](https://letsencrypt.org/certificates/) CDNs (HTTP). Refresh:

```bash
# Or: tests/scripts/fetch-letsencrypt-crl-fixtures.sh
curl -sS http://crl.root-x1.letsencrypt.org/ -o isrg-root-x1.crl
curl -sS http://x2.c.lencr.org/ -o isrg-root-x2.crl
curl -sSL http://letsencrypt.org/certs/isrgrootx1.der -o isrgrootx1.der
curl -sSL http://letsencrypt.org/certs/2024/e9.der -o e9.der
curl -sS http://x2.i.lencr.org/ -o isrg-root-x2.der
```

| File | Source | Role |
|------|--------|------|
| `isrg-root-x1.crl` | `http://crl.root-x1.letsencrypt.org/` | ISRG Root X1 CRL (~1 year `nextUpdate`) |
| `isrg-root-x2.crl` | `http://x2.c.lencr.org/` | ISRG Root X2 CRL |
| `isrgrootx1.der` | `http://letsencrypt.org/certs/isrgrootx1.der` | Root CA for signature checks |
| `e9.der` | `http://letsencrypt.org/certs/2024/e9.der` | E9 intermediate for AIA / ClimbChain tests |
| `isrg-root-x2.der` | `http://x2.i.lencr.org/` | Parent cert in PKCS#7 ClimbChain fixture |

Intermediate subscriber CRLs (`e9.c.lencr.org`, `r14.c.lencr.org`) often 404 outside rotation; set `PCL_LE_SUBSCRIBER_CRL_URL` when a live URL is available, or use `testdata/test.crl` for ~30-day subscriber windows.
