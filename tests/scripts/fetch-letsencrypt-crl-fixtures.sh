#!/usr/bin/env bash
# Refresh pinned Let's Encrypt CRL/CA fixtures (official HTTP endpoints).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="${ROOT}/internal/crl/testdata/letsencrypt"
mkdir -p "$DEST"

curl -sS "http://crl.root-x1.letsencrypt.org/" -o "${DEST}/isrg-root-x1.crl"
curl -sS "http://x2.c.lencr.org/" -o "${DEST}/isrg-root-x2.crl"
curl -sSL "http://letsencrypt.org/certs/isrgrootx1.der" -o "${DEST}/isrgrootx1.der"
curl -sSL "http://letsencrypt.org/certs/2024/e9.der" -o "${DEST}/e9.der"
curl -sS "http://x2.i.lencr.org/" -o "${DEST}/isrg-root-x2.der"

CERT_DEST="${ROOT}/internal/cert/testdata/letsencrypt"
mkdir -p "$CERT_DEST"
cp "${DEST}/e9.der" "${CERT_DEST}/e9.der"
cp "${DEST}/isrg-root-x2.der" "${CERT_DEST}/isrg-root-x2.der"

openssl crl -in "${DEST}/isrg-root-x1.crl" -inform DER -noout -issuer -lastupdate -nextupdate
echo "Updated fixtures in ${DEST} and ${CERT_DEST}"
