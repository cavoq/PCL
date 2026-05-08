#!/usr/bin/env bash
# Generate nameConstraints test chain:
#   nc-root.pem        — Root CA with nameConstraints permitting .example.test
#   nc-intermediate.pem — Intermediate signed by nc-root
#   nc-good-leaf.pem   — Leaf SAN nc-good.example.test (satisfies constraint)
#   nc-bad-leaf.pem    — Leaf SAN nc-bad.example.com  (violates constraint)
set -euo pipefail

OUT_DIR="certs"
mkdir -p "$OUT_DIR"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

CONF="$TMPDIR/nc.conf"

cat >"$CONF" <<'EOCONF'
[ req ]
default_bits        = 2048
default_md          = sha256
prompt              = no
distinguished_name  = dn_default

[ dn_default ]
CN = placeholder

[ v3_nc_root ]
basicConstraints        = critical, CA:TRUE
keyUsage                = critical, keyCertSign, cRLSign
subjectKeyIdentifier    = hash
nameConstraints         = critical, @nc_permitted

[ nc_permitted ]
permitted;DNS.1 = .example.test

[ v3_nc_inter ]
basicConstraints        = critical, CA:TRUE
keyUsage                = critical, keyCertSign
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always

[ v3_nc_leaf ]
basicConstraints        = CA:FALSE
keyUsage                = critical, digitalSignature
subjectAltName          = @leaf_san_good

[ v3_nc_bad_leaf ]
basicConstraints        = CA:FALSE
keyUsage                = critical, digitalSignature
subjectAltName          = @leaf_san_bad

[ leaf_san_good ]
DNS.1 = nc-good.example.test

[ leaf_san_bad ]
DNS.1 = nc-bad.example.com
EOCONF

echo "Generating nc-root..."
openssl genpkey -algorithm RSA -out "$TMPDIR/nc-root.key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -config "$CONF" -new -x509 -days 3650 -sha256 \
    -subj "/CN=NC Test Root CA" \
    -key "$TMPDIR/nc-root.key" -out "$OUT_DIR/nc-root.pem" \
    -extensions v3_nc_root

echo "Generating nc-intermediate..."
openssl genpkey -algorithm RSA -out "$TMPDIR/nc-inter.key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -config "$CONF" -new \
    -subj "/CN=NC Test Intermediate CA" \
    -key "$TMPDIR/nc-inter.key" -out "$TMPDIR/nc-inter.csr"
openssl x509 -req \
    -in "$TMPDIR/nc-inter.csr" \
    -CA "$OUT_DIR/nc-root.pem" -CAkey "$TMPDIR/nc-root.key" \
    -CAcreateserial -out "$OUT_DIR/nc-intermediate.pem" \
    -days 1825 -sha256 \
    -extfile "$CONF" -extensions v3_nc_inter

echo "Generating nc-good-leaf..."
openssl genpkey -algorithm RSA -out "$TMPDIR/nc-good.key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -config "$CONF" -new \
    -subj "/CN=nc-good.example.test" \
    -key "$TMPDIR/nc-good.key" -out "$TMPDIR/nc-good.csr"
openssl x509 -req \
    -in "$TMPDIR/nc-good.csr" \
    -CA "$OUT_DIR/nc-intermediate.pem" -CAkey "$TMPDIR/nc-inter.key" \
    -CAcreateserial -out "$OUT_DIR/nc-good-leaf.pem" \
    -days 825 -sha256 \
    -extfile "$CONF" -extensions v3_nc_leaf

echo "Generating nc-bad-leaf..."
openssl genpkey -algorithm RSA -out "$TMPDIR/nc-bad.key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -config "$CONF" -new \
    -subj "/CN=nc-bad.example.com" \
    -key "$TMPDIR/nc-bad.key" -out "$TMPDIR/nc-bad.csr"
openssl x509 -req \
    -in "$TMPDIR/nc-bad.csr" \
    -CA "$OUT_DIR/nc-intermediate.pem" -CAkey "$TMPDIR/nc-inter.key" \
    -CAcreateserial -out "$OUT_DIR/nc-bad-leaf.pem" \
    -days 825 -sha256 \
    -extfile "$CONF" -extensions v3_nc_bad_leaf

echo "Done. Certificates:"
openssl x509 -noout -text -in "$OUT_DIR/nc-root.pem" | grep -A4 "Name Constraints"
openssl x509 -noout -subject -in "$OUT_DIR/nc-good-leaf.pem"
openssl x509 -noout -text -in "$OUT_DIR/nc-good-leaf.pem" | grep -A2 "Subject Alternative Name"
openssl x509 -noout -subject -in "$OUT_DIR/nc-bad-leaf.pem"
openssl x509 -noout -text -in "$OUT_DIR/nc-bad-leaf.pem" | grep -A2 "Subject Alternative Name"
