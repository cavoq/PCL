#!/usr/bin/env bash
# Generate Root -> Intermediate -> Leaf certificates
# Only saves certs, keys are removed (securely if shred available)
set -euo pipefail

# ---------------------------
# Defaults
# ---------------------------
CONF="openssl-bsi.conf"
OUT_DIR="certs"
KEEP_KEYS=0
DAYS_ROOT=2190
DAYS_INTER=1825
DAYS_LEAF=825

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --conf FILE        OpenSSL config file (default: $CONF)
  --out-dir DIR      Directory to save certs (default: $OUT_DIR)
  --keep-keys        Keep private keys (default: keys are removed)
  --days-root N      Root certificate validity (default: $DAYS_ROOT)
  --days-inter N     Intermediate validity (default: $DAYS_INTER)
  --days-leaf N      Leaf validity (default: $DAYS_LEAF)
  -h, --help         Show this help
EOF
    exit 1
}

# ---------------------------
# Parse args
# ---------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --conf) CONF="$2"; shift 2;;
        --out-dir) OUT_DIR="$2"; shift 2;;
        --keep-keys) KEEP_KEYS=1; shift;;
        --days-root) DAYS_ROOT="$2"; shift 2;;
        --days-inter) DAYS_INTER="$2"; shift 2;;
        --days-leaf) DAYS_LEAF="$2"; shift 2;;
        -h|--help) usage;;
        *) echo "Unknown option: $1"; usage;;
    esac
done

[ -f "$CONF" ] || { echo "Config file $CONF not found"; exit 1; }
mkdir -p "$OUT_DIR"

# ---------------------------
# Temp workspace
# ---------------------------
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

DETECT_SHRED=0
command -v shred >/dev/null 2>&1 && DETECT_SHRED=1

# ---------------------------
# Helper functions
# ---------------------------
gen_key() {
    local keyfile="$1" bits="${2:-2048}"
    echo " -> generating key $keyfile (${bits} bits)"
    openssl genpkey -algorithm RSA -out "$keyfile" -pkeyopt rsa_keygen_bits:"$bits"
}

gen_self_signed() {
    local key="$1" cert="$2" subj="$3" days="$4" ext="$5"
    echo " -> creating self-signed cert $cert"
    openssl req -config "$CONF" -new -x509 -days "$days" -sha256 \
        -subj "$subj" -key "$key" -out "$cert" -extensions "$ext" -config "$CONF"
}

gen_csr() {
    local key="$1" csr="$2" subj="$3"
    echo " -> creating CSR $csr"
    openssl req -config "$CONF" -new -key "$key" -subj "$subj" -out "$csr"
}

sign_cert() {
    local csr="$1" ca_cert="$2" ca_key="$3" out="$4" days="$5" ext="$6"
    echo " -> signing $out with CA $ca_cert"
    openssl x509 -req -in "$csr" -CA "$ca_cert" -CAkey "$ca_key" \
        -CAcreateserial -out "$out" -days "$days" -sha256 \
        -extfile "$CONF" -extensions "$ext"
}

copy_certs() {
    echo " -> copying certs to $OUT_DIR"
    install -m 0644 "$ROOT_CERT" "$OUT_DIR/root.pem"
    install -m 0644 "$INTER_CERT" "$OUT_DIR/intermediate.pem"
    install -m 0644 "$LEAF_CERT" "$OUT_DIR/leaf.pem"
    cat "$LEAF_CERT" "$INTER_CERT" "$ROOT_CERT" > "$OUT_DIR/chain.pem"
}

secure_delete() {
    [ "$KEEP_KEYS" -eq 1 ] && return
    echo " -> securely deleting private keys"
    if [ $DETECT_SHRED -eq 1 ]; then
        find "$TMPDIR" -type f -name '*.key.pem' -print0 | xargs -0 -r shred -u
    else
        find "$TMPDIR" -type f -name '*.key.pem' -print0 | xargs -0 -r rm -f --
    fi
}

# ---------------------------
# Filenames
# ---------------------------
ROOT_KEY="$TMPDIR/root.key.pem"
ROOT_CERT="$TMPDIR/root.cert.pem"
INTER_KEY="$TMPDIR/intermediate.key.pem"
INTER_CSR="$TMPDIR/intermediate.csr.pem"
INTER_CERT="$TMPDIR/intermediate.cert.pem"
LEAF_KEY="$TMPDIR/leaf.key.pem"
LEAF_CSR="$TMPDIR/leaf.csr.pem"
LEAF_CERT="$TMPDIR/leaf.cert.pem"

# ---------------------------
# Generate chain
# ---------------------------
echo "Generating Root CA..."
gen_key "$ROOT_KEY" 4096
gen_self_signed "$ROOT_KEY" "$ROOT_CERT" \
    "/C=DE/ST=Berlin/L=Berlin/O=ExampleOrg/OU=Root/CN=BSI Root CA" \
    "$DAYS_ROOT" "v3_root_ca"

echo "Generating Intermediate..."
gen_key "$INTER_KEY" 4096
gen_csr "$INTER_KEY" "$INTER_CSR" \
    "/C=DE/ST=Berlin/L=Berlin/O=ExampleOrg/OU=Intermediate/CN=BSI Intermediate CA"
sign_cert "$INTER_CSR" "$ROOT_CERT" "$ROOT_KEY" "$INTER_CERT" "$DAYS_INTER" "v3_intermediate_ca"

echo "Generating Leaf..."
gen_key "$LEAF_KEY" 2048
gen_csr "$LEAF_KEY" "$LEAF_CSR" \
    "/C=DE/ST=Berlin/L=Berlin/O=ExampleOrg/OU=Leaf/CN=leaf.example.test"
sign_cert "$LEAF_CSR" "$INTER_CERT" "$INTER_KEY" "$LEAF_CERT" "$DAYS_LEAF" "v3_leaf"

copy_certs
secure_delete

# ---------------------------
# Report
# ---------------------------
echo "Certificates saved to ./$OUT_DIR/"
ls -l "$OUT_DIR"

echo
echo "Fingerprints (SHA256):"
openssl x509 -noout -sha256 -fingerprint -in "$OUT_DIR/root.pem"
openssl x509 -noout -sha256 -fingerprint -in "$OUT_DIR/intermediate.pem"
openssl x509 -noout -sha256 -fingerprint -in "$OUT_DIR/leaf.pem"

echo
[ "$KEEP_KEYS" -eq 0 ] && echo "Private keys were removed from temporary directory."
[ "$KEEP_KEYS" -eq 1 ] && echo "Private keys were preserved in temp dir: $TMPDIR"

echo "Done."