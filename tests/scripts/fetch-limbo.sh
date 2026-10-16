#!/usr/bin/env bash
# Download the pinned x509-limbo testcases to tests/limbo/limbo.json.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="${ROOT}/tests/limbo/limbo.json"

COMMIT="554528a9b0c0d95e071f55de018326f0b65a8364"
SHA256="611e337b9fb477b927bae65434650692cb9d2070ff5b05f975d0403510acd4de"

if [[ -f "$DEST" ]] && echo "${SHA256}  ${DEST}" | sha256sum --check --status; then
  echo "${DEST} is up to date"
  exit 0
fi

TMP="$(mktemp "${DEST}.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
curl -sSfL "https://raw.githubusercontent.com/C2SP/x509-limbo/${COMMIT}/limbo.json" -o "$TMP"
echo "${SHA256}  ${TMP}" | sha256sum --check --quiet
mv "$TMP" "$DEST"
echo "Fetched x509-limbo ${COMMIT} to ${DEST}"
