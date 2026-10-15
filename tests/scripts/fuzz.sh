#!/usr/bin/env bash
# Run every fuzz target for a short time (default 10s each).
# Usage: tests/scripts/fuzz.sh [fuzztime]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FUZZTIME="${1:-10s}"
cd "$ROOT"

for package in $(go list ./internal/...); do
	for target in $(go test -list '^Fuzz' "$package" | grep '^Fuzz' || true); do
		echo "=== $package $target"
		go test "$package" -run '^$' -fuzz "^${target}\$" -fuzztime "$FUZZTIME"
	done
done
