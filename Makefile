# Development entry point. CI runs the same targets.

GO ?= go
GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION := v1.9.0
FUZZTIME ?= 10s

LIMBO_JSON := tests/limbo/limbo.json
LIMBO_COMMIT := $(shell sed -n 's/^commit=//p' tests/limbo/pin)
LIMBO_SHA256 := $(shell sed -n 's/^sha256=//p' tests/limbo/pin)

LETSENCRYPT_CRL := internal/crl/testdata/letsencrypt
LETSENCRYPT_CERT := internal/cert/testdata/letsencrypt

.PHONY: all build test race cover integration limbo limbo-fetch fuzz lint vuln tidy-check \
	schema schema-check check fixtures letsencrypt-fixtures clean

all: check

build:
	$(GO) build -o pcl ./cmd/pcl

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

# Coverage over every package, the integration tests in ./tests included.
cover:
	$(GO) test -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

integration:
	$(GO) test -race ./tests

limbo: limbo-fetch
	PCL_REQUIRE_LIMBO=1 $(GO) test -v -run '^TestLimbo$$' ./tests

# Downloads the x509-limbo testcases pinned in tests/limbo/pin and checks
# their SHA-256; a current copy is kept.
limbo-fetch:
	@if echo "$(LIMBO_SHA256)  $(LIMBO_JSON)" | sha256sum --check --status 2>/dev/null; then \
		echo "$(LIMBO_JSON) is up to date"; \
	else \
		curl -sSfL "https://raw.githubusercontent.com/C2SP/x509-limbo/$(LIMBO_COMMIT)/limbo.json" -o "$(LIMBO_JSON).tmp" && \
		echo "$(LIMBO_SHA256)  $(LIMBO_JSON).tmp" | sha256sum --check --quiet && \
		mv "$(LIMBO_JSON).tmp" "$(LIMBO_JSON)" && \
		echo "Fetched x509-limbo $(LIMBO_COMMIT)"; \
	fi

# Runs every fuzz target for FUZZTIME.
fuzz:
	@set -e; for package in $$($(GO) list ./internal/...); do \
		for target in $$($(GO) test -list '^Fuzz' "$$package" | grep '^Fuzz' || true); do \
			echo "=== $$package $$target"; \
			$(GO) test "$$package" -run '^$$' -fuzz "^$$target\$$" -fuzztime "$(FUZZTIME)"; \
		done; \
	done

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

tidy-check:
	$(GO) mod tidy -diff

schema:
	$(GO) run ./cmd/pcl schema > schemas/policy.schema.json

schema-check:
	$(GO) run ./cmd/pcl schema | diff -u schemas/policy.schema.json -

# The checks to run before pushing.
check: tidy-check schema-check lint race

# Regenerates the certificate, CRL and OCSP fixtures in tests/certs,
# tests/crls and tests/ocsps with new keys.
fixtures:
	$(GO) run ./tests/fixturegen

# Refreshes the Let's Encrypt CRL and CA fixtures from the official endpoints.
letsencrypt-fixtures:
	mkdir -p $(LETSENCRYPT_CRL) $(LETSENCRYPT_CERT)
	curl -sS http://crl.root-x1.letsencrypt.org/ -o $(LETSENCRYPT_CRL)/isrg-root-x1.crl
	curl -sS http://x2.c.lencr.org/ -o $(LETSENCRYPT_CRL)/isrg-root-x2.crl
	curl -sSL http://letsencrypt.org/certs/isrgrootx1.der -o $(LETSENCRYPT_CRL)/isrgrootx1.der
	curl -sSL http://letsencrypt.org/certs/2024/e9.der -o $(LETSENCRYPT_CRL)/e9.der
	curl -sS http://x2.i.lencr.org/ -o $(LETSENCRYPT_CRL)/isrg-root-x2.der
	cp $(LETSENCRYPT_CRL)/e9.der $(LETSENCRYPT_CRL)/isrg-root-x2.der $(LETSENCRYPT_CERT)/
	openssl crl -in $(LETSENCRYPT_CRL)/isrg-root-x1.crl -inform DER -noout -issuer -lastupdate -nextupdate

clean:
	rm -f pcl coverage.out
