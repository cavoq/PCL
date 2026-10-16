# Development entry point. CI runs the same targets.

GO ?= go
GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION := v1.9.0
FUZZTIME ?= 10s

# Repository paths. Go tests locate their files through internal/testfiles;
# keep both in step when the layout changes.
CMD := ./cmd/pcl
INTEGRATION := ./tests
FIXTUREGEN := ./tests/fixturegen
SCHEMA_JSON := schemas/policy.schema.json
PSL_SNAPSHOT := internal/data/public_suffix_list.dat
LIMBO_DIR := tests/limbo

LIMBO_JSON := $(LIMBO_DIR)/limbo.json
LIMBO_COMMIT := $(shell sed -n 's/^commit=//p' $(LIMBO_DIR)/pin)
LIMBO_SHA256 := $(shell sed -n 's/^sha256=//p' $(LIMBO_DIR)/pin)

LETSENCRYPT_CRL := internal/crl/testdata/letsencrypt
LETSENCRYPT_CERT := internal/cert/testdata/letsencrypt

.PHONY: all build test race cover integration limbo limbo-fetch fuzz lint vuln tidy-check \
	schema schema-check check golden fixtures letsencrypt-fixtures psl-snapshot clean

all: check

build:
	$(GO) build -trimpath -ldflags="-s -w" -o pcl $(CMD)

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

# Coverage over every package, the integration tests in ./tests included.
cover:
	$(GO) test -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

integration:
	$(GO) test -race $(INTEGRATION)

limbo: limbo-fetch
	PCL_REQUIRE_LIMBO=1 $(GO) test -v -run '^TestLimbo$$' $(INTEGRATION)

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
	$(GO) run $(CMD) schema > $(SCHEMA_JSON)

schema-check:
	$(GO) run $(CMD) schema | diff -u $(SCHEMA_JSON) -

# The checks to run before pushing.
check: tidy-check schema-check lint race

# Rewrites the CLI golden files in cmd/pcl/testdata/golden; review the diff.
golden:
	$(GO) test $(CMD) -run '^TestGolden$$' -update

# Regenerates the certificate, CRL and OCSP fixtures in tests/certs,
# tests/crls and tests/ocsps with new keys.
fixtures:
	$(GO) run $(FIXTUREGEN)

# Refreshes the Public Suffix List snapshot embedded in the binary.
psl-snapshot:
	curl -sSfL https://publicsuffix.org/list/public_suffix_list.dat -o $(PSL_SNAPSHOT)
	grep -m1 '^// VERSION:' $(PSL_SNAPSHOT)

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
