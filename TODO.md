# PCL - Project TODO

## Priority 1: Critical Fixes

- [ ] **Fix nil pointer dereference in public_key_info.go**
  - Location: `internal/linter/public_key_info.go:16`
  - Issue: Accesses `job.Policy.Crypto.SubjectPublicKeyInfo` without checking if `job.Policy.Crypto` is nil
  - Impact: Runtime panic if policy has no crypto section

- [ ] **Fix silent error suppression in certificate loading**
  - Location: `internal/utils/certs.go:40`
  - Issue: Bad certificates are silently skipped with `continue`
  - Fix: Log which files failed to load, add strict mode flag

- [ ] **Fix daysCeil calculation bug**
  - Location: `internal/linter/validity.go:83`
  - Issue: `int(d.Hours()/24) + 1` always adds 1, overcounting days
  - Example: 24-hour duration returns 2 days instead of 1

## Priority 2: Test Coverage

- [ ] Add unit tests for `internal/linter/public_key_info.go`
- [ ] Add unit tests for `internal/linter/signature_algorithm.go`
- [ ] Add unit tests for `internal/linter/validity.go`
- [ ] Add unit tests for `internal/linter/extensions.go`
- [ ] Add unit tests for `internal/linter/name_rules.go`
- [ ] Add integration tests for `cmd/pcl`
- [ ] Add tests for `internal/report` formatters
- [ ] Target: >80% code coverage

## Priority 3: Implement Missing Policy Rules

These are defined in the policy schema but not yet implemented:

- [ ] **Subject name patterns** - `allowed` and `forbidden` regex matching
- [ ] **Issuer name patterns** - `allowed` and `forbidden` regex matching
- [ ] **SAN (Subject Alternative Name) validation**
- [ ] **CRL Distribution Points URL verification** - `verifyAccess` flag
- [ ] **Authority Info Access URL verification** - OCSP/CA Issuers URLs

## Priority 4: CLI Enhancements

- [ ] Add proper exit codes (0=pass, 1=failures, 2=errors)
- [ ] Add summary output (X passed, Y failed, Z warnings)
- [ ] Add verbose/debug logging mode (`--verbose`, `--debug`)
- [ ] Add filter by status (`--only-failures`, `--only-warnings`)
- [ ] Add policy validation command (`pcl validate-policy <file>`)
- [ ] Add certificate info command (`pcl info <cert>`)

## Priority 5: CI/CD

- [ ] Add GitHub Actions workflow for tests on PR
- [ ] Add code coverage tracking (codecov/coveralls)
- [ ] Add golangci-lint for code quality
- [ ] Add automated releases with goreleaser
- [ ] Add Makefile for common tasks

## Priority 6: Future Features

- [ ] Configuration file support (`pcl.yaml` or `.pclrc`)
- [ ] CRL/OCSP revocation checking
- [ ] Certificate transparency log validation
- [ ] Policy inheritance/composition
- [ ] Plugin architecture for custom rules
- [ ] Hostname validation
- [ ] OCSP stapling validation

## Code Quality Improvements

- [ ] Add nil checks for `job` parameter in all lint functions
- [ ] Define constants for magic numbers (e.g., default cert order 1000)
- [ ] Add context to error messages for better debugging
- [ ] Validate policy files against schema before use

## Documentation

- [x] Comprehensive README with usage examples
- [x] Policy configuration guide
- [x] Supported algorithms reference
- [ ] Architecture documentation
- [ ] Contributing guidelines (CONTRIBUTING.md)
- [ ] Changelog (CHANGELOG.md)
