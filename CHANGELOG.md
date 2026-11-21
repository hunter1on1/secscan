# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## 0.1.1 - 2026-11-21

### Fixed
- Certificates are now verified against the `certifi` CA bundle by default, for both the
  HTTP requests and the TLS checks. Before this, a Python install without a configured
  trust store (e.g. python.org Python on macOS) reported valid sites as
  "Not trusted: unable to get local issuer certificate" and graded them F.

### Added
- `--ca-bundle PATH` option, and support for the `SSL_CERT_FILE` environment variable, to
  trust a custom CA (priority: `--ca-bundle` > `SSL_CERT_FILE` > certifi).
- A hint on "unable to get local issuer certificate" failures pointing at the local
  CA store.
- A clear error when the CA bundle can't be loaded.

## 0.1.0 - 2026-11-20

### Added
- First release: HTTP security header checks (HSTS, CSP, clickjacking, nosniff,
  Referrer-Policy, Permissions-Policy, version disclosure), TLS checks (certificate,
  hostname, TLS 1.0/1.1/1.3, HTTP to HTTPS redirect), A+ to F grading, rich and JSON
  output, multiple targets and target files, `--min-grade` for CI.
