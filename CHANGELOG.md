# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## Unreleased

### Added
- **`--profile restaurant`**: optional privacy and booking checks for restaurant websites
  (cookie consent banners, a privacy/cookie policy link, Italian P.IVA, form transport,
  booking and delivery widgets, contact links and Google Maps). They get their own
  **compliance score**; the security grade is unchanged. This is not legal advice.

## 0.2.0 - 2026-11-22

### Added
- **Cookie checks**: `Secure`, `HttpOnly` (for session-like cookies) and `SameSite` on
  every `Set-Cookie`, including cookies set on redirect hops. Cookie values are never
  printed.
- **CORS check**: sends a browser-style `Origin` header (reserved `.invalid` domain) and
  flags reflected or `null` origins, especially with `Allow-Credentials: true`.
- **Mixed content check**: finds `http://` scripts, stylesheets, frames and objects
  (active) and images/media (passive) in the HTML of the HTTPS page; recognises CSP
  `upgrade-insecure-requests`.
- **security.txt check** (RFC 9116): present, `text/plain`, `Contact` and a valid,
  unexpired `Expires` (RFC 3339 parser that also works on Python 3.10).
- **Version disclosure** now also covers `X-AspNet-Version` and `X-AspNetMvc-Version`.
- **HTTPS -> HTTP downgrade**: flags HTTPS URLs whose redirects end on plain HTTP.
- **Fix advice** for every warning and failure: explanation plus copy-paste snippets for
  Nginx, Apache, Cloudflare, Netlify / Cloudflare Pages, Vercel and application code.
  Shown with `--explain` (filter with `--platform`), included in JSON.
- **HTML report** (`--html PATH`): self-contained, no scripts or external assets,
  light/dark mode, print-friendly, everything from the scanned site HTML-escaped.
- **SARIF 2.1.0 export** (`--sarif PATH`, `--sarif-artifact PATH`) with
  `security-severity`, stable fingerprints and fix advice as rule help, for GitHub code
  scanning. Validated against the official OASIS schema in the tests.
- **Hosting-platform detection** from passive signals (headers, cookie names,
  `<meta name="generator">`, asset hosts) for Wix, Squarespace, Shopify, Webflow,
  WordPress.com, self-hosted WordPress, GitHub Pages, Netlify, Vercel and Cloudflare, with
  confidence and evidence. Override with `--platform <id>` or switch off with `--no-detect`.
- **Who can fix it**: every finding is tagged *you can fix*, *partly via settings* or
  *platform-controlled*, based on conservative per-platform capability tables with links to
  the platforms' own docs. The grade is unchanged; a new **"Your part"** summary shows how
  many checks you control pass and how many problems belong to the platform (terminal,
  JSON, HTML and SARIF).
- Platform-specific fix steps come first in the advice; server snippets are hidden on hosted
  builders unless requested with `--platform nginx` etc.
- `Referrer-Policy` set with `<meta name="referrer">` now counts, so site-builder users can
  fix it without header access.
- CSP detail mentions when only a `Content-Security-Policy-Report-Only` policy exists.
- Findings are grouped by area (headers, cookies, CORS, content, disclosure, TLS) in all
  outputs, and the summary shows passed/warning/failed/info counts.
- `docs/LEARNING.md`: new sections on cookies, CORS, mixed content, security.txt,
  ASP.NET version headers and the shared-responsibility model, plus new practice exercises.

### Changed
- `--platform` now also accepts hosting platform ids, not only snippet formats.
- `Server` / `X-Powered-By` findings moved to the new `disclosure` category.
- Scores now include the new checks (see docs/SCORING.md), so some sites grade
  lower than with 0.1.x.

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
