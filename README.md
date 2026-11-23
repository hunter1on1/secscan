# secscan

[![CI](https://github.com/hunter1on1/secscan/actions/workflows/ci.yml/badge.svg)](https://github.com/hunter1on1/secscan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A command-line tool that grades a website's security configuration from A+ to F and tells
you how to fix each problem.

## What it checks

- **Headers**: HSTS, Content-Security-Policy, clickjacking protection, nosniff,
  Referrer-Policy, Permissions-Policy
- **TLS**: certificate trust, expiry and hostname; TLS 1.0/1.1 disabled, TLS 1.3 offered;
  HTTP to HTTPS redirect
- **Cookies**: `Secure`, `HttpOnly` and `SameSite` flags
- **CORS**: whether other sites can read responses, especially with credentials
- **Mixed content**: `http://` scripts, styles and images on an HTTPS page
- **security.txt**: a valid RFC 9116 file for reporting vulnerabilities
- **Version leaks**: `Server`, `X-Powered-By` and ASP.NET headers that reveal versions
- **Platform detection**: recognises Wix, Squarespace, Shopify, Webflow, WordPress, GitHub
  Pages, Netlify, Vercel and Cloudflare, and marks which problems only the platform can fix

## Example

Shortened output of a real scan:

```text
$ secscan example.com
╭─ Grade  F   score 23/100 ─────────────────────────────────────────╮
│ example.com                                                       │
│ Final URL: https://example.com/ (HTTP 200)                        │
│ TLS: TLSv1.3                                                      │
│ 7 passed · 3 warnings · 4 failed · 3 info                         │
│ Platform: Cloudflare CDN (high confidence), origin server unknown │
│ Your part: 7 of 14 checks you control pass                        │
╰───────────────────────────────────────────────────────────────────╯
 FAIL  Strict-Transport-Security  Header missing: browsers may use plain HTTP.     -20
 FAIL  Content-Security-Policy    Header missing: no browser-side XSS mitigation.  -20
 PASS  Certificate                Issued by SSL Corporation, expires 2026-12-25
 PASS  TLSv1.0 disabled           Refused
 ...
```

## Install

Requires Python 3.10 or newer.

```bash
pip install git+https://github.com/hunter1on1/secscan.git
```

## Usage

```bash
secscan example.com                        # scan a site
secscan example.com --explain              # how to fix each problem, with config snippets
secscan example.com --html report.html     # shareable HTML report
secscan example.com --sarif secscan.sarif  # findings for GitHub code scanning
secscan example.com --json                 # machine-readable output
secscan example.com --min-grade B          # exit code 1 below B (for CI)
```

All options, output formats and the GitHub Actions example are in
[docs/USAGE.md](docs/USAGE.md). How points are deducted is in
[docs/SCORING.md](docs/SCORING.md), and the security concepts behind each check are
explained in [docs/LEARNING.md](docs/LEARNING.md).

## Responsible use

secscan only makes the ordinary requests a browser makes when it opens a page (a few HTTPS
requests and TLS handshakes). It sends no attack payloads. Scan sites you own or have
permission to test.

## License

[MIT](LICENSE)
