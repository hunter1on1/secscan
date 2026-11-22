# secscan

[![CI](https://github.com/hunter1on1/secscan/actions/workflows/ci.yml/badge.svg)](https://github.com/hunter1on1/secscan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)

**secscan** is a command-line tool that audits a website's **security headers, cookies,
CORS policy, mixed content, `security.txt` and TLS configuration**. It explains every
finding in plain language, gives copy-paste fixes for Nginx, Apache, Cloudflare, Netlify
and Vercel, and sums it all up as a letter grade from **A+** to **F**. Results can be
exported as **JSON**, a self-contained **HTML report**, or **SARIF** for GitHub code
scanning.

```console
$ secscan https://example.com --explain --html report.html
```

## Why it matters

Most successful web attacks don't need a zero-day. They exploit configuration that was
never switched on: a missing `Content-Security-Policy` makes cross-site scripting (XSS)
far more damaging, a missing `Strict-Transport-Security` header allows SSL-stripping on
public Wi-Fi, a forgotten `X-Frame-Options` enables clickjacking, and a certificate that
quietly expires takes a site offline. These are cheap to fix once you know about them.
secscan makes them visible in seconds, and its `--min-grade` flag lets you enforce a
baseline in CI so they never come back.

## What it checks

All checks are passive: secscan only makes the ordinary requests a browser makes
(a few `GET`s and TLS handshakes). It never sends attack payloads.

| Area | Check | Why |
|------|-------|-----|
| Headers | `Strict-Transport-Security` (presence, `max-age` >= 180 days) | Forces HTTPS, prevents SSL stripping |
| Headers | `Content-Security-Policy` (presence, `'unsafe-inline'`, `'unsafe-eval'`, wildcard script sources, Report-Only) | Main browser defence against XSS |
| Headers | `X-Frame-Options` **or** CSP `frame-ancestors` | Prevents clickjacking |
| Headers | `X-Content-Type-Options: nosniff` | Stops MIME-type sniffing |
| Headers | `Referrer-Policy` | Stops URLs (and tokens in them) leaking to other sites |
| Headers | `Permissions-Policy` | Disables camera, mic, geolocation... when not needed |
| Cookies | `Secure`, `HttpOnly` (session cookies), `SameSite` on every `Set-Cookie`, including redirect hops | Stops session theft over HTTP, via XSS, and CSRF |
| CORS | Sends `Origin: https://secscan-cors-probe.invalid` and checks whether it is trusted, with or without credentials; `*` with credentials; `null` origin | A reflected origin with credentials lets any site read users' data |
| Content | `http://` scripts, stylesheets, iframes, objects (active) and images/media (passive) in the HTML of the HTTPS page | Mixed content can be read or replaced in transit |
| Disclosure | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version` revealing versions | Version numbers help attackers pick exploits |
| Disclosure | `/.well-known/security.txt` (RFC 9116): present, plain text, has `Contact`, valid unexpired `Expires` | Tells researchers how to report vulnerabilities |
| TLS | Certificate trust, issuer, expiry (days remaining), hostname match | Untrusted or expiring certs break the site |
| TLS | TLS 1.0 / 1.1 accepted? TLS 1.3 offered? | Old protocols are deprecated (RFC 8996) |
| TLS | HTTP to HTTPS redirect, and HTTPS never redirecting back to HTTP | Users must always end up on HTTPS |

## Installation

Requires Python 3.10 or newer.

```bash
pip install git+https://github.com/hunter1on1/secscan.git
```

Or from a clone, for development:

```bash
git clone https://github.com/hunter1on1/secscan.git
cd secscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
secscan https://example.com              # one site (https:// is assumed if omitted)
secscan example.com github.com           # several sites
secscan --file targets.txt               # one URL per line, '#' starts a comment
secscan example.com --explain            # how to fix each problem, with config snippets
secscan example.com --explain --platform nginx,cloudflare   # only these snippets
secscan example.com --json > report.json # machine-readable output
secscan example.com --html report.html   # shareable, self-contained HTML report
secscan example.com --sarif secscan.sarif  # SARIF 2.1.0 for GitHub code scanning
secscan example.com --no-tls             # skip TLS probing
secscan example.com --min-grade B        # exit code 1 if the grade is below B (for CI)
secscan intranet.local --ca-bundle corp-ca.pem  # trust a custom/internal CA
```

| Option | Description |
|--------|-------------|
| `-f, --file PATH` | Read targets from a file |
| `--explain` | Show a fix panel for every warning/failure, with config snippets |
| `--platform LIST` | Limit `--explain` snippets to `nginx`, `apache`, `cloudflare`, `netlify`, `vercel`, `app` |
| `--json` | Print results as JSON to stdout (includes the fix advice) |
| `--html PATH` | Write a self-contained HTML report (inline CSS, no scripts, works offline) |
| `--sarif PATH` | Write SARIF 2.1.0 |
| `--sarif-artifact PATH` | Repository file that SARIF alerts point at (default: the `--file` targets file, else the URL) |
| `--no-tls` | Skip certificate and protocol checks |
| `--ca-bundle PATH` | PEM file of trusted CA certificates (default: `$SSL_CERT_FILE`, else certifi) |
| `--timeout SECONDS` | Network timeout (default 10) |
| `--min-grade GRADE` | Fail (exit 1) if any target scores below `GRADE` |
| `-q, --quiet` | Hide the recommendations list |

`--json`, `--html` and `--sarif` can be combined in one run. Exit codes: `0` success,
`1` a target is below `--min-grade`, `2` a target could not be scanned.

### Trusted certificates

Certificates are verified against the [certifi](https://pypi.org/project/certifi/) CA bundle
(Mozilla's list of trusted roots), for both the HTTP requests and the TLS checks. Results
are therefore the same on every machine and don't depend on how Python or the OS was
installed. For example, python.org builds on macOS ship without a usable trust store until
you run *Install Certificates.command*, and secscan still works there.

To trust a different set of roots (a corporate proxy or an internal CA), pass
`--ca-bundle PATH` or set `SSL_CERT_FILE`. Priority: `--ca-bundle` > `SSL_CERT_FILE` > certifi.
If a certificate fails with *unable to get local issuer certificate*, secscan adds a hint
that the problem may be the local trust store rather than the site.

### Sample output

A real scan of `https://github.com` (run on 2026-11-22):

```text
╭─ Grade  A+   score 95/100 ────────────────╮
│ https://github.com                        │
│ Final URL: https://github.com/ (HTTP 200) │
│ TLS: TLSv1.3                              │
│ 15 passed · 1 warning · 0 failed · 3 info │
╰───────────────────────────────────────────╯
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━┓
┃ Status ┃ Check                     ┃ Details                           ┃ Pts ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━┩
│        │ HEADERS                   │                                   │     │
│ PASS   │ Strict-Transport-Security │ max-age=31536000                  │     │
│        │                           │ (includeSubDomains, preload)      │     │
│ PASS   │ Content-Security-Policy   │ Policy present (15 directives).   │     │
│ PASS   │ Clickjacking protection   │ CSP frame-ancestors 'none'        │     │
│ PASS   │ X-Content-Type-Options    │ nosniff                           │     │
│ PASS   │ Referrer-Policy           │ strict-origin-when-cross-origin   │     │
│ WARN   │ Permissions-Policy        │ Header missing.                   │  -5 │
├────────┼───────────────────────────┼───────────────────────────────────┼─────┤
│        │ COOKIES                   │                                   │     │
│ PASS   │ Cookie Secure flag        │ All 3 cookie(s) are Secure.       │     │
│ INFO   │ Cookie HttpOnly flag      │ 1 cookie(s) readable by           │     │
│        │                           │ JavaScript (_octo); none look     │     │
│        │                           │ like session cookies.             │     │
│ PASS   │ Cookie SameSite attribute │ Set on all cookies (Lax).         │     │
├────────┼───────────────────────────┼───────────────────────────────────┼─────┤
│        │ CORS                      │                                   │     │
│ PASS   │ CORS policy               │ No cross-origin read access       │     │
│        │                           │ granted.                          │     │
├────────┼───────────────────────────┼───────────────────────────────────┼─────┤
│        │ CONTENT                   │                                   │     │
│ PASS   │ Mixed content             │ No http:// resources found in the │     │
│        │                           │ page HTML.                        │     │
├────────┼───────────────────────────┼───────────────────────────────────┼─────┤
│        │ DISCLOSURE                │                                   │     │
│ INFO   │ Server header             │ 'github.com' (no version          │     │
│        │                           │ disclosed)                        │     │
│ PASS   │ security.txt              │ Contact                           │     │
│        │                           │ https://hackerone.com/github,     │     │
│        │                           │ expires 2026-12-22                │     │
├────────┼───────────────────────────┼───────────────────────────────────┼─────┤
│        │ TLS                       │                                   │     │
│ INFO   │ HTTP -> HTTPS redirect    │ Plain HTTP answered with status   │     │
│        │                           │ 500; redirect not confirmed.      │     │
│ PASS   │ Certificate               │ Issued by Sectigo Limited,        │     │
│        │                           │ expires 2027-01-27 (66 days left) │     │
│ PASS   │ Hostname match            │ Certificate covers github.com     │     │
│ PASS   │ TLSv1.0 disabled          │ Refused                           │     │
│ PASS   │ TLSv1.1 disabled          │ Refused                           │     │
│ PASS   │ TLSv1.3 supported         │ Accepted                          │     │
└────────┴───────────────────────────┴───────────────────────────────────┴─────┘
Recommendations  (run with --explain for config)
  • Permissions-Policy: Add e.g.: Permissions-Policy: camera=(), microphone=(), 
geolocation=()
```

> The *HTTP -> HTTPS redirect* row is INFO here because the network the scan ran from
> answers plain HTTP itself, so the redirect could not be confirmed. Inconclusive results
> never cost points.

### Fix advice (`--explain`)

Every warning and failure comes with an explanation and ready-to-paste configuration.
Excerpt from a real scan of `https://mixed-script.badssl.com` (a test site that is
broken on purpose) with `--explain --platform nginx,cloudflare`:

```text
╭─ FAIL Mixed content ─────────────────────────────────────────────────────────╮
│ Change every http:// resource URL to https:// (or a relative URL). As a      │
│ safety net, the CSP directive upgrade-insecure-requests makes browsers       │
│ upgrade them.                                                                │
│                                                                              │
│ Nginx                                                                        │
│ # server {} block; "always" also covers error pages                          │
│ add_header Content-Security-Policy "upgrade-insecure-requests" always;       │
│                                                                              │
│ Cloudflare                                                                   │
│ SSL/TLS > Edge Certificates > Automatic HTTPS Rewrites: On                   │
│                                                                              │
│ Learn more:                                                                  │
│ https://developer.mozilla.org/docs/Web/Security/Mixed_content                │
╰──────────────────────────────────────────────────────────────────────────────╯
```

The same advice is included in `--json` output (`findings[].advice`), in the HTML report,
and in the SARIF rule help that GitHub shows next to each alert.

### HTML report

`--html report.html` writes one self-contained file: inline CSS, no JavaScript and no
external assets, so it can be emailed or archived. It has a grade summary, the findings
grouped by area, and an expandable "How to fix" section with snippets for each platform.
Everything taken from the scanned site is HTML-escaped, so a hostile site can't inject
markup into the report. It adapts to light/dark mode and prints cleanly.

### GitHub code scanning (SARIF)

`--sarif secscan.sarif` writes [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/),
validated against the official schema in the test suite. Each warning/failure becomes a
result with a `security-severity` (so GitHub labels it low/medium/high/critical), a stable
fingerprint (re-scans update the same alert), and fix advice in the rule help.

GitHub attaches every alert to a file in the repository. Since a website isn't a file,
point alerts at something meaningful with `--sarif-artifact` (for example your server
config or targets file):

```yaml
# .github/workflows/secscan.yml
name: secscan
on:
  schedule: [{ cron: "0 6 * * 1" }]
  workflow_dispatch:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/hunter1on1/secscan.git
      - run: secscan --file targets.txt --sarif secscan.sarif --sarif-artifact targets.txt
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: secscan.sarif }
```

### JSON output

```json
[
  {
    "target": "https://mixed.badssl.com",
    "final_url": "https://mixed.badssl.com/",
    "status_code": 200,
    "score": 8,
    "grade": "F",
    "findings": [
      {
        "check_id": "mixed-content",
        "title": "Mixed content",
        "category": "content",
        "status": "warn",
        "detail": "1 passive http:// resource(s) (images/media): <img> http://mixed.badssl.com/image.jpg",
        "recommendation": "Load every resource over https:// (or add CSP upgrade-insecure-requests).",
        "deduction": 5,
        "critical": false,
        "advice": {
          "summary": "Change every http:// resource URL to https:// ...",
          "snippets": { "nginx": "...", "apache": "...", "cloudflare": "..." },
          "references": ["https://developer.mozilla.org/docs/Web/Security/Mixed_content"]
        }
      }
    ],
    "tls": { "negotiated_version": "TLSv1.2", "certificate": { "issuer": "Let's Encrypt" } }
  }
]
```

(shortened)

## How grading works

The scheme is deliberately simple so that every grade can be explained.

1. Every site starts with **100 points**.
2. Each finding subtracts a fixed number of points:

| Finding | Points |
|---------|-------:|
| HSTS missing, invalid or `max-age=0` | -20 |
| HSTS `max-age` shorter than 180 days | -5 |
| CSP missing | -20 |
| CSP allows `'unsafe-inline'` scripts (without nonce/hash) | -10 |
| CSP has no `script-src`/`default-src` | -10 |
| CSP allows `'unsafe-eval'` | -5 |
| CSP allows scripts from any host (`*` or `https:`) | -5 |
| No clickjacking protection | -15 |
| Weak clickjacking protection (`frame-ancestors *`, unknown XFO value) | -10 |
| `X-Content-Type-Options` missing or wrong | -10 |
| `Referrer-Policy` unsafe (`unsafe-url`, `no-referrer-when-downgrade`) | -10 |
| `Referrer-Policy` missing | -5 |
| `Permissions-Policy` missing | -5 |
| `Server` header discloses a version | -5 |
| `X-Powered-By` present | -5 |
| `X-AspNet-Version` / `X-AspNetMvc-Version` present (each) | -5 |
| Cookie(s) without `Secure` | -10 |
| Session-like cookie(s) without `HttpOnly` | -5 |
| `SameSite=None` without `Secure` | -5 |
| Cookie(s) without an explicit `SameSite` | -2 |
| CORS reflects any origin (or trusts `null`) **with** credentials | -20 |
| CORS reflects any origin (or trusts `null`) without credentials | -5 |
| CORS `*` combined with `Allow-Credentials: true` | -5 |
| Active mixed content (http:// scripts, styles, frames, objects) | -15 |
| Passive mixed content (http:// images, audio, video) | -5 |
| `security.txt` missing, or without `Contact`/valid unexpired `Expires` | -2 |
| HTTPS page redirects to plain HTTP | -20 |
| HTTP served without redirecting to HTTPS | -10 |
| Certificate expires in under 14 days | -10 |
| Certificate expires in under 30 days | -5 |
| TLS 1.0 accepted | -10 |
| TLS 1.1 accepted | -10 |
| TLS 1.3 not offered | -5 |

3. The score never goes below 0 and is mapped to a grade:

| Score | Grade |
|-------|-------|
| 95-100 | **A+** |
| 85-94 | **A** |
| 70-84 | **B** |
| 55-69 | **C** |
| 40-54 | **D** |
| 0-39 | **F** |

4. **Critical findings force an F** regardless of score: HTTPS not available, an untrusted
   or expired certificate, or a certificate that doesn't match the hostname. Browsers block
   these sites outright, so no header can make up for it.

Checks that can't be completed (for example, TLS 1.0 can't be tested because the local
OpenSSL build refuses it) are reported as **INFO** and never cost points. So are
observations that are not problems by themselves: a CORS `*` policy without credentials
(normal for public APIs and CDNs), cookies readable by JavaScript that don't look like
session cookies, or mixed content neutralised by `upgrade-insecure-requests`.

Each kind of problem is counted once per site, not once per cookie or per resource, so
one misconfiguration repeated on 20 cookies doesn't sink the grade on its own.

## Project layout

```text
src/secscan/
├── cli.py           # argument parsing, output selection, exit codes
├── scanner.py       # orchestrates one scan (requests, checks, grading)
├── headers.py       # pure: response headers -> findings
├── cookies.py       # pure: Set-Cookie values -> findings
├── cors.py          # pure: CORS response headers -> finding
├── mixedcontent.py  # pure: page HTML -> finding (stdlib html.parser)
├── securitytxt.py   # pure: security.txt response -> finding (RFC 9116)
├── tls.py           # TLS probing (network) + evaluation (pure)
├── advice.py        # catalogue of every check: severity + fix snippets
├── grading.py       # score and letter grade
├── report.py        # terminal output (rich) and JSON
├── html_report.py   # self-contained HTML report
├── sarif.py         # SARIF 2.1.0 export
└── models.py        # dataclasses shared by everything
tests/               # pytest suite; all network calls are mocked
docs/LEARNING.md     # the security concepts behind each check
```

Checks are pure functions that take headers, cookies, HTML or TLS facts and return
findings. The network code sits at the edges, so the whole suite runs offline in under
a second.

## Development

```bash
pytest            # run the test suite
ruff check .      # lint
ruff format .     # format
```

CI runs lint and tests on Python 3.10 to 3.13 for every push and pull request.

## Roadmap

- [x] Cookie flags, CORS, mixed content, `security.txt`, version disclosure (v0.2.0)
- [x] Fix advice with platform snippets, HTML and SARIF reports (v0.2.0)
- [ ] Publish to PyPI and a Docker image
- [ ] Reusable GitHub Action (`uses: hunter1on1/secscan@v1`)
- [ ] HSTS preload list status
- [ ] Weak cipher suite detection and certificate key size
- [ ] Subresource Integrity (SRI) on third-party scripts
- [ ] Concurrent scanning of many targets

## Ethical use

secscan sends a few ordinary HTTPS requests and TLS handshakes, about what a browser does
when it visits a page (the CORS check sends the same `Origin` header a browser sends for a
cross-site request, using a reserved `.invalid` domain). It is not an attack tool. Still: **only scan systems you own or have
explicit permission to test.** Unauthorised scanning may break a site's terms of service or
the law where you live.

## Learning

New to these topics? [docs/LEARNING.md](docs/LEARNING.md) explains each concept behind the
checks, with links to further reading.

## License

[MIT](LICENSE)
