# secscan

[![CI](https://github.com/hunter1on1/secscan/actions/workflows/ci.yml/badge.svg)](https://github.com/hunter1on1/secscan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)

**secscan** is a command-line tool that audits a website's **HTTP security headers** and
**TLS configuration**, explains every finding in plain language, tells you how to fix it,
and sums it all up as a letter grade from **A+** to **F**.

```console
$ secscan https://github.com
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

| Area | Check | Why |
|------|-------|-----|
| Headers | `Strict-Transport-Security` (presence, `max-age` >= 180 days) | Forces HTTPS, prevents SSL stripping |
| Headers | `Content-Security-Policy` (presence, `'unsafe-inline'`, `'unsafe-eval'`, wildcard script sources) | Main browser defence against XSS |
| Headers | `X-Frame-Options` **or** CSP `frame-ancestors` | Prevents clickjacking |
| Headers | `X-Content-Type-Options: nosniff` | Stops MIME-type sniffing |
| Headers | `Referrer-Policy` | Stops URLs (and tokens in them) leaking to other sites |
| Headers | `Permissions-Policy` | Disables camera, mic, geolocation... when not needed |
| Headers | `Server` / `X-Powered-By` version disclosure | Version numbers help attackers pick exploits |
| TLS | Certificate trust, issuer, expiry (days remaining) | Untrusted or expiring certs break the site |
| TLS | Hostname match | Certificate must cover the domain |
| TLS | TLS 1.0 / 1.1 accepted? TLS 1.3 offered? | Old protocols are deprecated (RFC 8996) |
| TLS | HTTP to HTTPS redirect | Users typing `http://` must land on HTTPS |

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
secscan example.com --json > report.json # machine-readable output
secscan example.com --no-tls             # headers only, skip TLS probing
secscan example.com --min-grade B        # exit code 1 if the grade is below B (for CI)
secscan intranet.local --ca-bundle corp-ca.pem  # trust a custom/internal CA
```

| Option | Description |
|--------|-------------|
| `-f, --file PATH` | Read targets from a file |
| `--json` | Print results as JSON instead of tables |
| `--no-tls` | Skip certificate and protocol checks |
| `--ca-bundle PATH` | PEM file of trusted CA certificates (default: `$SSL_CERT_FILE`, else certifi) |
| `--timeout SECONDS` | Network timeout (default 10) |
| `--min-grade GRADE` | Fail (exit 1) if any target scores below `GRADE` |
| `-q, --quiet` | Hide the recommendations list |

Exit codes: `0` success, `1` a target is below `--min-grade`, `2` a target could not be scanned.

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

A real scan of `https://github.com` (run on 2026-11-20):

```text
╭─ Grade  A+   score 95/100 ────────────────╮
│ https://github.com                        │
│ Final URL: https://github.com/ (HTTP 200) │
│ TLS: TLSv1.3                              │
╰───────────────────────────────────────────╯
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━┓
┃ Status ┃ Check                     ┃ Details                           ┃ Pts ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━┩
│ PASS   │ Strict-Transport-Security │ max-age=31536000                  │     │
│        │                           │ (includeSubDomains, preload)      │     │
│ PASS   │ Content-Security-Policy   │ Policy present (15 directives).   │     │
│ PASS   │ Clickjacking protection   │ CSP frame-ancestors 'none'        │     │
│ PASS   │ X-Content-Type-Options    │ nosniff                           │     │
│ PASS   │ Referrer-Policy           │ strict-origin-when-cross-origin   │     │
│ WARN   │ Permissions-Policy        │ Header missing.                   │  -5 │
│ INFO   │ Server header             │ 'github.com' (no version          │     │
│        │                           │ disclosed)                        │     │
│ INFO   │ HTTP -> HTTPS redirect    │ Plain HTTP answered with status   │     │
│        │                           │ 500; redirect not confirmed.      │     │
│ PASS   │ Certificate               │ Issued by Sectigo Limited,        │     │
│        │                           │ expires 2027-01-27 (68 days left) │     │
│ PASS   │ Hostname match            │ Certificate covers github.com     │     │
│ PASS   │ TLSv1.0 disabled          │ Refused                           │     │
│ PASS   │ TLSv1.1 disabled          │ Refused                           │     │
│ PASS   │ TLSv1.3 supported         │ Accepted                          │     │
└────────┴───────────────────────────┴───────────────────────────────────┴─────┘
Recommendations
  • Permissions-Policy: Add e.g.: Permissions-Policy: camera=(), microphone=(), 
geolocation=()
```

> The *HTTP -> HTTPS redirect* row is INFO here because the network the scan ran from
> answered plain HTTP itself, so the redirect could not be confirmed. Inconclusive
> results never cost points.

### JSON output

```json
[
  {
    "target": "github.com",
    "final_url": "https://github.com/",
    "status_code": 200,
    "score": 95,
    "grade": "A+",
    "findings": [
      {
        "check_id": "hsts",
        "title": "Strict-Transport-Security",
        "category": "headers",
        "status": "pass",
        "detail": "max-age=31536000 (includeSubDomains, preload)",
        "recommendation": "",
        "deduction": 0,
        "critical": false
      }
    ],
    "tls": { "negotiated_version": "TLSv1.3", "certificate": { "issuer": "Sectigo Limited" } }
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
OpenSSL build refuses it) are reported as **INFO** and never cost points.

## Project layout

```text
src/secscan/
├── cli.py       # argument parsing, exit codes
├── scanner.py   # orchestrates one scan (HTTP fetch, redirect check, TLS)
├── headers.py   # pure functions: headers -> findings
├── tls.py       # TLS probing (network) + evaluation (pure)
├── grading.py   # score and letter grade
├── report.py    # rich tables and JSON
└── models.py    # dataclasses shared by everything
tests/           # pytest suite; all network calls are mocked
docs/LEARNING.md # the security concepts behind each check
```

The checks are pure functions that take headers or TLS facts and return findings. The
network code sits at the edges, so the tests run offline in well under a second.

## Development

```bash
pytest            # run the test suite
ruff check .      # lint
ruff format .     # format
```

CI runs lint and tests on Python 3.10 to 3.13 for every push and pull request.

## Roadmap

- [ ] Cookie flags: `Secure`, `HttpOnly`, `SameSite` on `Set-Cookie`
- [ ] CORS misconfiguration checks (`Access-Control-Allow-Origin: *` with credentials)
- [ ] HSTS preload list status
- [ ] Weak cipher suite detection and certificate key size
- [ ] `security.txt` presence (RFC 9116)
- [ ] HTML report export
- [ ] Concurrent scanning of many targets
- [ ] Publish to PyPI

## Ethical use

secscan sends a few ordinary HTTPS requests and TLS handshakes, about what a browser does
when it visits a page. It is not an attack tool. Still: **only scan systems you own or have
explicit permission to test.** Unauthorised scanning may break a site's terms of service or
the law where you live.

## Learning

New to these topics? [docs/LEARNING.md](docs/LEARNING.md) explains each concept behind the
checks, with links to further reading.

## License

[MIT](LICENSE)
