# secscan usage guide

Everything the [README](../README.md) leaves out: every option, output format and how
hosted platforms are handled. Scoring is explained in [SCORING.md](SCORING.md).

## What it checks in detail

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

## Commands and options

```bash
secscan https://example.com              # one site (https:// is assumed if omitted)
secscan example.com github.com           # several sites
secscan --file targets.txt               # one URL per line, '#' starts a comment
secscan example.com --explain            # how to fix each problem, with config snippets
secscan example.com --explain --platform nginx,cloudflare   # only these snippets
secscan mysite.com --platform wix        # skip detection: treat the site as Wix
secscan mysite.com --no-detect           # generic advice, no platform detection
secscan example.com --json > report.json # machine-readable output
secscan example.com --html report.html   # shareable, self-contained HTML report
secscan example.com --sarif secscan.sarif  # SARIF 2.1.0 for GitHub code scanning
secscan example.com --no-tls             # skip TLS probing
secscan example.com --min-grade B        # exit code 1 if the grade is below B (for CI)
secscan intranet.local --ca-bundle corp-ca.pem  # trust a custom/internal CA
secscan example.com --profile restaurant        # privacy and booking checks
```

| Option | Description |
|--------|-------------|
| `-f, --file PATH` | Read targets from a file |
| `--explain` | Show a fix panel for every warning/failure, with config snippets |
| `--platform LIST` | Comma separated. A hosting platform (`wix`, `squarespace`, `shopify`, `webflow`, `wordpress-com`, `wordpress`, `github-pages`, `netlify`, `vercel`, `cloudflare`) overrides detection; a config format (`nginx`, `apache`, `cloudflare`, `netlify`, `vercel`, `app`) chooses which `--explain` snippets to show |
| `--no-detect` | Don't detect the hosting platform; every finding is treated as "you can fix" |
| `--profile restaurant` | Add privacy and booking checks and a separate compliance score. The security grade does not change. |
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

### Hosted platforms and "your part"

A site built with Wix or Squarespace can't send a `Content-Security-Policy` header no matter
how careful its owner is, because the platform runs the servers. secscan keeps the grade
honest (a visitor's browser doesn't care who hosts the site), but it also tells you **who can
fix each problem**:

| Tag | Meaning |
|-----|---------|
| **you can fix** | Your own code, content or server config |
| **partly via settings** | A platform setting, a plan upgrade, or HTML you can inject (e.g. a `<meta>` tag) |
| **platform-controlled** | Only the platform can change it |

The platform is detected from the response you already fetched (headers such as
`X-Wix-Request-Id` or `Server: Netlify`, cookie names, `<meta name="generator">`, asset
hosts), and the evidence is shown so you can judge it. Fix advice then starts with the
platform's own steps and docs link, and server snippets (Nginx/Apache) are hidden on hosted
builders, where there is no server config to edit. Ask for them with `--platform nginx`.
If detection is wrong, set the platform with `--platform wix` (or turn it off with
`--no-detect`).

Illustrative output for a Wix-hosted site (`example.com` stands in for the real domain):

```text
╭─ Grade  D   score 45/100 ────────────────────────────────────────────────────╮
│ https://example.com                                                          │
│ Final URL: https://example.com/ (HTTP 200)                                   │
│ TLS: TLSv1.3                                                                 │
│ 10 passed · 3 warnings · 3 failed · 3 info                                   │
│ Platform: Wix (high confidence) behind Cloudflare                            │
│   evidence: X-Wix-Request-Id header, generator "Wix.com Website Builder",    │
│ ssr-caching cookie, assets from static.wixstatic.com /                       │
│ static.parastorage.com                                                       │
│ Your part: 1 of 2 checks you control pass · 5 issues controlled by Wix       │
╰──────────────────────────────────────────────────────────────────────────────╯
...
Recommendations  (run with --explain for details)
  • Content-Security-Policy: On Wix (platform-controlled): Not available on
standard Wix plans; Wix Studio for Enterprise can set a CSP under Security
Headers.
  • Referrer-Policy: On Wix (partly via settings): Add <meta name="referrer"
content="strict-origin-when-cross-origin"> in the head via Settings > Custom
Code (site must be published with a connected domain). secscan recognises the
meta tag.
  • security.txt: On Wix (platform-controlled): Wix doesn't serve your own files
such as security.txt (Wix documents that they are ignored), so this can't be
fixed on Wix today.
```

What each platform lets you control, as documented by the platforms themselves (secscan
links the relevant docs page in every fix):

| Platform | Security headers | `security.txt` | TLS / HTTPS redirect |
|----------|------------------|----------------|----------------------|
| Wix | Platform-controlled (Wix Studio Enterprise only); `Referrer-Policy` via a `<meta>` tag in Custom Code | Platform-controlled | Platform |
| Squarespace | Platform-controlled; HSTS via the *HSTS Secure* setting; `Referrer-Policy` via Code Injection | Platform-controlled | HTTPS setting |
| Shopify | Platform-controlled on Liquid themes (Hydrogen can set them); `Referrer-Policy` via `theme.liquid` | Platform-controlled | Platform |
| Webflow | Custom headers on Enterprise; secure frame headers and HSTS options in publishing settings | Check docs | Platform |
| WordPress.com | Redirection plugin or `custom-redirects.php` (plans with plugins) | SFTP upload | Platform |
| GitHub Pages | Platform-controlled (`_headers` is ignored); `Referrer-Policy` via `<meta>` | You (commit `.well-known/`) | *Enforce HTTPS* setting |
| Netlify / Vercel | You (`_headers` / `vercel.json`) | You | Platform |
| Self-hosted / Cloudflare | You (server config or Transform Rules) | You | You / Cloudflare settings |

The capability table is conservative: when a platform's docs don't say something is
possible, secscan says "check the platform docs" instead of guessing.

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
Recommendations  (run with --explain for details)
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
        "responsibility": "you",
        "platform_steps": "",
        "platform_docs": "",
        "advice": {
          "summary": "Change every http:// resource URL to https:// ...",
          "snippets": { "nginx": "...", "apache": "...", "cloudflare": "..." },
          "references": ["https://developer.mozilla.org/docs/Web/Security/Mixed_content"]
        }
      }
    ],
    "platforms": [],
    "primary_platform": null,
    "tls": { "negotiated_version": "TLSv1.2", "certificate": { "issuer": "Let's Encrypt" } }
  }
]
```

(shortened) Each result also has a `your_part` object (`controllable`, `controllable_passed`,
`open_you`, `open_settings`, `platform_issues`), and each entry in `platforms` lists the
platform id, kind, confidence and evidence.

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
├── platforms.py     # hosting-platform detection + who-can-fix-what tables
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

## Restaurant profile

`secscan example.com --profile restaurant` adds a **Restaurant & privacy compliance**
section, aimed at restaurant websites (especially small sites in the EU / Italy, often
built on Wix, Squarespace or WordPress). The checks are still passive: the homepage
already fetched for the security scan, plus at most a few same-site pages a browser
would open (for example `/privacy-policy` if the homepage has no policy link). No form
is ever submitted.

| Check | What it looks for |
|-------|-------------------|
| Cookie consent banner | Known platforms (Cookiebot, iubenda, OneTrust, Complianz, CookieYes, Usercentrics, Wix/Squarespace banners). Tracking scripts or cookies (Google Analytics, Meta Pixel, TikTok, Hotjar) in the *first* response with no banner are flagged as **likely** loaded before consent. If a banner is also present, load order is not verified. |
| Privacy / cookie policy | A homepage link whose text or URL matches privacy, informativa, cookie policy, datenschutz, confidentialité, política de privacidad. |
| VAT / Partita IVA | `P.IVA`, `Partita IVA` or `VAT` plus 11 digits, or `IT` plus 11 digits. A warning if the page looks Italian and none is found; otherwise a note. The number itself is not printed in the report. |
| Form transport | `<form>` actions that post to `http://`, or a password field on a plain-HTTP page, are a failure. |
| Form privacy notice | A form that collects an email, with no nearby privacy or consent wording, is reported as info. |
| Booking and ordering widgets | TheFork, OpenTable, Resy, Quandoo, SevenRooms, Google Reserve, Just Eat, Deliveroo, Glovo, Uber Eats, Wix Bookings / Restaurants: listed as an inventory, failed if any embed is `http://`, and noted if a script comes from an unexpected host without Subresource Integrity. |
| Contact links / Google Maps | `mailto:` and `tel:` links (info, which is normal) and Maps embeds (must be HTTPS). |

These findings have their own **compliance** score and letter grade (the same 100-point
bands as the security grade). They never change the security grade, so a site can be
compared with a scan that did not use the profile.

Fix advice is written for a restaurant owner, with platform steps when the site is
detected as Wix or Squarespace (using those platforms' own help articles). **This is not
legal advice.**

How the compliance points are deducted is in [SCORING.md](SCORING.md). The ideas behind
cookie consent are in [LEARNING.md](LEARNING.md#16-cookie-consent-and-gdpr-basics).
