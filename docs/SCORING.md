# How secscan grades a site

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

## Compliance score (`--profile restaurant`)

The restaurant checks use the same 100-point bands, but as a **separate** score. Their
deductions are never added to the security grade.

| Finding | Points |
|---------|-------:|
| Tracking scripts or cookies on the first page, with no known consent banner | -20 |
| No privacy or cookie policy link on the homepage (and none at the usual paths) | -15 |
| Policy exists at a usual path but the homepage does not link to it | -5 |
| Italian-looking page with no visible Partita IVA / VAT number | -5 |
| Form posts to `http://`, or a password field is sent over HTTP | -20 |
| Booking or delivery widget loaded over `http://` | -20 |
| Google Maps embed loaded over `http://` | -10 |

Info-only notes (contact links, a banner whose load order was not verified, an email form
without a privacy sentence) do not cost points. A missing VAT number on a page that does
not look Italian is also info.

These checks are heuristics, and the report is **not legal advice**.
