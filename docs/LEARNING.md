# Learning notes: the security behind secscan

These are my study notes on each concept the tool checks. For each one: what it is, the
attack it stops, and how to see it for yourself.

> Tip: open your browser's DevTools (F12), go to **Network**, click the first request, and
> look at **Response Headers**. That's exactly what secscan reads.

---

## 1. HTTP vs HTTPS and TLS

**HTTP** sends everything in plain text. Anyone on the same network (café Wi-Fi, an ISP, a
compromised router) can read or change it. **HTTPS** is HTTP inside a **TLS** tunnel, which
gives three guarantees:

- **Confidentiality**: traffic is encrypted.
- **Integrity**: traffic can't be changed without detection.
- **Authentication**: the certificate proves you are talking to the real server.

### The TLS handshake (simplified)

1. The client says hello and lists the TLS versions and cipher suites it supports.
2. The server picks one and sends its **certificate**.
3. The client checks the certificate (see below) and both sides agree on session keys.
4. Everything after that is encrypted.

### Certificates and trust

A certificate binds a **public key** to a **hostname**. It is signed by a **Certificate
Authority (CA)** such as Let's Encrypt, Sectigo, or DigiCert. Your OS/browser ships a list
of trusted root CAs. A certificate is valid when:

- it chains up to a trusted root,
- it is within its validity dates (`notBefore` / `notAfter`),
- its Subject Alternative Names (SAN) include the hostname you asked for.

secscan reads the issuer and expiry date and lets Python's `ssl.create_default_context()`
do the trust and hostname checks, exactly as a browser would.

Try it: `openssl s_client -connect github.com:443 -servername github.com`

### Protocol versions

| Version | Status |
|---------|--------|
| SSL 2/3 | Broken (POODLE, DROWN) |
| TLS 1.0 / 1.1 | Deprecated by **RFC 8996** (2021). Weak hashing (SHA-1/MD5), attacks like BEAST |
| TLS 1.2 | Fine when configured with modern ciphers |
| TLS 1.3 | Current. Faster handshake, removed all legacy crypto, forward secrecy always on |

secscan connects once per version with a client that is *only allowed* that version. If
the handshake succeeds, the server supports it.

### HTTP to HTTPS redirect

Users still type `example.com` and browsers may try `http://` first. The server should
answer with a `301` redirect to `https://`. On its own that first request is still
unprotected, which is what HSTS fixes.

---

## 2. Strict-Transport-Security (HSTS)

**Attack: SSL stripping.** An attacker in the middle intercepts the first plain-HTTP
request and keeps the victim on HTTP while talking HTTPS to the real server. The victim
never sees the padlock disappear.

**Defence:**

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

After seeing this once, the browser *refuses* to use HTTP for that domain for `max-age`
seconds (here, one year) and turns any `http://` link into `https://` before sending.
`preload` lets the domain be hard-coded into browsers (https://hstspreload.org), which
protects even the very first visit.

---

## 3. Content-Security-Policy (CSP)

**Attack: Cross-Site Scripting (XSS).** If an attacker gets their JavaScript into your
page (through a comment field, a URL parameter, a compromised third-party script), it runs
with the victim's session: it can steal cookies or tokens, or act as the user.

**Defence:** CSP is an allow-list that tells the browser where content may come from:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'
```

- `default-src`: fallback for every resource type
- `script-src`: where JavaScript may load from (the most important directive)
- `'self'`: same origin only
- `'unsafe-inline'`: allows inline `<script>` blocks and `onclick=` handlers. **This
  defeats most of the XSS protection**, because injected scripts are usually inline.
- `'unsafe-eval'`: allows `eval()` and similar string-to-code functions
- `'nonce-...'` / `'sha256-...'`: allow *specific* inline scripts safely

secscan parses the policy (`headers.parse_csp`) and warns about these weaknesses.

Further reading: https://developer.mozilla.org/docs/Web/HTTP/CSP

---

## 4. Clickjacking: X-Frame-Options and frame-ancestors

**Attack:** the attacker's page loads your site inside an invisible `<iframe>` and places
it under a harmless-looking button. The victim thinks they're clicking "Play video" but
actually clicks "Delete account" or "Transfer money" on your site.

**Defence:** forbid other sites from framing you:

```
X-Frame-Options: DENY                         # legacy, widely supported
Content-Security-Policy: frame-ancestors 'none' # modern, more flexible
```

---

## 5. X-Content-Type-Options: nosniff

**Attack: MIME sniffing.** Browsers used to guess a file's type from its content. A user
uploads `avatar.jpg` that actually contains HTML/JS, the browser "sniffs" it as HTML, and
the script runs on your domain.

**Defence:** `X-Content-Type-Options: nosniff` makes the browser trust the
`Content-Type` header and nothing else.

---

## 6. Referrer-Policy

When you click a link, the browser sends the page you came from in the `Referer` header.
URLs can contain sensitive data: `https://site/reset?token=abc123`, internal paths, search
terms. A safe default:

```
Referrer-Policy: strict-origin-when-cross-origin
```

This sends the full URL within your own site, only the origin (`https://site`) to other
sites, and nothing when going from HTTPS to HTTP. `unsafe-url` sends everything everywhere,
so avoid it.

---

## 7. Permissions-Policy

Modern browsers expose powerful APIs: camera, microphone, geolocation, USB, payment. If
your site doesn't use them, switch them off so that an injected or third-party script
can't use them either:

```
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

This follows the **principle of least privilege**: grant only what is needed.

---

## 8. Information disclosure

```
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: PHP/7.2.24
```

These headers give an attacker your exact software versions, so they can look up known
CVEs for them straight away. Hiding versions doesn't fix vulnerabilities (that's
"security through obscurity"), but it removes free reconnaissance and is a common item in
penetration-test reports.

---

## 9. Cookies: Secure, HttpOnly, SameSite

HTTP is stateless, so websites remember you with **cookies**. After you log in, the
server sends something like:

```
Set-Cookie: sessionid=8f3a...; Path=/; Secure; HttpOnly; SameSite=Lax
```

and your browser sends `sessionid` back with every request. Whoever has that value *is*
you, as far as the site is concerned. Stealing it is called **session hijacking**. The
three flags each close a different door:

| Flag | Without it... | Attack it stops |
|------|---------------|-----------------|
| `Secure` | the cookie is also sent over plain `http://` | Sniffing on public Wi-Fi |
| `HttpOnly` | JavaScript can read it with `document.cookie` | XSS stealing the session |
| `SameSite=Lax` | it's attached to requests started by *other* sites | **CSRF**: a hostile page submitting a form to your bank as you |

`SameSite` values: `Strict` (never sent cross-site), `Lax` (sent only on top-level
navigation such as clicking a link; Chrome and Edge apply it by default), `None` (always sent, and
only allowed together with `Secure`).

secscan only demands `HttpOnly` on cookies whose names look like sessions or tokens,
because some cookies (UI preferences, consent banners) are meant to be read by
JavaScript. Bonus: cookie names starting with `__Host-` or `__Secure-` are **prefixes**
that make browsers enforce `Secure` for you.

Try it: DevTools > **Application** > **Cookies** shows these flags as columns.

---

## 10. CORS (Cross-Origin Resource Sharing)

First, the **Same-Origin Policy (SOP)**: JavaScript on `https://evil.example` may *send*
a request to `https://bank.example`, but it may not *read* the response. An **origin** is
scheme + host + port. The SOP is what stops any website from reading your email in
another tab.

**CORS** is the controlled way for a server to relax the SOP:

```
Access-Control-Allow-Origin: https://app.bank.example
Access-Control-Allow-Credentials: true
```

means "JavaScript on `app.bank.example` may read this, even with the user's cookies".

The classic misconfiguration is a lazy allow-list that **echoes back whatever `Origin`
the request had**, combined with `Allow-Credentials: true`. Now *every* website the
victim visits can fetch their private data with their cookies and read it.

How secscan tests it: it sends `Origin: https://secscan-cors-probe.invalid` (`.invalid`
is a domain reserved so it can never exist) and checks whether the server trusts it.

| Response | Verdict |
|----------|---------|
| No `Access-Control-Allow-Origin` | Fine: nobody else may read |
| A fixed, specific origin | Fine |
| `*` without credentials | Fine for public data (CDNs, public APIs). Browsers never send cookies with `*` |
| Our fake origin reflected | Risky: everyone is trusted |
| Our fake origin reflected **and** `Allow-Credentials: true` | Serious: any site can read logged-in users' data |
| `null` trusted | Same as reflection: sandboxed iframes let an attacker send `Origin: null` |

Further reading: https://portswigger.net/web-security/cors (with free labs).

---

## 11. Mixed content

An HTTPS page that loads something over `http://` is **mixed content**. That one request
travels unencrypted, so an attacker on the network can read or replace it:

- **Active** mixed content (`<script>`, stylesheets, `<iframe>`, `<object>`): replacing
  one script means controlling the whole page. Browsers block it, which also breaks
  the site.
- **Passive** mixed content (`<img>`, `<audio>`, `<video>`): can be swapped or used for
  tracking. Browsers now try to upgrade it to HTTPS automatically.

Fix: use `https://` (or relative `//` and `/` URLs) everywhere. Safety net:
`Content-Security-Policy: upgrade-insecure-requests` makes the browser rewrite
`http://` to `https://` before fetching.

secscan parses the page with Python's built-in `html.parser`. Note that plain links
(`<a href="http://...">`) are *navigation*, not mixed content, so they are not flagged.
It only sees the initial HTML, so resources added later by JavaScript won't show up.
The browser console (F12) catches those.

Try it: open https://mixed-script.badssl.com with DevTools open and read the console.

---

## 12. security.txt (RFC 9116)

If you find a bug in someone's website, who do you tell? `security.txt` answers that.
It's a small text file at `https://example.com/.well-known/security.txt`:

```
Contact: mailto:security@example.com
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en
Policy: https://example.com/security-policy
```

`Contact` and `Expires` are required. `Expires` makes sure outdated contacts don't stay
around forever (keep it under a year ahead). It's part of **responsible disclosure**:
researchers report privately, the company fixes the bug, and only then is it made public.
Big companies often point `Contact` to a **bug bounty** platform (GitHub's goes to
HackerOne). Those programs are where you can legally practise on real targets.

secscan also checks that the response really is `text/plain`, because many sites answer
*every* unknown URL with their homepage and status 200 (a "soft 404").

Try it: `curl https://github.com/.well-known/security.txt`

---

## 13. More information leaks: X-AspNet-Version and friends

Section 8 covered `Server` and `X-Powered-By`. Microsoft's ASP.NET adds two more by
default:

```
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
```

They exist only to announce versions, so any value counts as a leak. They're turned off in
`web.config` (`enableVersionHeader="false"`). Attackers collect these during
**reconnaissance**, the first phase of any attack (and of any penetration test), to
match the target against public CVE databases.

---

## 14. Concepts from the code itself

- **Defence in depth**: no single header is enough; each one covers a different attack.
- **Pure functions + dependency injection**: checks don't touch the network, and the
  scanner accepts a fake HTTP client (`httpx.MockTransport`) and a fake TLS probe. That's
  how the tests run offline, and it's a habit worth keeping for any security tool.
- **Fail safe**: anything we can't verify is reported as INFO instead of guessed, and a
  site we can't reach gets an F rather than a misleading score.
- **Output encoding**: the HTML report escapes every value from the scanned site with
  `html.escape`. A security tool that writes HTML must not itself be vulnerable to XSS
  (`tests/test_html_report.py` checks this with a malicious header).
- **Standards over invention**: SARIF (OASIS) for findings, RFC 9116 for security.txt,
  RFC 3339 for dates. Using standards means other tools (like GitHub) understand you.

---

## 15. Shared responsibility: who can fix what

Cloud providers describe security as a **shared responsibility model**: the provider secures
what it runs (data centres, servers, the platform), and the customer secures what they put
on top (their code, content, accounts and settings). Website builders work the same way.

| You run it yourself (VPS, own server) | Static hosts (Netlify, Vercel) | Site builders (Wix, Squarespace, Shopify) |
|---------------------------------------|--------------------------------|-------------------------------------------|
| You control headers, TLS, cookies, files | You control headers and files; the host runs TLS | The platform controls headers, TLS and cookies; you control content and some settings |

So a Wix site can score D even though its owner did nothing wrong: standard Wix plans
can't add a `Content-Security-Policy` header at all. Two tempting fixes are both wrong:

- **Grading Wix sites more gently.** The grade describes what a visitor's browser actually
  receives. An attacker doesn't care who forgot the header.
- **Hiding platform problems.** The site's visitors are still exposed; knowing that helps
  you choose a platform or plan, or ask the vendor for a fix.

secscan keeps the grade honest and adds a second view, **"your part"**: how many of the
checks *you* can act on pass, and how many problems belong to the platform. Each finding
is tagged *you can fix*, *partly via settings* or *platform-controlled*.

**How detection works: fingerprinting.** Platforms leave traces in every response:
headers (`X-Wix-Request-Id`, `Server: Netlify`, `X-Vercel-Id`), cookie names
(`_shopify_y`, `crumb`), `<meta name="generator">` tags, and the hosts their assets load
from (`static.wixstatic.com`, `cdn.shopify.com`). Each signal has a weight; a platform is
reported only when the weights add up, and the evidence is printed so you can check it.
This is the same passive reconnaissance that tools like Wappalyzer and WhatWeb do, and
attackers do too: knowing a site runs WordPress tells them which exploits to try. That's
one more reason to hide version numbers (section 8).

**A trick for builders: the `<meta>` tag.** Some policies can be set in the HTML instead
of a header. `<meta name="referrer" content="strict-origin-when-cross-origin">` works
exactly like the `Referrer-Policy` header, so on Wix (Custom Code), Squarespace (Code
Injection) or Shopify (`theme.liquid`) you can fix that one yourself, and secscan
recognises it. A CSP can also be set with `<meta http-equiv>`, but without
`frame-ancestors` or reporting, and HSTS can't be set in HTML at all, so it isn't a full
replacement.

**Edge vs origin.** When Cloudflare (or another CDN) sits in front of a site, the browser's
TLS connection ends at Cloudflare, not at your server. TLS versions and the HTTP-to-HTTPS
redirect are then Cloudflare settings, while headers can come from either your server or a
Cloudflare Transform Rule.

## Practice ideas

1. Scan a few well-known sites and compare grades. Why do some big sites score low?
2. Run a local nginx in Docker, scan `localhost`, then add headers one by one and watch
   the grade change.
3. Try https://badssl.com hosts (`expired.badssl.com`, `wrong.host.badssl.com`) to see
   certificate failures.
4. Scan `https://mixed.badssl.com` and `https://mixed-script.badssl.com` and compare the
   mixed-content results (passive vs active).
5. Scan `https://httpbin.org/get` and read the CORS finding. Then test it yourself:
   `curl -sI -H "Origin: https://evil.example" https://httpbin.org/get | grep -i access-control`
6. Write a `security.txt` for your own site and check it with secscan.
7. Run `secscan yoursite --sarif out.sarif` and open the file: find the `ruleId`,
   `level` and `security-severity` of each result.
8. Scan a Wix, a Shopify and a Netlify site and compare their "Your part" lines. Then run
   one with `--no-detect` and see how the advice changes.
9. Open your browser's developer tools (Network tab) on any site and try to guess its
   platform from the response headers alone, before secscan tells you.
10. Pick a check secscan doesn't do yet (for example Subresource Integrity on third-party
    scripts) and build it, tests first.

## References

- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP security: https://developer.mozilla.org/docs/Web/Security
- Mozilla Observatory (a similar tool, for comparison): https://developer.mozilla.org/observatory
- RFC 6797 (HSTS), RFC 8446 (TLS 1.3), RFC 8996 (deprecating TLS 1.0/1.1),
  RFC 6265bis (cookies), RFC 9116 (security.txt)
- PortSwigger Web Security Academy (free labs on CORS, CSRF, XSS, clickjacking):
  https://portswigger.net/web-security
- SARIF 2.1.0 specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
