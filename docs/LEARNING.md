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

## 9. Concepts from the code itself

- **Defence in depth**: no single header is enough; each one covers a different attack.
- **Pure functions + dependency injection**: checks don't touch the network, and the
  scanner accepts a fake HTTP client (`httpx.MockTransport`) and a fake TLS probe. That's
  how the tests run offline, and it's a habit worth keeping for any security tool.
- **Fail safe**: anything we can't verify is reported as INFO instead of guessed, and a
  site we can't reach gets an F rather than a misleading score.

## Practice ideas

1. Scan a few well-known sites and compare grades. Why do some big sites score low?
2. Run a local nginx in Docker, scan `localhost`, then add headers one by one and watch
   the grade change.
3. Try https://badssl.com hosts (`expired.badssl.com`, `wrong.host.badssl.com`) to see
   certificate failures.
4. Pick an item from the README roadmap (cookie flags is a good first one) and build it,
   tests first.

## References

- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP security: https://developer.mozilla.org/docs/Web/Security
- Mozilla Observatory (a similar tool, for comparison): https://developer.mozilla.org/observatory
- RFC 6797 (HSTS), RFC 8446 (TLS 1.3), RFC 8996 (deprecating TLS 1.0/1.1)
