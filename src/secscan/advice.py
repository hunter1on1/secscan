"""Fix advice for every check: what to change, and copy-paste config.

This is the single catalogue of checks. Each :class:`Rule` has

* a stable ``id`` (the ``check_id`` used by findings),
* a human name and description (also used for SARIF rules),
* a ``security_severity`` from 0-10, which GitHub code scanning uses to
  label results as low / medium / high / critical,
* an :class:`Advice` with snippets for common servers and hosting platforms.

Most header fixes look the same everywhere, so :func:`header_snippets`
generates them for one header name and value instead of repeating them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass

from secscan.models import Advice, Finding, Status

PLATFORMS = ("nginx", "apache", "cloudflare", "netlify", "vercel", "app")

PLATFORM_LABELS = {
    "nginx": "Nginx",
    "apache": "Apache",
    "cloudflare": "Cloudflare",
    "netlify": "Netlify / Cloudflare Pages",
    "vercel": "Vercel",
    "app": "Application code",
}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    security_severity: float
    advice: Advice


def header_snippets(name: str, value: str) -> dict[str, str]:
    """Ready-to-paste config that adds one response header on each platform."""
    vercel = {"headers": [{"source": "/(.*)", "headers": [{"key": name, "value": value}]}]}
    return {
        "nginx": '# server {} block; "always" also covers error pages\n'
        f'add_header {name} "{value}" always;',
        "apache": f"# .htaccess or <VirtualHost> (needs mod_headers)\n"
        f'Header always set {name} "{value}"',
        "cloudflare": "Rules > Transform Rules > Modify Response Header > Create rule\n"
        f"  Operation:   Set static\n  Header name: {name}\n  Value:       {value}\n"
        "(Cloudflare Pages: use a _headers file, see the Netlify snippet)",
        "netlify": f"# _headers file in the publish directory\n/*\n  {name}: {value}",
        "vercel": "// vercel.json\n" + json.dumps(vercel, indent=2),
    }


def _unset_header_snippets(name: str) -> dict[str, str]:
    return {
        "nginx": "# when nginx proxies your app (location block)\n"
        f"proxy_hide_header {name};\nfastcgi_hide_header {name};  # PHP-FPM",
        "apache": f"Header always unset {name}\nHeader unset {name}",
        "cloudflare": "Rules > Transform Rules > Modify Response Header > Create rule\n"
        f"  Operation:   Remove\n  Header name: {name}",
    }


_TLS_PROTOCOLS = {
    "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
    "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
    "cloudflare": "SSL/TLS > Edge Certificates:\n  Minimum TLS Version: TLS 1.2\n  TLS 1.3: On",
    "netlify": "Managed by Netlify (TLS 1.2+ by default); nothing to configure.",
    "vercel": "Managed by Vercel (TLS 1.2+ by default); nothing to configure.",
}

_COOKIE_APP = (
    "# Django (settings.py)\n"
    "SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\n"
    "SESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = 'Lax'\n\n"
    "# Flask\n"
    "app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,\n"
    "                  SESSION_COOKIE_SAMESITE='Lax')\n\n"
    "// Express (express-session)\n"
    "app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }))"
)

_COOKIE_PROXY = {
    "nginx": "# nginx 1.19.3+, inside the location that proxies your app\n"
    "proxy_cookie_flags ~ secure httponly samesite=lax;",
    "apache": "# Apache 2.4 (mod_headers): append flags to every cookie\n"
    'Header always edit Set-Cookie "^(.*)$" "$1; Secure; HttpOnly; SameSite=Lax"',
    "app": _COOKIE_APP,
}

_SECURITY_TXT = (
    "Contact: mailto:security@example.com\n"
    "Expires: 2027-12-31T23:59:59.000Z\n"
    "Preferred-Languages: en\n"
    "Canonical: https://example.com/.well-known/security.txt"
)

RULES: dict[str, Rule] = {}


def _rule(
    id: str,
    name: str,
    description: str,
    severity: float,
    summary: str,
    snippets: dict[str, str] | None = None,
    references: Iterable[str] = (),
) -> None:
    RULES[id] = Rule(
        id, name, description, severity, Advice(summary, snippets or {}, list(references))
    )


_rule(
    "hsts",
    "Strict-Transport-Security",
    "HSTS forces browsers to use HTTPS for the site, preventing SSL-stripping attacks.",
    6.5,
    "Tell browsers to only ever use HTTPS for this domain. Start with a short max-age "
    "while testing, then raise it to one year. Only add includeSubDomains if every "
    "subdomain supports HTTPS.",
    header_snippets("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
)
_rule(
    "csp",
    "Content-Security-Policy",
    "CSP restricts where scripts and other resources can load from, limiting XSS.",
    6.5,
    "Add a Content-Security-Policy. Deploy it first as Content-Security-Policy-Report-Only "
    "to see what would break, then enforce it. Avoid 'unsafe-inline' for scripts: use "
    "nonces or hashes instead.",
    header_snippets(
        "Content-Security-Policy",
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    ),
    ["https://developer.mozilla.org/docs/Web/HTTP/CSP", "https://csp-evaluator.withgoogle.com/"],
)
_rule(
    "framing",
    "Clickjacking protection",
    "X-Frame-Options or CSP frame-ancestors stops other sites from framing the page.",
    5.0,
    "Forbid other sites from loading your pages in a frame. CSP frame-ancestors is the "
    "modern control; X-Frame-Options covers old browsers. Use SAMEORIGIN/'self' if you "
    "frame your own pages.",
    header_snippets("X-Frame-Options", "DENY"),
    ["https://owasp.org/www-community/attacks/Clickjacking"],
)
_rule(
    "xcto",
    "X-Content-Type-Options",
    "nosniff stops browsers from guessing (sniffing) content types.",
    4.0,
    "Stop browsers from second-guessing the Content-Type you send.",
    header_snippets("X-Content-Type-Options", "nosniff"),
)
_rule(
    "referrer",
    "Referrer-Policy",
    "Controls how much of the URL is leaked to other sites via the Referer header.",
    3.0,
    "Send only the origin (not the full URL) to other sites.",
    header_snippets("Referrer-Policy", "strict-origin-when-cross-origin"),
)
_rule(
    "permissions",
    "Permissions-Policy",
    "Disables powerful browser features (camera, microphone, geolocation) the site does not use.",
    2.0,
    "Switch off browser features you don't use. List only what you need, e.g. "
    "geolocation=(self) if your own pages use it.",
    header_snippets("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
)
_rule(
    "server",
    "Server version disclosure",
    "The Server header reveals software versions that help attackers pick exploits.",
    3.0,
    "Keep the Server header generic (or remove it) so it doesn't advertise versions.",
    {
        "nginx": "# http { } block\nserver_tokens off;",
        "apache": "# httpd.conf / apache2.conf\nServerTokens Prod\nServerSignature Off",
        "cloudflare": "Cloudflare already replaces the Server header with 'cloudflare'.",
    },
)
_rule(
    "powered-by",
    "X-Powered-By disclosure",
    "X-Powered-By reveals the framework or language running the site.",
    3.0,
    "Remove X-Powered-By. It is set by the application stack, so fix it there first.",
    {
        **_unset_header_snippets("X-Powered-By"),
        "app": "; PHP (php.ini)\nexpose_php = Off\n\n"
        "// Express\napp.disable('x-powered-by')\n\n"
        "<!-- ASP.NET / IIS (web.config) -->\n<system.webServer><httpProtocol>"
        '<customHeaders><remove name="X-Powered-By" /></customHeaders>'
        "</httpProtocol></system.webServer>",
    },
)
_rule(
    "aspnet-version",
    "X-AspNet-Version disclosure",
    "X-AspNet-Version reveals the exact .NET framework version.",
    3.0,
    "Turn off the ASP.NET version header in web.config.",
    {
        **_unset_header_snippets("X-AspNet-Version"),
        "app": "<!-- web.config -->\n<system.web>\n"
        '  <httpRuntime enableVersionHeader="false" />\n</system.web>',
    },
)
_rule(
    "aspnetmvc-version",
    "X-AspNetMvc-Version disclosure",
    "X-AspNetMvc-Version reveals the ASP.NET MVC version.",
    3.0,
    "Disable the MVC version header at application start.",
    {
        **_unset_header_snippets("X-AspNetMvc-Version"),
        "app": "// Global.asax.cs, Application_Start()\n"
        "MvcHandler.DisableMvcResponseHeader = true;",
    },
)
_rule(
    "https-redirect",
    "HTTP to HTTPS redirect",
    "Plain-HTTP requests should be permanently redirected to HTTPS.",
    5.0,
    "Answer every plain-HTTP request with a 301 redirect to the same URL on HTTPS.",
    {
        "nginx": "server {\n    listen 80;\n    server_name example.com;\n"
        "    return 301 https://$host$request_uri;\n}",
        "apache": "<VirtualHost *:80>\n    ServerName example.com\n"
        "    Redirect permanent / https://example.com/\n</VirtualHost>",
        "cloudflare": "SSL/TLS > Edge Certificates > Always Use HTTPS: On",
        "netlify": "Automatic once a certificate is provisioned (Domain settings > HTTPS).",
        "vercel": "Automatic: Vercel redirects HTTP to HTTPS for every domain.",
    },
)
_rule(
    "https-downgrade",
    "HTTPS to HTTP downgrade",
    "An HTTPS URL that redirects to plain HTTP throws away the encryption.",
    7.0,
    "Make every redirect target an https:// URL, including redirects to other hostnames "
    "(e.g. example.com -> www.example.com).",
    {
        "nginx": "return 301 https://www.example.com$request_uri;",
        "apache": "Redirect permanent / https://www.example.com/",
        "cloudflare": "Rules > Redirect Rules: make sure the target URL starts with https://",
        "app": "# check the whole chain\ncurl -sIL https://example.com | grep -i '^location'",
    },
)
_rule(
    "tls",
    "HTTPS available",
    "The site must accept TLS connections on port 443.",
    9.0,
    "Serve the site over HTTPS. Free, automatically renewed certificates are available "
    "from Let's Encrypt.",
    {
        "nginx": "sudo certbot --nginx -d example.com -d www.example.com",
        "apache": "sudo certbot --apache -d example.com -d www.example.com",
        "cloudflare": "SSL/TLS > Overview: set encryption mode to Full (strict).",
        "netlify": "Domain settings > HTTPS > Verify DNS configuration > Provision certificate.",
        "vercel": "Certificates are issued automatically when the domain is added.",
    },
    ["https://letsencrypt.org/getting-started/"],
)
_rule(
    "certificate",
    "TLS certificate",
    "The certificate must be trusted, unexpired and renewed in time.",
    9.0,
    "Install a certificate from a trusted CA and automate renewal so it never expires. "
    "If the error is 'unable to get local issuer certificate' on a site that works in "
    "your browser, check your local CA store (--ca-bundle) or that the server sends its "
    "intermediate certificates (fullchain).",
    {
        "nginx": "# use the FULL chain, not just the leaf certificate\n"
        "ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;\n"
        "ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
        "apache": "SSLCertificateFile    /etc/letsencrypt/live/example.com/fullchain.pem\n"
        "SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem",
        "cloudflare": "SSL/TLS > Edge Certificates: Universal SSL is renewed automatically.",
        "app": "# check renewal works\nsudo certbot renew --dry-run",
    },
)
_rule(
    "hostname",
    "Certificate hostname match",
    "The certificate must list the domain in its Subject Alternative Names.",
    8.0,
    "Reissue the certificate so it covers every hostname you serve (including www).",
    {
        "nginx": "sudo certbot --nginx -d example.com -d www.example.com",
        "apache": "sudo certbot --apache -d example.com -d www.example.com",
    },
)
for _version in ("TLSv1.0", "TLSv1.1"):
    _rule(
        f"proto-{_version}",
        f"{_version} enabled",
        f"{_version} is deprecated (RFC 8996) and should be disabled.",
        5.0,
        "Allow only TLS 1.2 and TLS 1.3. Every browser from the last decade supports them.",
        dict(_TLS_PROTOCOLS),
        ["https://ssl-config.mozilla.org/"],
    )
_rule(
    "proto-TLSv1.3",
    "TLS 1.3 not offered",
    "TLS 1.3 is faster and removes legacy cryptography.",
    2.0,
    "Enable TLS 1.3 (needs OpenSSL 1.1.1 or newer on the server).",
    dict(_TLS_PROTOCOLS),
    ["https://ssl-config.mozilla.org/"],
)
_rule(
    "cookie-secure",
    "Cookie without Secure flag",
    "Cookies without Secure can be sent over plain HTTP and intercepted.",
    6.5,
    "Mark every cookie Secure. Cookies are set by your application, so fix them there; "
    "the proxy snippets are a stop-gap.",
    dict(_COOKIE_PROXY),
    ["https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies"],
)
_rule(
    "cookie-httponly",
    "Session cookie without HttpOnly",
    "Session cookies readable by JavaScript can be stolen through XSS.",
    5.0,
    "Add HttpOnly to session and authentication cookies so scripts cannot read them.",
    dict(_COOKIE_PROXY),
    ["https://owasp.org/www-community/HttpOnly"],
)
_rule(
    "cookie-samesite",
    "Cookie SameSite attribute",
    "SameSite limits when cookies are sent on cross-site requests, reducing CSRF.",
    3.0,
    "Set SameSite=Lax on cookies (Strict for very sensitive ones). Use SameSite=None "
    "only for cookies that must work cross-site, and always together with Secure.",
    dict(_COOKIE_PROXY),
    ["https://web.dev/articles/samesite-cookies-explained"],
)
_rule(
    "security-txt",
    "security.txt",
    "RFC 9116 security.txt tells researchers how to report vulnerabilities.",
    1.0,
    "Publish a plain-text file at /.well-known/security.txt with at least Contact and "
    "Expires (less than a year ahead). Generator: https://securitytxt.org/",
    {
        "nginx": "# serve the file from disk\nlocation = /.well-known/security.txt {\n"
        "    root /var/www/security;\n    default_type text/plain;\n}",
        "apache": "# place the file at <DocumentRoot>/.well-known/security.txt\n"
        '<Files "security.txt">\n    ForceType text/plain\n</Files>',
        "netlify": "# create public/.well-known/security.txt (or static/.well-known/...)",
        "vercel": "# create public/.well-known/security.txt",
        "app": "# /.well-known/security.txt\n" + _SECURITY_TXT,
    },
    ["https://www.rfc-editor.org/rfc/rfc9116", "https://securitytxt.org/"],
)
_rule(
    "cors",
    "CORS misconfiguration",
    "Overly permissive CORS lets other websites read responses meant for the user.",
    7.5,
    "Never echo the request's Origin back blindly. Keep an explicit allow-list of "
    "trusted origins, and only send Access-Control-Allow-Credentials: true to those.",
    {
        "nginx": "# http { } block: allow-list, empty for everyone else\n"
        'map $http_origin $cors_origin {\n    default "";\n'
        '    "https://app.example.com" $http_origin;\n}\n'
        "# server/location block\n"
        "add_header Access-Control-Allow-Origin $cors_origin always;\n"
        "add_header Vary Origin always;",
        "apache": 'SetEnvIf Origin "^https://app\\.example\\.com$" CORS_OK=$0\n'
        'Header always set Access-Control-Allow-Origin "%{CORS_OK}e" env=CORS_OK\n'
        "Header always merge Vary Origin",
        "app": "// Express (cors package)\n"
        "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))\n\n"
        "# Django (django-cors-headers)\n"
        'CORS_ALLOWED_ORIGINS = ["https://app.example.com"]',
    },
    ["https://portswigger.net/web-security/cors"],
)
_rule(
    "mixed-content",
    "Mixed content",
    "HTTPS pages that load http:// resources expose them to tampering.",
    5.0,
    "Change every http:// resource URL to https:// (or a relative URL). As a safety "
    "net, the CSP directive upgrade-insecure-requests makes browsers upgrade them.",
    {
        **header_snippets("Content-Security-Policy", "upgrade-insecure-requests"),
        "cloudflare": "SSL/TLS > Edge Certificates > Automatic HTTPS Rewrites: On",
    },
    ["https://developer.mozilla.org/docs/Web/Security/Mixed_content"],
)

_GDPR = "https://gdpr.eu/cookies/"
_NOT_LEGAL = " This is not legal advice."

_rule(
    "cookie-consent",
    "Cookie consent banner",
    "A consent banner should appear before analytics or advertising cookies are set, "
    "for visitors in the EU.",
    5.0,
    "Add a cookie consent banner and block analytics and ads until the visitor agrees."
    + _NOT_LEGAL,
    {"app": "Add a consent banner and hold analytics/ads back until the visitor agrees."},
    [_GDPR],
)
_rule(
    "privacy-policy",
    "Privacy / cookie policy",
    "Visitors should be able to open a privacy policy (and a cookie policy, if you use "
    "cookies) from the homepage.",
    4.0,
    "Publish a privacy policy and link it in the footer, in the language of your guests. "
    "A lawyer or your platform's template can help you write it." + _NOT_LEGAL,
    {"app": "Publish a privacy policy and link it in the footer."},
    [_GDPR],
)
_rule(
    "vat-number",
    "VAT / Partita IVA",
    "Italian businesses are generally required to show their Partita IVA on the website.",
    2.0,
    "Add the Partita IVA (and the legal name / registered office) in the footer, next to "
    "the other legal links." + _NOT_LEGAL,
    {"app": "Add the Partita IVA and legal name in the footer."},
)
_rule(
    "form-https",
    "Form transport",
    "Forms that post over plain HTTP can leak names, emails, bookings or passwords.",
    8.0,
    "Serve the site over HTTPS and point every form action at an https:// URL. A blank or "
    "relative action on an HTTPS page is fine.",
    {"app": "Use https:// for every form action (a relative action on an HTTPS page is fine)."},
    ["https://developer.mozilla.org/docs/Web/Security/Mixed_content"],
)
_rule(
    "form-consent",
    "Form privacy notice",
    "Forms that collect an email address should mention why and link to the privacy policy.",
    2.0,
    "Add a short note and a privacy-policy link next to the email field, and only use the "
    "address for the purpose you describe." + _NOT_LEGAL,
    {"app": "Add a short privacy note and a link next to the email field."},
)
_rule(
    "booking-widgets",
    "Booking and ordering widgets",
    "Third-party booking or delivery widgets should load over HTTPS, from the official embed.",
    6.0,
    "Use the official https:// embed from your booking or delivery partner. If you load a "
    "script from an unexpected host, switch back to the official snippet (and add Subresource "
    "Integrity if the vendor publishes a hash).",
    {"app": "Use the official https:// embed from your booking or delivery partner."},
)
_rule(
    "contact-links",
    "Contact links",
    "Telephone and email links on a restaurant homepage are expected and useful.",
    1.0,
    "No change needed; telephone and email links are normal for a restaurant.",
    {"app": "# No change needed."},
)
_rule(
    "google-maps",
    "Google Maps embed",
    "A maps embed should be loaded over HTTPS.",
    3.0,
    "Use the official https://www.google.com/maps/embed URL from Google Maps > Share > Embed.",
    {"app": "Use the official HTTPS embed from Google Maps > Share > Embed."},
)


def advice_for(check_id: str) -> Advice | None:
    rule = RULES.get(check_id)
    return rule.advice if rule else None


def attach_advice(findings: Iterable[Finding]) -> None:
    """Give every WARN/FAIL finding its fix advice (in place)."""
    for finding in findings:
        if finding.status in (Status.WARN, Status.FAIL) and finding.advice is None:
            finding.advice = advice_for(finding.check_id)
