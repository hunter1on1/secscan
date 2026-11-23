"""Hosting-platform detection and the shared-responsibility model.

A site built on Wix, Squarespace or Shopify is not configured the way a
self-hosted nginx server is: the platform controls the servers, so some
problems are simply not the site owner's to fix. This module

1. **detects** the platform from passive signals (response headers, cookie
   names, and markers in the HTML), with a confidence level and the evidence,
2. **tags** every finding with who can fix it:

   * ``you``       - you can fix it yourself (code, content, your own server)
   * ``settings``  - partly, through a platform setting, plan or add-on
   * ``platform``  - only the platform can change it

3. gives **platform-specific fix steps** with a link to the platform's docs.

The capability tables are deliberately conservative: they only claim what
the platforms' own documentation says. Where we are not sure, the note says
"check the platform docs" and links to them. The grade itself never changes:
a visitor's browser doesn't care who hosts the site.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from html.parser import HTMLParser

from secscan.models import Finding, Status

YOU = "you"
SETTINGS = "settings"
PLATFORM = "platform"

RESPONSIBILITY_LABELS = {
    YOU: "you can fix",
    SETTINGS: "partly via settings",
    PLATFORM: "platform-controlled",
}


# --------------------------------------------------------------------------- #
# Platforms
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Platform:
    id: str
    name: str
    kind: str  # "builder", "host", "cms" or "cdn"
    docs: str
    # Builders and static hosts don't let you edit a web-server config, so
    # Nginx/Apache snippets are irrelevant there.
    server_snippets: bool = False
    snippet_platforms: tuple[str, ...] = ()  # advice snippets that apply


PLATFORMS: dict[str, Platform] = {
    p.id: p
    for p in (
        Platform("wix", "Wix", "builder", "https://support.wix.com/en/article/about-ssl-and-https"),
        Platform(
            "squarespace",
            "Squarespace",
            "builder",
            "https://support.squarespace.com/hc/en-us",
        ),
        Platform("shopify", "Shopify", "builder", "https://help.shopify.com/en/manual"),
        Platform("webflow", "Webflow", "builder", "https://help.webflow.com/hc/en-us"),
        Platform(
            "wordpress-com",
            "WordPress.com",
            "builder",
            "https://developer.wordpress.com/docs/guides/add-http-headers/",
        ),
        Platform(
            "github-pages",
            "GitHub Pages",
            "host",
            "https://docs.github.com/en/pages",
        ),
        Platform(
            "netlify",
            "Netlify",
            "host",
            "https://docs.netlify.com/manage/routing/headers/",
            snippet_platforms=("netlify",),
        ),
        Platform(
            "vercel",
            "Vercel",
            "host",
            "https://vercel.com/docs/headers",
            snippet_platforms=("vercel", "app"),
        ),
        Platform(
            "wordpress",
            "WordPress (self-hosted)",
            "cms",
            "https://wordpress.org/documentation/",
            server_snippets=True,
            snippet_platforms=("nginx", "apache", "cloudflare", "app"),
        ),
        Platform(
            "cloudflare",
            "Cloudflare",
            "cdn",
            "https://developers.cloudflare.com/rules/transform/response-header-modification/",
            server_snippets=True,
            snippet_platforms=("cloudflare", "nginx", "apache", "app"),
        ),
    )
}

# Order used to pick the *primary* platform when several are detected:
# a site builder on top of Cloudflare is still "a Wix site".
_PRIORITY = [
    "wix",
    "squarespace",
    "shopify",
    "webflow",
    "wordpress-com",
    "github-pages",
    "netlify",
    "vercel",
    "wordpress",
    "cloudflare",
]


@dataclass
class Detection:
    platform: str  # Platform.id
    name: str
    kind: str
    confidence: str  # "high", "medium" or "low"
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "name": self.name,
            "kind": self.kind,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


# --------------------------------------------------------------------------- #
# HTML markers
# --------------------------------------------------------------------------- #
class _MetaCollector(HTMLParser):
    """Collect <meta name=... content=...> values (generator, referrer...)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.attributes: set[str] = set()  # attribute names seen, e.g. data-wf-site

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self.attributes.update(values)
        if tag == "meta" and "name" in values:
            self.meta.setdefault(values["name"].lower(), values.get("content", ""))


def extract_meta(html: str) -> tuple[dict[str, str], set[str]]:
    collector = _MetaCollector()
    collector.feed(html[:2_000_000])
    collector.close()
    return collector.meta, collector.attributes


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Signals:
    host: str
    headers: Mapping[str, str]  # lower-cased names
    cookies: set[str]  # cookie names
    html: str
    meta: Mapping[str, str]
    html_attrs: set[str]

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def _cookie_names(set_cookie_headers: Iterable[str]) -> set[str]:
    return {h.split("=", 1)[0].strip() for h in set_cookie_headers if "=" in h}


# Each rule: (platform, weight, evidence text, predicate). Weight 3 = a signal
# only that platform produces; 2 = a strong hint; 1 = a weak hint. A platform
# is reported once its weights add up to 2 or more.
_RULES: list[tuple[str, int, str, Callable[[_Signals], bool]]] = [
    # Wix
    ("wix", 3, "X-Wix-Request-Id header", lambda s: bool(s.header("x-wix-request-id"))),
    ("wix", 3, "Server: Pepyaka", lambda s: "pepyaka" in s.header("server").lower()),
    ("wix", 3, 'generator "Wix.com Website Builder"',
     lambda s: s.meta.get("generator", "").lower().startswith("wix.com")),
    ("wix", 2, "ssr-caching cookie", lambda s: "ssr-caching" in s.cookies),
    ("wix", 2, "assets from static.wixstatic.com / static.parastorage.com",
     lambda s: "static.wixstatic.com" in s.html or "static.parastorage.com" in s.html),
    # Squarespace
    ("squarespace", 3, "Server: Squarespace",
     lambda s: s.header("server").lower() == "squarespace"),
    ("squarespace", 3, "<!-- This is Squarespace. --> comment",
     lambda s: "This is Squarespace." in s.html),
    ("squarespace", 2, "assets from static1.squarespace.com",
     lambda s: "static1.squarespace.com" in s.html),
    ("squarespace", 1, "crumb / SS_MID cookie", lambda s: bool({"crumb", "SS_MID"} & s.cookies)),
    # Shopify
    ("shopify", 3, "Powered-By: Shopify header",
     lambda s: "shopify" in s.header("powered-by").lower()),
    ("shopify", 3, "X-ShopId / X-Shopify-Stage header",
     lambda s: bool(s.header("x-shopid") or s.header("x-shopify-stage")
                    or s.header("x-sorting-hat-shopid"))),
    ("shopify", 2, "_shopify_* cookies",
     lambda s: any(c.startswith("_shopify") for c in s.cookies)),
    ("shopify", 2, "assets from cdn.shopify.com", lambda s: "cdn.shopify.com" in s.html),
    # Webflow
    ("webflow", 3, "data-wf-site attribute",
     lambda s: "data-wf-site" in s.html_attrs or "data-wf-site=" in s.html),
    ("webflow", 3, 'generator "Webflow"',
     lambda s: s.meta.get("generator", "").lower().startswith("webflow")),
    ("webflow", 2, "X-Wf-* headers", lambda s: any(h.startswith("x-wf-") for h in s.headers)),
    ("webflow", 1, "assets from website-files.com", lambda s: "website-files.com" in s.html),
    # WordPress.com
    ("wordpress-com", 3, "Host-Header: WordPress.com",
     lambda s: "wordpress.com" in s.header("host-header").lower()),
    ("wordpress-com", 3, 'generator "WordPress.com"',
     lambda s: s.meta.get("generator", "").lower() == "wordpress.com"),
    ("wordpress-com", 1, "X-Hacker header (Automattic)",
     lambda s: bool(s.header("x-hacker"))),
    # Self-hosted WordPress
    ("wordpress", 3, "generator WordPress <version>",
     lambda s: bool(re.match(r"wordpress \d", s.meta.get("generator", "").lower()))),
    ("wordpress", 2, 'Link rel="https://api.w.org/" header',
     lambda s: "api.w.org" in s.header("link")),
    ("wordpress", 2, "/wp-content/ or /wp-includes/ paths",
     lambda s: "/wp-content/" in s.html or "/wp-includes/" in s.html),
    # GitHub Pages (github.com itself sends "Server: github.com", lower case)
    ("github-pages", 3, "*.github.io hostname", lambda s: s.host.endswith(".github.io")),
    ("github-pages", 2, "Server: GitHub.com", lambda s: s.header("server") == "GitHub.com"),
    ("github-pages", 1, "X-GitHub-Request-Id via Fastly",
     lambda s: bool(s.header("x-github-request-id") and s.header("x-fastly-request-id"))),
    # Netlify
    ("netlify", 3, "Server: Netlify", lambda s: s.header("server").lower() == "netlify"),
    ("netlify", 3, "X-NF-Request-Id header", lambda s: bool(s.header("x-nf-request-id"))),
    # Vercel
    ("vercel", 3, "Server: Vercel", lambda s: s.header("server").lower() == "vercel"),
    ("vercel", 3, "X-Vercel-Id header", lambda s: bool(s.header("x-vercel-id"))),
    # Cloudflare (as a CDN / proxy layer)
    ("cloudflare", 2, "Server: cloudflare", lambda s: s.header("server").lower() == "cloudflare"),
    ("cloudflare", 2, "CF-Ray header", lambda s: bool(s.header("cf-ray"))),
    ("cloudflare", 1, "__cf_bm cookie", lambda s: "__cf_bm" in s.cookies),
]  # fmt: skip


def _confidence(score: int) -> str:
    return "high" if score >= 3 else "medium" if score == 2 else "low"


def detect_platforms(
    host: str,
    headers: Mapping[str, str],
    set_cookie_headers: Iterable[str] = (),
    html: str = "",
) -> list[Detection]:
    """Return detected platforms, primary first. Only uses data already fetched."""
    meta, attrs = extract_meta(html) if html else ({}, set())
    signals = _Signals(
        host=host.lower(),
        headers={k.lower(): v for k, v in headers.items()},
        cookies=_cookie_names(set_cookie_headers),
        html=html[:2_000_000],
        meta=meta,
        html_attrs=attrs,
    )
    scores: dict[str, int] = {}
    evidence: dict[str, list[str]] = {}
    for platform, weight, text, predicate in _RULES:
        if predicate(signals):
            scores[platform] = scores.get(platform, 0) + weight
            evidence.setdefault(platform, []).append(text)

    # WordPress.com runs WordPress, so its sites also match the self-hosted
    # WordPress markers; the more specific detection wins.
    if "wordpress-com" in scores and scores["wordpress-com"] >= 3:
        scores.pop("wordpress", None)

    detections = [
        Detection(
            platform=pid,
            name=PLATFORMS[pid].name,
            kind=PLATFORMS[pid].kind,
            confidence=_confidence(score),
            evidence=evidence[pid],
        )
        for pid, score in scores.items()
        if score >= 2  # a single weak hint is not enough to claim anything
    ]
    detections.sort(key=lambda d: _PRIORITY.index(d.platform))
    return detections


def detection_for(platform_id: str) -> Detection:
    """A Detection for a platform the user named with --platform."""
    p = PLATFORMS[platform_id]
    return Detection(p.id, p.name, p.kind, "manual", ["set with --platform"])


# --------------------------------------------------------------------------- #
# Capability tables: who can fix what, per platform
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Capability:
    responsibility: str  # YOU / SETTINGS / PLATFORM
    steps: str  # what to do on this platform
    docs: str = ""


# Check groups, so tables don't have to list every check id.
GROUPS: dict[str, tuple[str, ...]] = {
    "headers": ("hsts", "csp", "framing", "xcto", "referrer", "permissions"),
    "disclosure": ("server", "powered-by", "aspnet-version", "aspnetmvc-version"),
    "cookies": ("cookie-secure", "cookie-httponly", "cookie-samesite", "cookies"),
    "tls": ("tls", "certificate", "hostname"),  # plus every "proto-*" id
    "redirect": ("https-redirect", "https-downgrade"),
}  # fmt: skip

_WIX_HEADERS = "https://support.wix.com/en/article/request-adding-and-customizing-security-headers"
_WIX_ENTERPRISE = (
    "https://support.wix.com/en/article/wix-enterprise-adding-and-setting-up-security-headers"
)
_WIX_CODE = "https://support.wix.com/en/article/embedding-custom-code-on-your-site"
_WIX_FILES = (
    "https://dev.wix.com/docs/develop-websites/articles/coding-with-wix-studio/"
    "wix-studio-about-the-wix-ide"
)
_WIX_SSL = "https://support.wix.com/en/article/about-ssl-and-https"
_SQ_SSL = (
    "https://support.squarespace.com/hc/en-us/articles/205815898-Understanding-SSL-certificates"
)
_SQ_CODE = (
    "https://support.squarespace.com/hc/en-us/articles/"
    "205815908-Customize-parts-of-your-site-with-code-injection"
)
_SHOPIFY_HYDROGEN = "https://shopify.dev/docs/storefronts/headless/hydrogen/content-security-policy"
_SHOPIFY_THEMES = "https://help.shopify.com/en/manual/online-store/themes"
_WF_HEADERS = "https://help.webflow.com/hc/en-us/articles/46651836279059-Custom-security-headers"
_WF_PUBLISH = (
    "https://help.webflow.com/hc/en-us/articles/33961287288339-Advanced-publishing-options"
)
_WPCOM_HEADERS = "https://developer.wordpress.com/docs/guides/add-http-headers/"
_WPCOM_SFTP = "https://developer.wordpress.com/docs/developer-tools/sftp/"
_GHP_HTTPS = (
    "https://docs.github.com/en/pages/getting-started-with-github-pages/"
    "securing-your-github-pages-site-with-https"
)
_NETLIFY_HEADERS = "https://docs.netlify.com/manage/routing/headers/"
_VERCEL_HEADERS = "https://vercel.com/docs/headers"
_CF_TRANSFORM = "https://developers.cloudflare.com/rules/transform/response-header-modification/"
_CF_HTTPS = (
    "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/"
)
_CF_TLS = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/"
_CF_SECTXT = "https://developers.cloudflare.com/security-center/infrastructure/security-file/"

_META_REFERRER = '<meta name="referrer" content="strict-origin-when-cross-origin">'

# platform -> {check id or group name: Capability}. Check ids win over groups.
CAPABILITIES: dict[str, dict[str, Capability]] = {
    "wix": {
        "headers": Capability(
            PLATFORM,
            "Standard Wix plans can't add or change security response headers. Only Wix "
            "Studio for Enterprise can (Security Headers in the enterprise dashboard).",
            _WIX_HEADERS,
        ),
        "referrer": Capability(
            SETTINGS,
            f"Add {_META_REFERRER} in the head via Settings > Custom Code (site must be "
            "published with a connected domain). secscan recognises the meta tag.",
            _WIX_CODE,
        ),
        "csp": Capability(
            PLATFORM,
            "Not available on standard Wix plans; Wix Studio for Enterprise can set a CSP "
            "under Security Headers.",
            _WIX_ENTERPRISE,
        ),
        "cookies": Capability(
            PLATFORM, "These cookies are set by Wix's servers, not by your site.", _WIX_HEADERS
        ),
        "cors": Capability(PLATFORM, "Wix controls CORS headers.", _WIX_HEADERS),
        "disclosure": Capability(PLATFORM, "Wix controls these headers.", _WIX_HEADERS),
        "security-txt": Capability(
            PLATFORM,
            "Wix doesn't serve your own files such as security.txt (Wix documents that they "
            "are ignored), so this can't be fixed on Wix today.",
            _WIX_FILES,
        ),
        "tls": Capability(PLATFORM, "Wix manages SSL certificates and TLS.", _WIX_SSL),
        "redirect": Capability(PLATFORM, "Wix handles HTTP to HTTPS automatically.", _WIX_SSL),
        "mixed-content": Capability(
            YOU,
            "Replace http:// URLs in embeds, custom code and links to images you added.",
            "https://support.wix.com/en/article/troubleshooting-your-ssl-certificate",
        ),
    },
    "squarespace": {
        "headers": Capability(
            PLATFORM,
            "Squarespace doesn't support custom response headers on any plan; Code "
            "Injection only adds HTML to the page.",
            _SQ_CODE,
        ),
        "hsts": Capability(
            SETTINGS, "In the SSL settings choose Secure and turn on HSTS Secure.", _SQ_SSL
        ),
        "referrer": Capability(
            SETTINGS,
            f"Add {_META_REFERRER} via Code Injection (header). Code Injection is on Core, "
            "Plus and Advanced plans.",
            _SQ_CODE,
        ),
        "cookies": Capability(PLATFORM, "These cookies are set by Squarespace.", _SQ_CODE),
        "cors": Capability(PLATFORM, "Squarespace controls CORS headers.", _SQ_CODE),
        "disclosure": Capability(PLATFORM, "Squarespace controls these headers.", _SQ_CODE),
        "security-txt": Capability(
            PLATFORM,
            "Squarespace doesn't document a way to publish files under /.well-known/. "
            "Check the platform docs.",
            "https://support.squarespace.com/hc/en-us",
        ),
        "tls": Capability(PLATFORM, "Squarespace manages SSL certificates and TLS.", _SQ_SSL),
        "redirect": Capability(
            SETTINGS, "In the SSL settings choose Secure (always redirect to HTTPS).", _SQ_SSL
        ),
        "mixed-content": Capability(
            YOU, "Replace http:// URLs in your custom code, embeds and integrations.", _SQ_SSL
        ),
    },
    "shopify": {
        "headers": Capability(
            PLATFORM,
            "Shopify sets the response headers of Liquid storefronts. A Hydrogen (headless) "
            "storefront can set them in code.",
            _SHOPIFY_HYDROGEN,
        ),
        "referrer": Capability(
            SETTINGS,
            f"Add {_META_REFERRER} to layout/theme.liquid (Online Store > Themes > Edit code).",
            _SHOPIFY_THEMES,
        ),
        "cookies": Capability(PLATFORM, "These cookies are set by Shopify.", _SHOPIFY_THEMES),
        "cors": Capability(PLATFORM, "Shopify controls CORS headers.", _SHOPIFY_THEMES),
        "disclosure": Capability(PLATFORM, "Shopify controls these headers.", _SHOPIFY_THEMES),
        "security-txt": Capability(
            PLATFORM,
            "No documented way to publish /.well-known/security.txt on a Liquid storefront. "
            "Check the platform docs.",
            "https://help.shopify.com/en/manual",
        ),
        "tls": Capability(PLATFORM, "Shopify manages SSL certificates and TLS.", _SHOPIFY_THEMES),
        "redirect": Capability(PLATFORM, "Shopify handles HTTPS redirects.", _SHOPIFY_THEMES),
        "mixed-content": Capability(
            YOU, "Replace http:// URLs in your theme code and content.", _SHOPIFY_THEMES
        ),
    },
    "webflow": {
        "headers": Capability(
            SETTINGS,
            "Custom security headers are Enterprise-only: Site settings > Publishing > Custom "
            "Headers, then republish.",
            _WF_HEADERS,
        ),
        "hsts": Capability(
            SETTINGS,
            "HSTS is on automatically for non-Enterprise sites; the subdomain and preload "
            "options are under Site settings > Publishing > Advanced publishing options.",
            _WF_HEADERS,
        ),
        "framing": Capability(
            SETTINGS,
            'Turn on "Use secure frame headers" in Advanced publishing options.',
            _WF_PUBLISH,
        ),
        "permissions": Capability(
            PLATFORM,
            "Webflow doesn't support Permissions-Policy (Enterprise can set the older "
            "Feature-Policy header instead).",
            _WF_HEADERS,
        ),
        "cookies": Capability(PLATFORM, "These cookies are set by Webflow.", _WF_HEADERS),
        "cors": Capability(PLATFORM, "Webflow controls CORS headers.", _WF_HEADERS),
        "disclosure": Capability(PLATFORM, "Webflow controls these headers.", _WF_HEADERS),
        "security-txt": Capability(
            SETTINGS,
            "Check the platform docs for publishing files under /.well-known/ on your plan.",
            "https://help.webflow.com/hc/en-us",
        ),
        "tls": Capability(PLATFORM, "Webflow manages SSL certificates and TLS.", _WF_PUBLISH),
        "redirect": Capability(PLATFORM, "Webflow handles HTTPS redirects.", _WF_PUBLISH),
        "mixed-content": Capability(
            YOU, "Replace http:// URLs in embeds and custom code.", _WF_PUBLISH
        ),
    },
    "wordpress-com": {
        "headers": Capability(
            SETTINGS,
            "Add the header with the Redirection plugin or a custom-redirects.php file (paid "
            "plans with plugins / hosting features). Some headers can't be changed.",
            _WPCOM_HEADERS,
        ),
        "cors": Capability(
            SETTINGS, "CORS headers can be set like other headers (see docs).", _WPCOM_HEADERS
        ),
        "cookies": Capability(
            PLATFORM,
            "Most cookies come from WordPress.com or plugins; check which one sets it.",
            _WPCOM_HEADERS,
        ),
        "disclosure": Capability(PLATFORM, "WordPress.com controls these headers.", _WPCOM_HEADERS),
        "security-txt": Capability(
            SETTINGS,
            "On plans with hosting features you can upload .well-known/security.txt over "
            "SFTP. Check the platform docs.",
            _WPCOM_SFTP,
        ),
        "tls": Capability(PLATFORM, "WordPress.com manages SSL and TLS.", _WPCOM_HEADERS),
        "redirect": Capability(PLATFORM, "WordPress.com handles HTTPS redirects.", _WPCOM_HEADERS),
        "mixed-content": Capability(YOU, "Replace http:// URLs in posts, widgets and themes."),
    },
    "github-pages": {
        "headers": Capability(
            PLATFORM,
            "GitHub Pages doesn't support custom response headers (_headers files are "
            "ignored). Put a CDN such as Cloudflare in front, or move to a host that does.",
            "https://docs.github.com/en/pages",
        ),
        "referrer": Capability(
            YOU,
            f"Add {_META_REFERRER} to the <head> of your layout.",
            "https://docs.github.com/en/pages",
        ),
        "cookies": Capability(PLATFORM, "Cookies on Pages sites come from GitHub."),
        "cors": Capability(PLATFORM, "GitHub Pages controls CORS headers."),
        "disclosure": Capability(PLATFORM, "GitHub Pages controls these headers."),
        "security-txt": Capability(
            YOU,
            'Commit .well-known/security.txt. With Jekyll, add include: [".well-known"] to '
            "_config.yml (Jekyll skips dot-folders by default).",
            "https://docs.github.com/en/pages",
        ),
        "tls": Capability(PLATFORM, "GitHub manages the certificate and TLS.", _GHP_HTTPS),
        "redirect": Capability(
            SETTINGS, "Repository Settings > Pages > tick Enforce HTTPS.", _GHP_HTTPS
        ),
        "mixed-content": Capability(YOU, "Use https:// URLs in your pages.", _GHP_HTTPS),
    },
    "netlify": {
        "headers": Capability(
            YOU, "Add the header to a _headers file (or netlify.toml).", _NETLIFY_HEADERS
        ),
        "cors": Capability(
            YOU, "Set CORS headers in _headers or your functions.", _NETLIFY_HEADERS
        ),
        "cookies": Capability(YOU, "Cookies are set by your site or functions."),
        "security-txt": Capability(
            YOU, "Put .well-known/security.txt in your publish directory.", _NETLIFY_HEADERS
        ),
        "disclosure": Capability(PLATFORM, "Netlify sets the Server header."),
        "tls": Capability(PLATFORM, "Netlify manages certificates and TLS."),
        "redirect": Capability(
            PLATFORM, "Netlify redirects to HTTPS once the certificate is live."
        ),
        "mixed-content": Capability(YOU, "Use https:// URLs in your pages."),
    },
    "vercel": {
        "headers": Capability(
            YOU,
            "Add the header in vercel.json (headers) or your framework config.",
            _VERCEL_HEADERS,
        ),
        "cors": Capability(
            YOU, "Set CORS headers in vercel.json or your API code.", _VERCEL_HEADERS
        ),
        "cookies": Capability(YOU, "Cookies are set by your app."),
        "security-txt": Capability(YOU, "Put .well-known/security.txt in public/."),
        "disclosure": Capability(
            YOU, "Remove framework headers (e.g. poweredByHeader: false in Next.js)."
        ),
        "server": Capability(PLATFORM, "Vercel sets the Server header."),
        "tls": Capability(PLATFORM, "Vercel manages certificates and TLS."),
        "redirect": Capability(PLATFORM, "Vercel redirects HTTP to HTTPS automatically."),
        "mixed-content": Capability(YOU, "Use https:// URLs in your pages."),
    },
    "cloudflare": {
        "headers": Capability(
            YOU,
            "Set it on your origin server, or at the edge with a Cloudflare Transform Rule "
            "(Modify Response Header).",
            _CF_TRANSFORM,
        ),
        "security-txt": Capability(
            YOU,
            "Serve it from your origin, or use Cloudflare's security.txt feature in Security "
            "Center.",
            _CF_SECTXT,
        ),
        "tls": Capability(
            SETTINGS,
            "Edge TLS is configured in Cloudflare: SSL/TLS > Edge Certificates (Minimum TLS "
            "Version, TLS 1.3).",
            _CF_TLS,
        ),
        "redirect": Capability(SETTINGS, "Turn on Always Use HTTPS in Cloudflare.", _CF_HTTPS),
    },
}

# Self-hosted WordPress: you own the server, but Cloudflare (if present) owns
# the edge, so TLS/redirect questions fall through to the Cloudflare table.
_EDGE_GROUPS = {"tls", "redirect"}


def _group_of(check_id: str) -> str | None:
    if check_id.startswith("proto-"):
        return "tls"
    for group, ids in GROUPS.items():
        if check_id in ids:
            return group
    return None


def capability_for(check_id: str, detections: Sequence[Detection]) -> Capability | None:
    """Look up who can fix `check_id` given the detected platforms."""
    if not detections:
        return None
    primary = detections[0].platform
    group = _group_of(check_id)
    cdn_present = any(d.platform == "cloudflare" for d in detections)

    tables = [CAPABILITIES.get(primary, {})]
    if primary in ("wordpress",) and cdn_present and group in _EDGE_GROUPS:
        tables.insert(0, CAPABILITIES["cloudflare"])
    for table in tables:
        if check_id in table:
            return table[check_id]
        if group and group in table:
            return table[group]
    return None


def tag_findings(findings: Iterable[Finding], detections: Sequence[Detection]) -> None:
    """Set responsibility (and platform steps) on every finding, in place."""
    primary = PLATFORMS[detections[0].platform] if detections else None
    for finding in findings:
        capability = capability_for(finding.check_id, detections)
        if capability is None:
            finding.responsibility = YOU
            continue
        finding.responsibility = capability.responsibility
        if finding.status in (Status.WARN, Status.FAIL) and primary is not None:
            finding.platform_steps = capability.steps
            finding.platform_docs = capability.docs or primary.docs


@dataclass
class YourPart:
    """The 'shared responsibility' view of one scan."""

    platform: str | None  # primary platform name
    controllable: int  # graded checks you can act on (you + settings)
    controllable_passed: int
    open_you: int  # problems you can fix yourself
    open_settings: int  # problems fixable via platform settings/plans
    platform_issues: int  # problems only the platform can fix

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "controllable": self.controllable,
            "controllable_passed": self.controllable_passed,
            "open_you": self.open_you,
            "open_settings": self.open_settings,
            "platform_issues": self.platform_issues,
        }

    def summary(self) -> str:
        text = f"{self.controllable_passed} of {self.controllable} checks you control pass"
        if self.platform_issues:
            who = self.platform or "the platform"
            noun = "issue" if self.platform_issues == 1 else "issues"
            text += f" · {self.platform_issues} {noun} controlled by {who}"
        return text


def your_part(findings: Iterable[Finding], detections: Sequence[Detection]) -> YourPart:
    graded = [f for f in findings if f.status in (Status.PASS, Status.WARN, Status.FAIL)]
    problems = [f for f in graded if f.status != Status.PASS]
    controllable = [f for f in graded if f.responsibility in (YOU, SETTINGS)]
    return YourPart(
        platform=detections[0].name if detections else None,
        controllable=len(controllable),
        controllable_passed=sum(f.status == Status.PASS for f in controllable),
        open_you=sum(f.responsibility == YOU for f in problems),
        open_settings=sum(f.responsibility == SETTINGS for f in problems),
        platform_issues=sum(f.responsibility == PLATFORM for f in problems),
    )


# --------------------------------------------------------------------------- #
# Which config snippets are worth showing
# --------------------------------------------------------------------------- #
def snippet_platforms(
    detections: Sequence[Detection], requested: Sequence[str] | None = None
) -> tuple[str, ...]:
    """Pick which --explain snippets (nginx, apache, ...) to show.

    Snippets the user explicitly asked for always win. Otherwise: on a site
    builder there is no server config to edit, so show none (the platform
    steps are shown instead); on Netlify/Vercel show only their own format;
    on a self-hosted or unknown site show everything.
    """
    from secscan.advice import PLATFORMS as SNIPPETS  # local import: avoid a cycle

    if requested:
        return tuple(p for p in SNIPPETS if p in requested)
    if not detections:
        return SNIPPETS
    platform = PLATFORMS[detections[0].platform]
    if platform.server_snippets or platform.snippet_platforms:
        return tuple(p for p in SNIPPETS if p in platform.snippet_platforms)
    return ()


def describe(detections: Sequence[Detection]) -> str:
    """One line such as "Wix (high confidence) behind Cloudflare"."""
    if not detections:
        return "not detected"
    primary = detections[0]
    if primary.kind == "cdn" and primary.confidence != "manual":
        # A CDN alone tells us nothing about the server behind it.
        return f"{primary.name} CDN ({primary.confidence} confidence), origin server unknown"
    conf = "set manually" if primary.confidence == "manual" else f"{primary.confidence} confidence"
    text = f"{primary.name} ({conf})"
    if any(d.platform == "cloudflare" for d in detections[1:]):
        text += " behind Cloudflare"
    return text
