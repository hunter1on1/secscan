"""Restaurant and privacy-compliance checks (``--profile restaurant``).

These look at the homepage (and at most a handful of same-site pages a
browser would open) for a cookie-consent banner, a privacy policy, an
Italian VAT number (P.IVA), form safety, and booking or delivery widgets.

They never change the security grade: they get their own compliance score.
Findings use cautious wording ("likely") when the signal is a heuristic.
This is not legal advice.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from secscan.models import Category, Finding, Status

# Used by the CLI help and reports.
PROFILES = ("restaurant",)

MAX_HTML_BYTES = 2_000_000

# Common privacy-policy paths tried only when the homepage has no link.
# Three requests is enough and keeps the scan short.
_PRIVACY_PATHS = ("/privacy-policy", "/privacy", "/informativa-privacy")

_PRIVACY_WORDS = (
    "privacy",
    "informativa",
    "cookie policy",
    "cookie-policy",
    "cookiepolicy",
    "datenschutz",
    "confidentialité",
    "confidentialite",
    "política de privacidad",
    "politica de privacidad",
    "política de cookies",
    "politica de cookies",
    "politica sulla privacy",
    "politica-sulla-privacy",
    "informativa sulla privacy",
    "informativa privacy",
    "avviso cookie",
    "cookies policy",
)

# A page looks Italian when the language is "it" or these words appear.
_ITALIAN_CUES = (
    "ristorante",
    "prenota",
    "prenotazione",
    "informativa",
    "contatti",
    "chi siamo",
    "allergeni",
    "pizzeria",
    "trattoria",
    "osteria",
    "partita iva",
    "p.iva",
    "menù",
    "cucina",
)

_VAT_LABEL = re.compile(
    r"(?:p\.?\s*iva|partita\s+iva|n(?:umero)?\.?\s*iva|vat(?:\s*(?:number|id|n[o°.])?)?)"
    r"\s*[:.\-–]?\s*(?:IT\s*)?(\d{11})",
    re.IGNORECASE,
)
_VAT_IT = re.compile(r"\bIT\s*(\d{11})\b", re.IGNORECASE)

# Consent / privacy wording next to a form that collects an email address.
_FORM_CONSENT = re.compile(
    r"privacy|informativa|consenso|consent|gdpr|cookie|trattamento|"
    r"dati personali|accetto|i agree|i accept|ho letto",
    re.IGNORECASE,
)
_EMAIL_FIELD = re.compile(r"e-?mail|mail", re.IGNORECASE)

# Official docs we have actually opened (200). Don't invent dashboard menus.
_WIX_COOKIE_DOCS = "https://support.wix.com/en/article/displaying-a-cookie-banner-on-your-site"
_SQ_COOKIE_DOCS = (
    "https://support.squarespace.com/hc/en-us/articles/"
    "206545727-Providing-cookie-consent-options-with-a-banner"
)
_GDPR_COOKIES = "https://gdpr.eu/cookies/"


def _finding(check_id: str, title: str, status: Status, detail: str, **kw) -> Finding:
    return Finding(check_id, title, Category.RESTAURANT, status, detail, **kw)


# --------------------------------------------------------------------------- #
# HTML facts
# --------------------------------------------------------------------------- #
@dataclass
class Script:
    src: str
    integrity: str
    body: str = ""


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: list[tuple[str, str]]  # (type, name-or-id)
    text: str


@dataclass
class Page:
    url: str
    lang: str = ""
    links: list[tuple[str, str]] = field(default_factory=list)  # (href, text)
    scripts: list[Script] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    mailto: list[str] = field(default_factory=list)
    tel: list[str] = field(default_factory=list)
    text: str = ""
    html: str = ""


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lang = ""
        self.links: list[tuple[str, str]] = []
        self.scripts: list[Script] = []
        self.iframes: list[str] = []
        self.forms: list[FormInfo] = []
        self.mailto: list[str] = []
        self.tel: list[str] = []
        self._chunks: list[str] = []
        self._link_href = ""
        self._link_parts: list[str] = []
        self._script: Script | None = None
        self._form: FormInfo | None = None
        self._form_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html" and not self.lang:
            self.lang = values.get("lang", "")
        if tag == "a":
            href = values.get("href", "").strip()
            lower = href.lower()
            if lower.startswith("mailto:"):
                self.mailto.append(href.split(":", 1)[1].split("?", 1)[0])
            elif lower.startswith("tel:"):
                self.tel.append(href.split(":", 1)[1])
            else:
                self._link_href = href
                self._link_parts = []
        elif tag == "script":
            self._script = Script(
                values.get("src", "").strip(), values.get("integrity", "").strip()
            )
        elif tag == "iframe":
            src = values.get("src", "").strip()
            if src:
                self.iframes.append(src)
        elif tag == "form":
            self._form = FormInfo(
                values.get("action", "").strip(), values.get("method", "get"), [], ""
            )
            self._form_parts = []
        elif tag == "input" and self._form is not None:
            typ = values.get("type", "text")
            name = values.get("name") or values.get("id") or values.get("placeholder") or ""
            self._form.inputs.append((typ, name))
            if values.get("placeholder"):
                self._form_parts.append(values["placeholder"])
        elif tag == "textarea" and self._form is not None:
            name = values.get("name") or values.get("id") or ""
            self._form.inputs.append(("textarea", name))

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._link_href is not None and self._link_href != "":
            self.links.append((self._link_href, " ".join(self._link_parts).strip()))
            self._link_href = ""
            self._link_parts = []
        elif tag == "script" and self._script is not None:
            self.scripts.append(self._script)
            self._script = None
        elif tag == "form" and self._form is not None:
            self._form.text = " ".join(self._form_parts)
            self.forms.append(self._form)
            self._form = None
            self._form_parts = []

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if not text:
            return
        self._chunks.append(text)
        if self._link_href:
            self._link_parts.append(text)
        if self._script is not None and not self._script.src:
            self._script.body += data
        if self._form is not None:
            self._form_parts.append(text)


def parse_page(url: str, html: str) -> Page:
    parser = _PageParser()
    parser.feed(html[:MAX_HTML_BYTES])
    parser.close()
    return Page(
        url=url,
        lang=parser.lang,
        links=parser.links,
        scripts=parser.scripts,
        iframes=parser.iframes,
        forms=parser.forms,
        mailto=parser.mailto,
        tel=parser.tel,
        text=" ".join(parser._chunks)[:50_000],
        html=html[:MAX_HTML_BYTES],
    )


def _blob(page: Page, cookies: Iterable[str] = ()) -> str:
    """One lowercase string we can search for vendor signatures."""
    parts = [page.html, page.text, *cookies]
    parts += [s.src + " " + s.body for s in page.scripts]
    parts += page.iframes
    parts += [href for href, _ in page.links]
    return "\n".join(parts).lower()


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #
# (name, distinctive substrings). Short generic words are avoided on purpose.
CMPS: list[tuple[str, tuple[str, ...]]] = [
    ("Cookiebot", ("cookiebot.com", "cookiebot", "data-cookieconsent")),
    ("iubenda", ("cdn.iubenda.com", "iubenda.com", "iubenda-cs", "_iub.csconfiguration")),
    ("OneTrust", ("onetrust.com", "cdn.cookielaw.org", "optanonconsent", "onetrust")),
    ("Complianz", ("complianz.io", "cmplz-", "complianz")),
    ("CookieYes", ("cookieyes.com", "cky-consent", "cookieyes")),
    ("Usercentrics", ("usercentrics.eu", "usercentrics.com", "uniconsent", "uc-banner")),
    ("Wix Cookie Banner", ("consent-policy", "wix-consent", "cookie_consent_manager")),
    ("Squarespace Cookie Banner", ("sqs-cookie-banner", "squarespace-cookie-banner")),
]

TRACKERS: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
    # name, html/script markers, cookie-name prefixes
    (
        "Google Analytics or Tag Manager",
        ("google-analytics.com", "googletagmanager.com/gtag", "googletagmanager.com/gtm", "gtag("),
        ("_ga", "_gid", "_gat", "_gcl_au"),
    ),
    (
        "Meta Pixel",
        ("connect.facebook.net", "fbevents.js", "fbq("),
        ("_fbp", "_fbc"),
    ),
    (
        "TikTok Pixel",
        ("analytics.tiktok.com", "ttq("),
        ("_ttp", "ttcsid"),
    ),
    (
        "Hotjar",
        ("static.hotjar.com", "hotjar.com/c/", "hj("),
        ("_hj",),
    ),
]

# Booking / ordering / delivery widgets. Patterns must be distinctive.
WIDGETS: list[tuple[str, tuple[str, ...]]] = [
    ("TheFork", ("widget.thefork", "thefork.com", "theforkcdn", "lafourchette.com")),
    ("OpenTable", ("opentable.com", "www.opentable.", "//opentable.")),
    ("Resy", ("widgets.resy.com", "resy.com/embed", "//resy.com")),
    ("Quandoo", ("quandoo.com", "quandoo.")),
    ("SevenRooms", ("sevenrooms.com", "sevenrooms.")),
    ("Google Reserve", ("maps.google.com/maps/reserve", "restaurant-reservations")),
    ("Just Eat", ("just-eat.", "justeat.")),
    ("Deliveroo", ("deliveroo.",)),
    ("Glovo", ("glovoapp.com", "//glovo.")),
    ("Uber Eats", ("ubereats.com", "uber.com/eats")),
    (
        "Wix Bookings / Restaurants",
        ("bookings.wix", "calendar.wix", "wixrestaurants", "wix.com/bookings"),
    ),
]

_MAPS = ("maps.google.", "google.com/maps", "maps.googleapis.com", "maps.gstatic.com")


def _cookie_names(set_cookies: Iterable[str]) -> list[str]:
    return [h.split("=", 1)[0].strip() for h in set_cookies if "=" in h]


def _found(blob: str, markers: Iterable[str]) -> list[str]:
    return [m for m in markers if m.lower() in blob]


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def detect_cmps(blob: str) -> list[str]:
    return [name for name, markers in CMPS if _found(blob, markers)]


def detect_trackers(blob: str, cookie_names: Iterable[str]) -> list[str]:
    found = []
    cookies = [c.lower() for c in cookie_names]
    for name, markers, prefixes in TRACKERS:
        html_hit = bool(_found(blob, markers))
        cookie_hit = any(c.startswith(p.lower()) for c in cookies for p in prefixes)
        if html_hit or cookie_hit:
            found.append(name)
    return found


def check_cookie_consent(page: Page, set_cookies: Iterable[str]) -> Finding:
    blob = _blob(page, set_cookies)
    cmps = detect_cmps(blob)
    trackers = detect_trackers(blob, _cookie_names(set_cookies))
    title = "Cookie consent banner"
    if cmps and trackers:
        return _finding(
            "cookie-consent",
            title,
            Status.INFO,
            f"Found {', '.join(cmps)}. Tracking also present in the first response "
            f"({', '.join(trackers)}); load order was not verified (this is a first-page "
            "check, not a live browser).",
        )
    if cmps:
        return _finding(
            "cookie-consent",
            title,
            Status.PASS,
            f"Found a known consent platform: {', '.join(cmps)}.",
        )
    if trackers:
        return _finding(
            "cookie-consent",
            title,
            Status.WARN,
            f"Likely loading {', '.join(trackers)} on the first page response, with no "
            "known consent banner (Cookiebot, iubenda, OneTrust, Complianz, CookieYes, "
            "Usercentrics, or a Wix/Squarespace banner). If these are analytics or ads "
            "cookies, visitors in the EU typically need to opt in first.",
            recommendation="Add a cookie consent banner and block analytics/ads until the "
            "visitor agrees. This is not legal advice.",
            deduction=20,
        )
    return _finding(
        "cookie-consent",
        title,
        Status.INFO,
        "No known consent banner or tracking scripts were found on the first page. "
        "If you later add analytics or ads, put a consent banner in place first.",
    )


def _link_looks_like_policy(href: str, text: str) -> bool:
    hay = f"{href} {text}".lower().replace("_", "-")
    return any(word in hay for word in _PRIVACY_WORDS)


def _page_looks_like_policy(page: Page) -> bool:
    hay = (page.text + " " + page.html)[:20_000].lower()
    return any(
        word in hay
        for word in (
            "privacy policy",
            "informativa sulla privacy",
            "informativa privacy",
            "personal data",
            "dati personali",
            "datenschutz",
            "cookie policy",
        )
    )


def _fetch_same_site(client: httpx.Client, base: str, path: str) -> Page | None:
    url = urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))
    origin = urlsplit(base)
    target = urlsplit(url)
    if target.scheme != "https" or target.netloc != origin.netloc:
        return None
    try:
        response = client.get(url, follow_redirects=True)
    except httpx.HTTPError:
        return None
    # Stay on the same site even after redirects.
    if urlsplit(str(response.url)).netloc != origin.netloc:
        return None
    if "html" not in response.headers.get("content-type", "").lower():
        return None
    if not response.is_success:
        return None
    return parse_page(str(response.url), response.text)


def check_privacy_policy(page: Page, client: httpx.Client | None = None) -> Finding:
    title = "Privacy / cookie policy"
    matches = [(href, text) for href, text in page.links if _link_looks_like_policy(href, text)]
    if matches:
        href, text = matches[0]
        label = text or href
        return _finding(
            "privacy-policy",
            title,
            Status.PASS,
            f"Homepage links to a privacy or cookie policy ({label}).",
        )
    # No link on the homepage: try a few well-known paths.
    if client is not None:
        for path in _PRIVACY_PATHS:
            fetched = _fetch_same_site(client, page.url, path)
            if fetched and _page_looks_like_policy(fetched):
                return _finding(
                    "privacy-policy",
                    title,
                    Status.WARN,
                    f"A policy-like page exists at {fetched.url}, but the homepage does "
                    "not link to it. Add a clear footer link so visitors can find it.",
                    recommendation="Link 'Privacy policy' (or 'Informativa sulla privacy') "
                    "in the site footer and, if you use cookies, in the consent banner.",
                    deduction=5,
                )
    return _finding(
        "privacy-policy",
        title,
        Status.WARN,
        "No privacy or cookie policy link was found on the homepage (looked for "
        "'privacy', 'informativa', 'cookie policy', 'datenschutz', 'confidentialité', "
        "'política de privacidad').",
        recommendation="Publish a privacy policy and link it in the footer. This is not "
        "legal advice; a lawyer or your platform's template can help you write one.",
        deduction=15,
    )


def looks_italian(page: Page) -> bool:
    if page.lang.lower().startswith("it"):
        return True
    hay = (page.text + " " + page.html)[:20_000].lower()
    return sum(1 for cue in _ITALIAN_CUES if cue in hay) >= 2


def check_vat_number(page: Page) -> Finding:
    title = "VAT / Partita IVA"
    hay = page.text + "\n" + page.html[:20_000]
    match = _VAT_LABEL.search(hay) or _VAT_IT.search(hay)
    if match:
        # Show only that an 11-digit number was found, not the number itself
        # (no need to republish a tax ID in scan reports).
        return _finding(
            "vat-number",
            title,
            Status.PASS,
            "A VAT / Partita IVA number (11 digits, optional IT prefix) is visible.",
        )
    italian = looks_italian(page)
    detail = (
        "No Partita IVA / VAT number was found (looked for P.IVA, Partita IVA or VAT "
        "followed by 11 digits, or IT plus 11 digits)."
    )
    if italian:
        return _finding(
            "vat-number",
            title,
            Status.WARN,
            detail + " Italian businesses are generally required to show their P.IVA "
            "on the site. This is not legal advice.",
            recommendation="Add the Partita IVA (and legal name / registered office) in "
            "the footer, next to the other legal links.",
            deduction=5,
        )
    return _finding(
        "vat-number",
        title,
        Status.INFO,
        detail + " If this is an Italian business, the P.IVA should appear on the site.",
    )


def _resolved_action(page_url: str, action: str) -> str:
    if not action or action.startswith("#") or action.lower().startswith("javascript:"):
        return page_url
    if action.lower().startswith("mailto:") or action.lower().startswith("tel:"):
        return action
    return urljoin(page_url, action)


def check_form_https(page: Page) -> Finding:
    title = "Form transport"
    page_scheme = urlsplit(page.url).scheme
    if not page.forms:
        return _finding("form-https", title, Status.INFO, "No <form> elements on the homepage.")
    problems = []
    for form in page.forms:
        target = _resolved_action(page.url, form.action)
        scheme = urlsplit(target).scheme.lower()
        has_password = any(t.lower() == "password" for t, _ in form.inputs)
        if scheme == "http":
            problems.append(f"a form posts to a plain HTTP address ({target})")
        if has_password and (scheme == "http" or page_scheme == "http"):
            problems.append("a password field is submitted over plain HTTP")
    if problems:
        # Deduplicate while keeping order.
        unique = list(dict.fromkeys(problems))
        return _finding(
            "form-https",
            title,
            Status.FAIL,
            "Insecure form: " + "; ".join(unique) + ".",
            recommendation="Serve the site over HTTPS and point every form action at an "
            "https:// URL (a blank or relative action on an HTTPS page is fine).",
            deduction=20,
        )
    return _finding(
        "form-https",
        title,
        Status.PASS,
        f"{len(page.forms)} form(s) on the homepage submit over HTTPS (or a relative action).",
    )


def _collects_email(form: FormInfo) -> bool:
    for typ, name in form.inputs:
        if typ.lower() == "email" or _EMAIL_FIELD.search(name):
            return True
    return bool(_EMAIL_FIELD.search(form.text))


def check_form_consent(page: Page) -> Finding:
    title = "Form privacy notice"
    email_forms = [f for f in page.forms if _collects_email(f)]
    if not email_forms:
        return _finding(
            "form-consent",
            title,
            Status.INFO,
            "No homepage form that obviously collects an email address.",
        )
    missing = [f for f in email_forms if not _FORM_CONSENT.search(f.text)]
    if missing:
        return _finding(
            "form-consent",
            title,
            Status.INFO,
            f"{len(missing)} form(s) collect an email address with no nearby privacy or "
            "consent wording (looked for privacy, informativa, consenso, GDPR, accetto). "
            "This is a hint, not a legal conclusion.",
            recommendation="Add a short note and a privacy-policy link next to the email "
            "field, and only use the address for the purpose you describe.",
        )
    return _finding(
        "form-consent",
        title,
        Status.PASS,
        "Email form(s) mention privacy or consent next to the fields.",
    )


# Extra tokens used only after a widget is already identified, so we also
# catch unofficial copies of the script (for the HTTPS / SRI notes).
_WIDGET_TOKENS: dict[str, tuple[str, ...]] = {
    "TheFork": ("thefork", "lafourchette"),
    "OpenTable": ("opentable",),
    "Resy": ("resy",),
    "Quandoo": ("quandoo",),
    "SevenRooms": ("sevenrooms",),
    "Just Eat": ("just-eat", "justeat"),
    "Deliveroo": ("deliveroo",),
    "Glovo": ("glovo",),
    "Uber Eats": ("ubereats",),
    "Wix Bookings / Restaurants": ("wixrestaurants", "bookings.wix"),
    "Google Reserve": ("maps/reserve",),
}


def _urls_matching(page: Page, needles: tuple[str, ...]) -> list[str]:
    urls: list[str] = []
    for script in page.scripts:
        if script.src and any(m in script.src.lower() for m in needles):
            urls.append(script.src)
    for src in page.iframes:
        if any(m in src.lower() for m in needles):
            urls.append(src)
    for href, _ in page.links:
        if any(m in href.lower() for m in needles):
            urls.append(href)
    return urls


def detect_widgets(page: Page) -> list[tuple[str, list[str]]]:
    blob = _blob(page)
    found = []
    for name, markers in WIDGETS:
        if not any(m in blob for m in markers):
            continue
        urls = _urls_matching(page, markers)
        tokens = _WIDGET_TOKENS.get(name, ())
        if tokens:
            for extra in _urls_matching(page, tokens):
                if extra not in urls:
                    urls.append(extra)
        found.append((name, urls))
    return found


_VENDOR_HOSTS = (
    "thefork",
    "opentable",
    "resy",
    "quandoo",
    "sevenrooms",
    "just-eat",
    "justeat",
    "deliveroo",
    "glovo",
    "ubereats",
    "wix",
)


def _unknown_cdn_scripts(page: Page, widget_urls: list[str]) -> list[str]:
    """Widget scripts served from an unexpected host and missing SRI."""
    notes = []
    for url in widget_urls:
        if ".js" not in url.lower():
            continue
        script = next((s for s in page.scripts if s.src == url), None)
        if script is None or script.integrity:
            continue
        host = (urlsplit(urljoin(page.url, url)).hostname or "").lower()
        if host and not any(token in host for token in _VENDOR_HOSTS):
            notes.append(url)
    return notes


def check_booking_widgets(page: Page) -> Finding:
    title = "Booking and ordering widgets"
    found = detect_widgets(page)
    if not found:
        return _finding(
            "booking-widgets",
            title,
            Status.INFO,
            "No known booking or delivery widgets were found (TheFork, OpenTable, Resy, "
            "Quandoo, SevenRooms, Google Reserve, Just Eat, Deliveroo, Glovo, Uber Eats, "
            "Wix Bookings).",
        )
    names = [name for name, _ in found]
    inventory = "Your booking or ordering runs on " + ", ".join(names) + "."
    insecure = []
    all_urls = []
    for _name, urls in found:
        for url in urls:
            all_urls.append(url)
            scheme = urlsplit(urljoin(page.url, url)).scheme.lower()
            if scheme == "http":
                insecure.append(url)
    if insecure:
        return _finding(
            "booking-widgets",
            title,
            Status.FAIL,
            inventory + " At least one widget loads over plain HTTP: " + ", ".join(insecure) + ".",
            recommendation="Switch the widget embed to its official https:// snippet.",
            deduction=20,
        )
    sri = _unknown_cdn_scripts(page, all_urls)
    detail = inventory + " All detected embeds use HTTPS."
    if sri:
        detail += (
            " A widget script is loaded from an unexpected host without Subresource "
            f"Integrity: {', '.join(sri)}. Prefer the official embed, or add an integrity "
            "attribute if the vendor publishes one."
        )
    return _finding("booking-widgets", title, Status.PASS, detail)


def check_contact_links(page: Page) -> Finding | None:
    if not page.mailto and not page.tel:
        return None
    parts = []
    if page.tel:
        parts.append(f"{len(page.tel)} telephone link(s)")
    if page.mailto:
        parts.append(f"{len(page.mailto)} email link(s)")
    return _finding(
        "contact-links",
        "Contact links",
        Status.INFO,
        "Homepage exposes " + " and ".join(parts) + ". That is normal for a restaurant.",
    )


def check_google_maps(page: Page) -> Finding | None:
    urls = []
    for src in [*page.iframes, *[s.src for s in page.scripts], *[h for h, _ in page.links]]:
        low = src.lower()
        if any(m in low for m in _MAPS):
            urls.append(src)
    if not urls:
        return None
    insecure = [u for u in urls if urlsplit(urljoin(page.url, u)).scheme == "http"]
    if insecure:
        return _finding(
            "google-maps",
            "Google Maps embed",
            Status.WARN,
            "A Google Maps embed is loaded over plain HTTP.",
            recommendation="Use the official https://www.google.com/maps/embed URL.",
            deduction=10,
        )
    return _finding(
        "google-maps",
        "Google Maps embed",
        Status.PASS,
        "Google Maps is embedded over HTTPS.",
    )


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def check_restaurant(
    url: str,
    html: str,
    set_cookies: Iterable[str] = (),
    *,
    client: httpx.Client | None = None,
) -> list[Finding]:
    """Run every restaurant / privacy check on one already-fetched homepage."""
    page = parse_page(url, html)
    findings = [
        check_cookie_consent(page, set_cookies),
        check_privacy_policy(page, client),
        check_vat_number(page),
        check_form_https(page),
        check_form_consent(page),
        check_booking_widgets(page),
    ]
    for extra in (check_contact_links(page), check_google_maps(page)):
        if extra is not None:
            findings.append(extra)
    return findings


@dataclass
class Compliance:
    """The restaurant/privacy score, kept separate from the security grade."""

    score: int
    grade: str
    passed: int = 0
    warnings: int = 0
    failed: int = 0
    info: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        return f"{self.grade} {self.score}/100"

    @classmethod
    def from_findings(cls, findings, score: int, grade_for) -> Compliance:
        restaurant = [f for f in findings if f.category == Category.RESTAURANT]
        counts = {status: sum(f.status == status for f in restaurant) for status in Status}
        return cls(
            score=score,
            grade=grade_for(score, restaurant),
            passed=counts[Status.PASS],
            warnings=counts[Status.WARN],
            failed=counts[Status.FAIL],
            info=counts[Status.INFO],
        )
