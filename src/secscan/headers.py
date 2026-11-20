"""HTTP security header checks.

Every function here is *pure*: it receives a mapping of response headers and
returns a list of :class:`Finding` objects. No network access happens in this
module, which makes the logic easy to read and easy to unit test.

Header names are case-insensitive in HTTP, so callers should pass something
like ``httpx.Headers`` or a dict with lower-cased keys.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from secscan.models import Category, Finding, Status

# Browsers only enforce HSTS for as long as max-age says. Six months is the
# commonly recommended minimum; one year (31536000) is required for preload.
HSTS_MIN_MAX_AGE = 15_552_000  # 180 days in seconds

# Referrer policies that may leak full URLs (including paths/query strings)
# to other sites.
UNSAFE_REFERRER_POLICIES = {"unsafe-url", "no-referrer-when-downgrade"}


def _get(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _finding(check_id: str, title: str, status: Status, detail: str, **kw) -> Finding:
    return Finding(check_id, title, Category.HEADERS, status, detail, **kw)


# --------------------------------------------------------------------------- #
# Strict-Transport-Security (HSTS)
# --------------------------------------------------------------------------- #
def check_hsts(headers: Mapping[str, str]) -> Finding:
    """HSTS tells browsers "only ever talk to me over HTTPS".

    Without it, the very first plain-HTTP request can be intercepted and the
    user silently downgraded (an "SSL stripping" attack).
    """
    value = _get(headers, "Strict-Transport-Security")
    title = "Strict-Transport-Security"
    fix = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    if value is None:
        return _finding(
            "hsts",
            title,
            Status.FAIL,
            "Header missing: browsers may use plain HTTP.",
            recommendation=fix,
            deduction=20,
        )

    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    if not match:
        return _finding(
            "hsts",
            title,
            Status.FAIL,
            f"No valid max-age directive: {value!r}",
            recommendation=fix,
            deduction=20,
        )

    max_age = int(match.group(1))
    if max_age == 0:
        return _finding(
            "hsts", title, Status.FAIL, "max-age=0 disables HSTS.", recommendation=fix, deduction=20
        )
    if max_age < HSTS_MIN_MAX_AGE:
        return _finding(
            "hsts",
            title,
            Status.WARN,
            f"max-age={max_age} is shorter than 180 days.",
            recommendation=fix,
            deduction=5,
        )

    extras = [d for d in ("includeSubDomains", "preload") if d.lower() in value.lower()]
    detail = f"max-age={max_age}" + (f" ({', '.join(extras)})" if extras else "")
    return _finding("hsts", title, Status.PASS, detail)


# --------------------------------------------------------------------------- #
# Content-Security-Policy (CSP)
# --------------------------------------------------------------------------- #
def parse_csp(value: str) -> dict[str, list[str]]:
    """Turn "default-src 'self'; img-src *" into {"default-src": ["'self'"], ...}."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            # The first occurrence of a directive wins, as in browsers.
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def check_csp(headers: Mapping[str, str]) -> Finding:
    """CSP is an allow-list of where scripts, styles, frames... may load from.

    It is the main browser-side defence against Cross-Site Scripting (XSS).
    A policy that allows 'unsafe-inline' scripts largely defeats that purpose.
    """
    value = _get(headers, "Content-Security-Policy")
    title = "Content-Security-Policy"
    if value is None:
        return _finding(
            "csp",
            title,
            Status.FAIL,
            "Header missing: no browser-side XSS mitigation.",
            recommendation="Start with: Content-Security-Policy: default-src 'self'; "
            "object-src 'none'; frame-ancestors 'self' and tighten from there.",
            deduction=20,
        )

    directives = parse_csp(value)
    # script-src falls back to default-src when it is not set.
    script_sources = directives.get("script-src", directives.get("default-src"))
    problems: list[str] = []
    deduction = 0

    if script_sources is None:
        problems.append("no script-src or default-src, so scripts are unrestricted")
        deduction += 10
    else:
        has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha")) for s in script_sources)
        # Browsers ignore 'unsafe-inline' when a nonce or hash is present (CSP2+).
        if "'unsafe-inline'" in script_sources and not has_nonce_or_hash:
            problems.append("scripts allow 'unsafe-inline'")
            deduction += 10
        if "'unsafe-eval'" in script_sources:
            problems.append("scripts allow 'unsafe-eval'")
            deduction += 5
        if "*" in script_sources or "https:" in script_sources:
            problems.append("scripts may load from any host")
            deduction += 5

    if problems:
        return _finding(
            "csp",
            title,
            Status.WARN,
            "Policy present but weak: " + "; ".join(problems),
            recommendation="Remove 'unsafe-inline'/'unsafe-eval' and wildcards; "
            "use nonces or hashes for inline scripts.",
            deduction=deduction,
        )
    return _finding("csp", title, Status.PASS, f"Policy present ({len(directives)} directives).")


# --------------------------------------------------------------------------- #
# Clickjacking: X-Frame-Options or CSP frame-ancestors
# --------------------------------------------------------------------------- #
def check_framing(headers: Mapping[str, str]) -> Finding:
    """Stop other sites from loading this page in an invisible <iframe>.

    "Clickjacking" tricks a user into clicking buttons on a framed page they
    cannot see. CSP frame-ancestors is the modern control; X-Frame-Options is
    the legacy one. Either is enough.
    """
    title = "Clickjacking protection"
    csp = _get(headers, "Content-Security-Policy")
    if csp and "frame-ancestors" in parse_csp(csp):
        sources = " ".join(parse_csp(csp)["frame-ancestors"])
        if "*" in sources.split():
            return _finding(
                "framing",
                title,
                Status.WARN,
                "frame-ancestors allows any site (*).",
                recommendation="Use frame-ancestors 'self' or 'none'.",
                deduction=10,
            )
        return _finding("framing", title, Status.PASS, f"CSP frame-ancestors {sources}")

    xfo = _get(headers, "X-Frame-Options")
    if xfo and xfo.strip().upper() in {"DENY", "SAMEORIGIN"}:
        return _finding("framing", title, Status.PASS, f"X-Frame-Options: {xfo.strip()}")
    if xfo:
        return _finding(
            "framing",
            title,
            Status.WARN,
            f"Unrecognised X-Frame-Options value {xfo!r}.",
            recommendation="Use X-Frame-Options: DENY (or SAMEORIGIN).",
            deduction=10,
        )
    return _finding(
        "framing",
        title,
        Status.FAIL,
        "Neither X-Frame-Options nor CSP frame-ancestors is set.",
        recommendation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        deduction=15,
    )


# --------------------------------------------------------------------------- #
# X-Content-Type-Options
# --------------------------------------------------------------------------- #
def check_content_type_options(headers: Mapping[str, str]) -> Finding:
    """Disable MIME sniffing.

    Without "nosniff", a browser may guess that an uploaded .txt file is really
    HTML or JavaScript and execute it.
    """
    value = _get(headers, "X-Content-Type-Options")
    title = "X-Content-Type-Options"
    if value and value.strip().lower() == "nosniff":
        return _finding("xcto", title, Status.PASS, "nosniff")
    return _finding(
        "xcto",
        title,
        Status.FAIL,
        "Missing or invalid: browsers may MIME-sniff responses.",
        recommendation="Add: X-Content-Type-Options: nosniff",
        deduction=10,
    )


# --------------------------------------------------------------------------- #
# Referrer-Policy
# --------------------------------------------------------------------------- #
def check_referrer_policy(headers: Mapping[str, str]) -> Finding:
    """Control how much of the current URL is sent to other sites.

    URLs often contain secrets (reset tokens, search terms, IDs). The policy
    decides whether those leak through the Referer header.
    """
    value = _get(headers, "Referrer-Policy")
    title = "Referrer-Policy"
    fix = "Add: Referrer-Policy: strict-origin-when-cross-origin"
    if value is None:
        # Modern browsers default to strict-origin-when-cross-origin, so this is
        # a small deduction: you are relying on the browser's default.
        return _finding(
            "referrer",
            title,
            Status.WARN,
            "Header missing (browser default applies).",
            recommendation=fix,
            deduction=5,
        )
    # Several comma-separated values are allowed; the last supported one wins.
    effective = value.split(",")[-1].strip().lower()
    if effective in UNSAFE_REFERRER_POLICIES:
        return _finding(
            "referrer",
            title,
            Status.FAIL,
            f"{effective} can leak full URLs.",
            recommendation=fix,
            deduction=10,
        )
    return _finding("referrer", title, Status.PASS, effective)


# --------------------------------------------------------------------------- #
# Permissions-Policy
# --------------------------------------------------------------------------- #
def check_permissions_policy(headers: Mapping[str, str]) -> Finding:
    """Switch off powerful browser features (camera, microphone, geolocation...)
    that the site does not need, so injected or third-party code cannot use them.
    """
    value = _get(headers, "Permissions-Policy")
    title = "Permissions-Policy"
    if value is None:
        return _finding(
            "permissions",
            title,
            Status.WARN,
            "Header missing.",
            recommendation="Add e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            deduction=5,
        )
    return _finding(
        "permissions", title, Status.PASS, f"{len(value.split(','))} feature(s) restricted."
    )


# --------------------------------------------------------------------------- #
# Information leakage
# --------------------------------------------------------------------------- #
_VERSION_RE = re.compile(r"\d+(\.\d+)+|/\d")


def check_info_leak(headers: Mapping[str, str]) -> list[Finding]:
    """Headers that advertise software and versions help attackers pick exploits.

    "Server: nginx" is harmless; "Server: Apache/2.4.29 (Ubuntu)" tells an
    attacker exactly which CVEs to try.
    """
    findings: list[Finding] = []

    server = _get(headers, "Server")
    if server and _VERSION_RE.search(server):
        findings.append(
            _finding(
                "server",
                "Server header",
                Status.WARN,
                f"Discloses version: {server!r}",
                recommendation="Hide the version (e.g. nginx: server_tokens off; "
                "Apache: ServerTokens Prod).",
                deduction=5,
            )
        )
    elif server:
        findings.append(
            _finding("server", "Server header", Status.INFO, f"{server!r} (no version disclosed)")
        )

    powered = _get(headers, "X-Powered-By")
    if powered:
        findings.append(
            _finding(
                "powered-by",
                "X-Powered-By",
                Status.WARN,
                f"Discloses technology: {powered!r}",
                recommendation="Remove the X-Powered-By header.",
                deduction=5,
            )
        )
    return findings


def check_all(headers: Mapping[str, str]) -> list[Finding]:
    """Run every header check and return the findings in a stable order."""
    return [
        check_hsts(headers),
        check_csp(headers),
        check_framing(headers),
        check_content_type_options(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
        *check_info_leak(headers),
    ]
