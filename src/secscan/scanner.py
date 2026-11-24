"""Orchestrates one scan: fetch the page, run every check, grade.

Requests made per target (all ordinary requests a browser would make):

1. GET the HTTPS page (headers, cookies, HTML for mixed content)
2. GET the same page again with an Origin header (CORS)
3. GET /.well-known/security.txt
4. GET http://host/ to confirm the redirect to HTTPS
5. A few TLS handshakes (certificate and protocol versions)
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from secscan import __version__
from secscan.advice import attach_advice
from secscan.cookies import check_cookies
from secscan.cors import PROBE_ORIGIN, check_cors
from secscan.grading import grade_for, score_compliance, score_findings
from secscan.headers import check_all
from secscan.mixedcontent import check_mixed_content
from secscan.models import Category, Finding, ScanResult, Status, TLSInfo
from secscan.platforms import (
    Detection,
    detect_platforms,
    detection_for,
    extract_meta,
    tag_findings,
    your_part,
)
from secscan.restaurant import Compliance, check_restaurant
from secscan.securitytxt import PATH as SECURITY_TXT_PATH
from secscan.securitytxt import check_security_txt
from secscan.tls import create_verified_context, evaluate_tls, probe_tls

USER_AGENT = f"secscan/{__version__} (+https://github.com/hunter1on1/secscan)"

# Order in which categories appear in reports.
CATEGORY_ORDER = [
    Category.HEADERS,
    Category.COOKIES,
    Category.CORS,
    Category.CONTENT,
    Category.DISCLOSURE,
    Category.TLS,
    Category.RESTAURANT,
]

# Called as probe(host, port, timeout, ca_bundle=...); see tls.probe_tls.
TLSProbe = Callable[..., TLSInfo]


class TargetError(ValueError):
    """Raised for input that is not a usable http(s) URL."""


def normalize_target(raw: str) -> tuple[str, str, int]:
    """Return (https_url, host, port) for user input like "example.com".

    We always scan the HTTPS version of the site; plain HTTP is only used to
    check that it redirects to HTTPS.
    """
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise TargetError(f"Not a valid http(s) URL: {raw!r}")
    host = parts.hostname
    # Keep an explicit port only if it was given for HTTPS.
    port = parts.port if (parts.scheme == "https" and parts.port) else 443
    netloc = host if port == 443 else f"{host}:{port}"
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"https://{netloc}{path}{query}", host, port


def check_https_redirect(client: httpx.Client, host: str) -> Finding:
    """Does http://host end up on an https:// URL?"""
    title = "HTTP -> HTTPS redirect"
    try:
        response = client.get(f"http://{host}/", follow_redirects=True)
    except httpx.HTTPError:
        return Finding(
            "https-redirect",
            title,
            Category.TLS,
            Status.INFO,
            "Plain HTTP (port 80) is not served.",
        )
    if response.url.scheme == "https":
        return Finding(
            "https-redirect", title, Category.TLS, Status.PASS, f"Redirects to {response.url}"
        )
    if not response.is_success:
        # An error page is not "serving content over HTTP", but we also could
        # not confirm a redirect, so report it without changing the score.
        return Finding(
            "https-redirect",
            title,
            Category.TLS,
            Status.INFO,
            f"Plain HTTP answered with status {response.status_code}; redirect not confirmed.",
        )
    return Finding(
        "https-redirect",
        title,
        Category.TLS,
        Status.FAIL,
        "Plain HTTP is served without redirecting to HTTPS.",
        recommendation="Redirect all HTTP traffic to HTTPS with a 301.",
        deduction=10,
    )


def check_page_content(response: httpx.Response) -> Finding:
    """Mixed-content check on the HTML of the final HTTPS page."""
    content_type = response.headers.get("content-type", "")
    if "html" not in content_type.lower():
        return Finding(
            "mixed-content",
            "Mixed content",
            Category.CONTENT,
            Status.INFO,
            f"Not an HTML page ({content_type or 'no content type'}); skipped.",
        )
    return check_mixed_content(response.text, response.headers.get("content-security-policy"))


def check_cors_policy(client: httpx.Client, url: str) -> Finding:
    """Send the request a browser would send for a cross-origin fetch."""
    try:
        response = client.get(url, headers={"Origin": PROBE_ORIGIN}, follow_redirects=True)
    except httpx.HTTPError as exc:
        return Finding(
            "cors", "CORS policy", Category.CORS, Status.INFO, f"CORS request failed: {exc}"
        )
    return check_cors(response.headers, PROBE_ORIGIN)


def fetch_security_txt(client: httpx.Client, base_url: str) -> Finding:
    parts = urlsplit(base_url)
    try:
        response = client.get(
            f"{parts.scheme}://{parts.netloc}{SECURITY_TXT_PATH}", follow_redirects=True
        )
    except httpx.HTTPError:
        return check_security_txt(None, "", "")
    return check_security_txt(
        response.status_code, response.headers.get("content-type", ""), response.text
    )


def scan(
    target: str,
    *,
    client: httpx.Client | None = None,
    tls_probe: TLSProbe | None = probe_tls,
    timeout: float = 10.0,
    ca_bundle: str | None = None,
    platform: str | None = None,
    detect: bool = True,
    profile: str | None = None,
) -> ScanResult:
    """Scan one target and return a graded :class:`ScanResult`.

    `client` and `tls_probe` can be injected, which is how the tests run the
    whole pipeline without touching the network. Pass ``tls_probe=None`` to
    skip the TLS checks. `ca_bundle` overrides the trusted CA file (default:
    SSL_CERT_FILE if set, otherwise certifi's bundle).

    `platform` forces a hosting platform id (see platforms.PLATFORMS) instead
    of detecting it; ``detect=False`` skips detection entirely.

    ``profile="restaurant"`` adds privacy and booking checks and a separate
    compliance score; the security grade is unchanged.
    """
    result = ScanResult(target=target, profile=profile)
    if platform is not None:
        result.platforms = [detection_for(platform)]
    try:
        url, host, port = normalize_target(target)
    except TargetError as exc:
        result.error = str(exc)
        return result

    own_client = client is None
    client = client or httpx.Client(
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        # Same trust store as the TLS checks, so both always agree.
        verify=create_verified_context(ca_bundle),
    )
    try:
        # 1. Fetch the HTTPS page and check its headers.
        try:
            response = client.get(url, follow_redirects=True)
            result.final_url = str(response.url)
            result.status_code = response.status_code
            if response.url.scheme == "http":
                result.findings.append(
                    Finding(
                        "https-downgrade",
                        "HTTPS -> HTTP downgrade",
                        Category.TLS,
                        Status.FAIL,
                        f"The HTTPS page redirects to plain HTTP ({response.url}); visitors "
                        "end up on an unencrypted page. Header results below describe that "
                        "HTTP response.",
                        recommendation="Keep every redirect on https://.",
                        deduction=20,
                    )
                )
            is_html = "html" in response.headers.get("content-type", "").lower()
            html = response.text if is_html else ""
            meta, _ = extract_meta(html) if html else ({}, set())
            result.findings.extend(check_all(response.headers, meta.get("referrer")))

            # Cookies may be set on any hop of a redirect chain, not just the
            # final page, so collect Set-Cookie from every response.
            set_cookies = [
                value
                for r in (*response.history, response)
                for value in r.headers.get_list("set-cookie")
            ]
            if platform is None and detect:
                result.platforms = detect_platforms(
                    response.url.host, response.headers, set_cookies, html
                )
            result.findings.extend(check_cookies(set_cookies))
            result.findings.append(check_cors_policy(client, result.final_url))
            result.findings.append(check_page_content(response))
            result.findings.append(fetch_security_txt(client, result.final_url))
            if profile == "restaurant" and html:
                result.findings.extend(
                    check_restaurant(result.final_url, html, set_cookies, client=client)
                )
        except httpx.HTTPError as exc:
            result.error = f"HTTPS request failed: {exc}"

        # 2. HTTP -> HTTPS redirect (only meaningful for the default port).
        if port == 443:
            result.findings.append(check_https_redirect(client, host))
    finally:
        if own_client:
            client.close()

    # 3. Certificate and protocol versions.
    if tls_probe is not None:
        result.tls = tls_probe(host, port, timeout, ca_bundle=ca_bundle)
        result.findings.extend(evaluate_tls(result.tls))

    # Group findings by category (sorted() is stable, so order within a
    # category is preserved) and attach fix advice to WARN/FAIL findings.
    result.findings.sort(key=lambda f: CATEGORY_ORDER.index(f.category))
    attach_advice(result.findings)
    detections: list[Detection] = result.platforms
    tag_findings(result.findings, detections)
    result.your_part = your_part(result.findings, detections)

    result.score = score_findings(result.findings)
    result.grade = grade_for(result.score, result.findings)
    if profile == "restaurant":
        result.compliance = Compliance.from_findings(
            result.findings, score_compliance(result.findings), grade_for
        )
    if result.error and not result.status_code:
        # We could not read any headers, so a score would be misleading.
        result.score = 0
        result.grade = "F"
    return result
