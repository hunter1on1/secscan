"""Orchestrates one scan: fetch the page, run header and TLS checks, grade."""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from secscan import __version__
from secscan.grading import grade_for, score_findings
from secscan.headers import check_all
from secscan.models import Category, Finding, ScanResult, Status, TLSInfo
from secscan.tls import create_verified_context, evaluate_tls, probe_tls

USER_AGENT = f"secscan/{__version__} (+https://github.com/hunter1on1/secscan)"

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


def scan(
    target: str,
    *,
    client: httpx.Client | None = None,
    tls_probe: TLSProbe | None = probe_tls,
    timeout: float = 10.0,
    ca_bundle: str | None = None,
) -> ScanResult:
    """Scan one target and return a graded :class:`ScanResult`.

    `client` and `tls_probe` can be injected, which is how the tests run the
    whole pipeline without touching the network. Pass ``tls_probe=None`` to
    skip the TLS checks. `ca_bundle` overrides the trusted CA file (default:
    SSL_CERT_FILE if set, otherwise certifi's bundle).
    """
    result = ScanResult(target=target)
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
            result.findings.extend(check_all(response.headers))
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

    result.score = score_findings(result.findings)
    result.grade = grade_for(result.score, result.findings)
    if result.error and not result.status_code:
        # We could not read any headers, so a score would be misleading.
        result.score = 0
        result.grade = "F"
    return result
