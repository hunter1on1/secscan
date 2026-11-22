"""Shared fixtures: fake HTTP servers built with httpx.MockTransport."""

from __future__ import annotations

import httpx
import pytest

from secscan.models import CertificateInfo, TLSInfo

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Server": "nginx",
}


VALID_SECURITY_TXT = "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00.000Z\n"


def make_client(
    https_headers: dict,
    http_redirects: bool = True,
    body: str = "<html><body><p>hi</p></body></html>",
    set_cookies: list[str] | None = None,
    security_txt: str | None = VALID_SECURITY_TXT,
    cors_headers: dict | None = None,
) -> httpx.Client:
    """A client whose "network" is a function: no real requests are made.

    * ``/.well-known/security.txt`` returns `security_txt` (404 if None)
    * a request carrying an Origin header gets `cors_headers` added; the
      special value "{origin}" is replaced by the Origin that was sent
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            if http_redirects:
                return httpx.Response(
                    301, headers={"Location": str(request.url.copy_with(scheme="https"))}
                )
            return httpx.Response(200, text="plain http")
        if request.url.path == "/.well-known/security.txt":
            if security_txt is None:
                return httpx.Response(404, text="not found")
            return httpx.Response(
                200, text=security_txt, headers={"Content-Type": "text/plain; charset=utf-8"}
            )
        headers = [("Content-Type", "text/html; charset=utf-8"), *https_headers.items()]
        headers += [("Set-Cookie", c) for c in set_cookies or []]
        origin = request.headers.get("origin")
        if origin and cors_headers:
            headers += [(k, v.replace("{origin}", origin)) for k, v in cors_headers.items()]
        return httpx.Response(200, headers=headers, text=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def good_tls(
    host: str = "example.com", port: int = 443, timeout: float = 10, ca_bundle: str | None = None
) -> TLSInfo:
    return TLSInfo(
        host=host,
        port=port,
        reachable=True,
        negotiated_version="TLSv1.3",
        certificate=CertificateInfo(
            subject="example.com",
            issuer="Let's Encrypt",
            not_after="2030-01-01",
            days_remaining=365,
            valid=True,
        ),
        protocols={"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
    )


@pytest.fixture
def secure_headers() -> dict:
    return dict(SECURE_HEADERS)
