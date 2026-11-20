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


def make_client(https_headers: dict, http_redirects: bool = True) -> httpx.Client:
    """A client whose "network" is a function: no real requests are made."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            if http_redirects:
                return httpx.Response(
                    301, headers={"Location": str(request.url.copy_with(scheme="https"))}
                )
            return httpx.Response(200, text="plain http")
        return httpx.Response(200, headers=https_headers, text="<html></html>")

    return httpx.Client(transport=httpx.MockTransport(handler))


def good_tls(host: str = "example.com", port: int = 443, timeout: float = 10) -> TLSInfo:
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
