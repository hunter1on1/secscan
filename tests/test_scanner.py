import httpx
import pytest

from secscan.scanner import TargetError, normalize_target, scan

from .conftest import good_tls, make_client


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", ("https://example.com/", "example.com", 443)),
        ("http://example.com/login?x=1", ("https://example.com/login?x=1", "example.com", 443)),
        ("https://example.com:8443/", ("https://example.com:8443/", "example.com", 8443)),
    ],
)
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


def test_normalize_rejects_other_schemes():
    with pytest.raises(TargetError):
        normalize_target("ftp://example.com")


def test_secure_site_gets_a_plus(secure_headers):
    result = scan("example.com", client=make_client(secure_headers), tls_probe=good_tls)
    assert result.grade == "A+"
    assert result.score == 100
    assert result.status_code == 200


def test_bare_site_gets_f():
    result = scan(
        "example.com",
        client=make_client({"X-Powered-By": "Express"}, http_redirects=False),
        tls_probe=good_tls,
    )
    # 20 HSTS + 20 CSP + 15 framing + 10 nosniff + 5 referrer + 5 permissions
    # + 5 powered-by + 10 no redirect = 90 points lost
    assert result.score == 10
    assert result.grade == "F"
    redirect = next(f for f in result.findings if f.check_id == "https-redirect")
    assert redirect.deduction == 10


def test_unreachable_site_is_graded_f():
    def handler(request):
        raise httpx.ConnectError("no route", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = scan("down.example", client=client, tls_probe=None)
    assert result.grade == "F" and result.score == 0
    assert "failed" in result.error


def test_invalid_target_reports_error():
    result = scan("ftp://nope", tls_probe=None)
    assert result.error and result.grade == "F"


def test_json_roundtrip(secure_headers):
    result = scan("example.com", client=make_client(secure_headers), tls_probe=good_tls)
    data = result.to_dict()
    assert data["grade"] == "A+"
    assert data["tls"]["certificate"]["issuer"] == "Let's Encrypt"
    assert {"check_id", "status", "recommendation"} <= set(data["findings"][0])


def test_http_error_page_is_not_counted_as_insecure(secure_headers):
    def handler(request):
        if request.url.scheme == "http":
            return httpx.Response(500)
        return httpx.Response(200, headers=secure_headers)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = scan("example.com", client=client, tls_probe=good_tls)
    redirect = next(f for f in result.findings if f.check_id == "https-redirect")
    assert redirect.status.value == "info" and redirect.deduction == 0
    assert result.grade == "A+"


def test_ca_bundle_is_passed_to_tls_probe(secure_headers):
    seen = {}

    def probe(host, port, timeout, ca_bundle=None):
        seen["ca_bundle"] = ca_bundle
        return good_tls(host, port)

    scan("example.com", client=make_client(secure_headers), tls_probe=probe, ca_bundle="/x.pem")
    assert seen["ca_bundle"] == "/x.pem"
