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


def by_id(result):
    return {f.check_id: f for f in result.findings}


def test_new_checks_run_in_full_scan(secure_headers):
    client = make_client(
        secure_headers,
        set_cookies=["sessionid=1; Path=/"],
        security_txt=None,
        cors_headers={
            "Access-Control-Allow-Origin": "{origin}",
            "Access-Control-Allow-Credentials": "true",
        },
        body='<img src="http://img.example.com/a.png">',
    )
    found = by_id(scan("example.com", client=client, tls_probe=good_tls))
    assert found["cookie-secure"].deduction == 10
    assert found["cors"].status.value == "fail"
    assert found["mixed-content"].status.value == "warn"
    assert found["security-txt"].status.value == "warn"
    # every problem carries fix advice
    assert all(f.advice for f in found.values() if f.status.value in ("warn", "fail"))


def test_cookies_from_redirect_hops_are_checked(secure_headers):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(302, headers={"Location": "/home", "Set-Cookie": "sid=1; Path=/"})
        if request.url.path == "/home":
            return httpx.Response(200, headers={"Content-Type": "text/html", **secure_headers})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    found = by_id(scan("example.com", client=client, tls_probe=None))
    assert found["cookie-secure"].status.value == "fail"


def test_non_html_page_skips_mixed_content(secure_headers):
    def handler(request):
        return httpx.Response(200, headers={"Content-Type": "application/json"}, text="{}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    found = by_id(scan("api.example.com", client=client, tls_probe=None))
    assert found["mixed-content"].status.value == "info"


def test_findings_are_grouped_by_category(secure_headers):
    result = scan("example.com", client=make_client(secure_headers), tls_probe=good_tls)
    order = [f.category.value for f in result.findings]
    assert order == sorted(
        order, key=["headers", "cookies", "cors", "content", "disclosure", "tls"].index
    )


def test_https_to_http_downgrade_is_flagged(secure_headers):
    def handler(request):
        if request.url.scheme == "https" and request.url.path == "/":
            return httpx.Response(301, headers={"Location": "http://www.example.com/"})
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<p>plain</p>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = scan("example.com", client=client, tls_probe=good_tls)
    found = by_id(result)
    assert found["https-downgrade"].status.value == "fail"
    assert found["https-downgrade"].deduction == 20
    assert found["https-downgrade"].advice is not None
    assert result.final_url == "http://www.example.com/"


def test_no_downgrade_finding_on_normal_https(secure_headers):
    result = scan("example.com", client=make_client(secure_headers), tls_probe=good_tls)
    assert "https-downgrade" not in by_id(result)
