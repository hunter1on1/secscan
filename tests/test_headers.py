import pytest

from secscan import headers as h
from secscan.models import Status


def test_all_secure_headers_pass(secure_headers):
    findings = h.check_all(secure_headers)
    assert all(f.status in (Status.PASS, Status.INFO) for f in findings)
    assert sum(f.deduction for f in findings) == 0


def test_header_lookup_is_case_insensitive():
    assert h.check_content_type_options({"x-content-type-options": "NoSniff"}).status == Status.PASS


@pytest.mark.parametrize(
    ("value", "status", "deduction"),
    [
        (None, Status.FAIL, 20),
        ("max-age=0", Status.FAIL, 20),
        ("includeSubDomains", Status.FAIL, 20),
        ("max-age=86400", Status.WARN, 5),
        ("max-age=31536000; includeSubDomains", Status.PASS, 0),
        ('max-age="31536000"', Status.PASS, 0),
    ],
)
def test_hsts(value, status, deduction):
    finding = h.check_hsts({} if value is None else {"Strict-Transport-Security": value})
    assert (finding.status, finding.deduction) == (status, deduction)


def test_parse_csp():
    parsed = h.parse_csp("default-src 'self'; img-src * data:;  ")
    assert parsed == {"default-src": ["'self'"], "img-src": ["*", "data:"]}


@pytest.mark.parametrize(
    ("policy", "status", "deduction"),
    [
        ("default-src 'self'", Status.PASS, 0),
        ("script-src 'self' 'unsafe-inline'", Status.WARN, 10),
        ("script-src 'self' 'unsafe-inline' 'nonce-abc123'", Status.PASS, 0),
        ("script-src 'self' 'unsafe-eval'", Status.WARN, 5),
        ("default-src *", Status.WARN, 5),
        ("img-src 'self'", Status.WARN, 10),  # nothing restricts scripts
    ],
)
def test_csp(policy, status, deduction):
    finding = h.check_csp({"Content-Security-Policy": policy})
    assert (finding.status, finding.deduction) == (status, deduction)


def test_csp_missing():
    finding = h.check_csp({})
    assert finding.status == Status.FAIL
    assert finding.recommendation


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"X-Frame-Options": "DENY"}, Status.PASS),
        ({"X-Frame-Options": "sameorigin"}, Status.PASS),
        ({"X-Frame-Options": "ALLOW-FROM https://a.example"}, Status.WARN),
        ({"Content-Security-Policy": "frame-ancestors 'self'"}, Status.PASS),
        ({"Content-Security-Policy": "frame-ancestors *"}, Status.WARN),
        ({}, Status.FAIL),
    ],
)
def test_framing(headers, status):
    assert h.check_framing(headers).status == status


@pytest.mark.parametrize(
    ("value", "status"),
    [
        (None, Status.WARN),
        ("no-referrer", Status.PASS),
        ("unsafe-url", Status.FAIL),
        ("no-referrer, unsafe-url", Status.FAIL),  # last value wins
        ("unsafe-url, strict-origin", Status.PASS),
    ],
)
def test_referrer_policy(value, status):
    headers = {} if value is None else {"Referrer-Policy": value}
    assert h.check_referrer_policy(headers).status == status


def test_permissions_policy():
    assert h.check_permissions_policy({}).status == Status.WARN
    ok = h.check_permissions_policy({"Permissions-Policy": "camera=(), geolocation=()"})
    assert ok.status == Status.PASS


def test_info_leak_flags_versions_only():
    findings = h.check_info_leak({"Server": "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/8.1"})
    assert [f.status for f in findings] == [Status.WARN, Status.WARN]
    assert sum(f.deduction for f in findings) == 10

    findings = h.check_info_leak({"Server": "cloudflare"})
    assert [f.status for f in findings] == [Status.INFO]
    assert h.check_info_leak({}) == []
