import pytest

from secscan.cookies import check_cookies, parse_set_cookie
from secscan.models import Status


def by_id(findings):
    return {f.check_id: f for f in findings}


def test_parse_set_cookie():
    cookie = parse_set_cookie("sessionid=abc=def; Path=/; Secure; HttpOnly; SameSite=strict")
    assert cookie.name == "sessionid"
    assert cookie.secure and cookie.httponly
    assert cookie.samesite == "Strict"
    assert cookie.looks_like_session


def test_no_cookies_is_info():
    (finding,) = check_cookies([])
    assert finding.status == Status.INFO and finding.deduction == 0


def test_well_configured_cookies_pass():
    found = by_id(
        check_cookies(
            [
                "sessionid=1; Secure; HttpOnly; SameSite=Lax",
                "__Host-csrf=2; Path=/; Secure; HttpOnly; SameSite=Strict",
            ]
        )
    )
    assert all(f.status == Status.PASS for f in found.values())
    assert sum(f.deduction for f in found.values()) == 0


def test_missing_secure_fails_once_for_many_cookies():
    found = by_id(check_cookies([f"c{i}=1; HttpOnly; SameSite=Lax" for i in range(8)]))
    secure = found["cookie-secure"]
    assert secure.status == Status.FAIL and secure.deduction == 10
    assert "8 cookie(s)" in secure.detail and "+3 more" in secure.detail


def test_cookie_values_are_never_reported():
    found = check_cookies(["sessionid=SUPERSECRETTOKEN; Path=/"])
    assert all("SUPERSECRETTOKEN" not in f.detail for f in found)


@pytest.mark.parametrize(
    ("header", "status", "deduction"),
    [
        ("sessionid=1; Secure; SameSite=Lax", Status.WARN, 5),  # session, no HttpOnly
        ("auth_token=1; Secure; SameSite=Lax", Status.WARN, 5),
        ("theme=dark; Secure; SameSite=Lax", Status.INFO, 0),  # UI cookie: fine
        ("sessionid=1; Secure; HttpOnly; SameSite=Lax", Status.PASS, 0),
    ],
)
def test_httponly_only_required_for_session_cookies(header, status, deduction):
    finding = by_id(check_cookies([header]))["cookie-httponly"]
    assert (finding.status, finding.deduction) == (status, deduction)


@pytest.mark.parametrize(
    ("header", "status", "deduction"),
    [
        ("a=1; Secure; HttpOnly", Status.WARN, 2),
        ("a=1; HttpOnly; SameSite=None", Status.FAIL, 5),  # None requires Secure
        ("a=1; Secure; HttpOnly; SameSite=None", Status.PASS, 0),
        ("a=1; Secure; HttpOnly; samesite=lax", Status.PASS, 0),
    ],
)
def test_samesite(header, status, deduction):
    finding = by_id(check_cookies([header]))["cookie-samesite"]
    assert (finding.status, finding.deduction) == (status, deduction)
