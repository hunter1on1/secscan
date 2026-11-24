"""Restaurant / privacy-compliance checks. Fixtures use example.com only."""

from __future__ import annotations

import io

import httpx
import pytest
from rich.console import Console

from secscan.html_report import to_html
from secscan.models import Category, Status
from secscan.report import render
from secscan.restaurant import (
    check_booking_widgets,
    check_cookie_consent,
    check_form_consent,
    check_form_https,
    check_privacy_policy,
    check_vat_number,
    parse_page,
)
from secscan.sarif import to_sarif
from secscan.scanner import scan

from .conftest import good_tls, make_client

POLICY_FOOTER = '<footer><a href="/privacy-policy">Privacy Policy</a></footer>'
PIVA = "P.IVA 12345678901"
ITALIAN_BITS = "Ristorante da Esempio. Prenota un tavolo. Chi siamo. Contatti."


def page(html: str, url: str = "https://example.com/"):
    return parse_page(url, html)


def by_id(findings):
    return {f.check_id: f for f in findings}


# --------------------------------------------------------------------------- #
# Cookie consent
# --------------------------------------------------------------------------- #
def test_trackers_without_banner_are_a_warning():
    html = (
        '<html><head><script src="https://www.googletagmanager.com/gtag/js?id=G-XXX">'
        "</script><script>gtag('config','G-XXX')</script></head><body>Hi</body></html>"
    )
    finding = check_cookie_consent(page(html), ["_ga=GA1.1; Secure"])
    assert finding.status == Status.WARN
    assert "likely" in finding.detail.lower()
    assert "Google Analytics" in finding.detail
    assert finding.deduction == 20


def test_iubenda_banner_is_a_pass():
    html = (
        '<script src="https://cdn.iubenda.com/cs/iubenda_cs.js"></script>'
        "<script>_iub.csConfiguration = {country:'IT'}</script>"
        f"<body>{POLICY_FOOTER}</body>"
    )
    finding = check_cookie_consent(page(html), [])
    assert finding.status == Status.PASS
    assert "iubenda" in finding.detail.lower()


def test_banner_plus_trackers_is_info_not_a_failure():
    html = (
        '<script src="https://consent.cookiebot.com/uc.js"></script>'
        '<script src="https://www.google-analytics.com/analytics.js"></script>'
    )
    finding = check_cookie_consent(page(html), [])
    assert finding.status == Status.INFO
    assert "Cookiebot" in finding.detail
    assert "not verified" in finding.detail


def test_no_trackers_and_no_banner_is_info():
    finding = check_cookie_consent(page("<html><body>Menu of the day</body></html>"), [])
    assert finding.status == Status.INFO
    assert finding.deduction == 0


# --------------------------------------------------------------------------- #
# Privacy policy and VAT
# --------------------------------------------------------------------------- #
def test_homepage_privacy_link_passes():
    html = f"<body>Welcome. {POLICY_FOOTER}</body>"
    finding = check_privacy_policy(page(html))
    assert finding.status == Status.PASS
    assert "Privacy Policy" in finding.detail


@pytest.mark.parametrize(
    "label",
    [
        "Informativa sulla privacy",
        "Cookie Policy",
        "Datenschutz",
        "Politique de confidentialité",
        "Política de privacidad",
    ],
)
def test_multilingual_privacy_links(label):
    html = f'<a href="/legal">{label}</a>'
    assert check_privacy_policy(page(html)).status == Status.PASS


def test_policy_found_only_on_a_well_known_path_is_a_warning():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/privacy-policy":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text="<html><body>Our Privacy Policy explains personal data.</body></html>",
            )
        return httpx.Response(404, text="no")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    finding = check_privacy_policy(page("<html><body>Home</body></html>"), client)
    assert finding.status == Status.WARN
    assert "does not link" in finding.detail
    assert finding.deduction == 5


def test_missing_policy_is_a_warning():
    finding = check_privacy_policy(page("<html><body>Just a menu</body></html>"))
    assert finding.status == Status.WARN
    assert finding.deduction == 15


def test_vat_detected_without_reprinting_the_number():
    finding = check_vat_number(page(f"<footer>{PIVA}</footer>"))
    assert finding.status == Status.PASS
    assert "12345678901" not in finding.detail


def test_italian_page_without_vat_is_a_warning():
    html = f"<html lang='it'><body>{ITALIAN_BITS}</body></html>"
    finding = check_vat_number(page(html))
    assert finding.status == Status.WARN
    assert finding.deduction == 5
    assert "not legal advice" in finding.detail.lower()


def test_non_italian_page_without_vat_is_info():
    finding = check_vat_number(page("<html lang='en'><body>Hello and welcome.</body></html>"))
    assert finding.status == Status.INFO
    assert finding.deduction == 0


# --------------------------------------------------------------------------- #
# Forms and widgets
# --------------------------------------------------------------------------- #
def test_http_form_action_fails():
    html = '<form action="http://example.com/book" method="post"><input name="n"></form>'
    finding = check_form_https(page(html, "https://example.com/"))
    assert finding.status == Status.FAIL
    assert finding.deduction == 20
    assert "plain HTTP" in finding.detail


def test_password_over_http_page_fails():
    html = '<form action="/login" method="post"><input type="password" name="p"></form>'
    finding = check_form_https(page(html, "http://example.com/"))
    assert finding.status == Status.FAIL
    assert "password" in finding.detail.lower()


def test_https_relative_form_passes():
    html = '<form action="/book" method="post"><input name="n"></form>'
    finding = check_form_https(page(html, "https://example.com/"))
    assert finding.status == Status.PASS


def test_email_form_without_privacy_note_is_info():
    html = '<form action="/n" method="post"><input type="email" name="email"></form>'
    finding = check_form_consent(page(html))
    assert finding.status == Status.INFO
    assert "email" in finding.detail.lower()


def test_email_form_with_privacy_note_passes():
    html = (
        '<form action="/n" method="post"><input type="email" name="email">'
        'I have read the <a href="/privacy">privacy</a> policy.</form>'
    )
    assert check_form_consent(page(html)).status == Status.PASS


def test_thefork_widget_over_https_is_inventory():
    html = '<script src="https://widget.thefork.com/sdk.js"></script>'
    finding = check_booking_widgets(page(html))
    assert finding.status == Status.PASS
    assert "TheFork" in finding.detail


def test_widget_over_http_fails():
    html = '<iframe src="http://www.opentable.com/widget"></iframe>'
    finding = check_booking_widgets(page(html))
    assert finding.status == Status.FAIL
    assert "OpenTable" in finding.detail
    assert finding.deduction == 20


def test_unknown_cdn_script_gets_sri_note():
    html = '<script src="https://cdn.unexpected-example.com/thefork-widget.js"></script>'
    # Need a TheFork marker somewhere so the widget is detected, plus the odd host.
    html = (
        '<script src="https://cdn.unexpected-example.com/thefork-widget.js"></script>'
        '<a href="https://www.thefork.com/restaurant/x">Book</a>'
    )
    finding = check_booking_widgets(page(html))
    # The marker is on a link, the script host is unexpected and has no integrity.
    assert "TheFork" in finding.detail
    assert "Subresource Integrity" in finding.detail or "unexpected" in finding.detail.lower()


# --------------------------------------------------------------------------- #
# End-to-end through scan(), grade isolation, every output format
# --------------------------------------------------------------------------- #
GOOD_RESTAURANT = f"""
<html lang="it">
<head></head>
<body>
  <h1>Ristorante Esempio</h1>
  <p>{ITALIAN_BITS}</p>
  <p>{PIVA}</p>
  <form action="/prenota" method="post">
    <input type="email" name="email">
    <label><input type="checkbox"> Accetto l'informativa sulla privacy</label>
  </form>
  <iframe src="https://www.google.com/maps/embed?pb=0"></iframe>
  <a href="tel:+390000000">Chiama</a>
  {POLICY_FOOTER}
  <script src="https://cdn.iubenda.com/cs/iubenda_cs.js"></script>
</body>
</html>
"""


def _scan(body: str, **kwargs):
    client = make_client(
        {"Strict-Transport-Security": "max-age=31536000"},
        body=body,
        set_cookies=[],
        security_txt=None,
    )
    kwargs.setdefault("tls_probe", good_tls)
    return scan("example.com", client=client, **kwargs)


def test_profile_does_not_change_the_security_grade():
    plain = _scan(GOOD_RESTAURANT)
    restaurant = _scan(GOOD_RESTAURANT, profile="restaurant")
    assert restaurant.grade == plain.grade
    assert restaurant.score == plain.score
    assert restaurant.profile == "restaurant"
    assert restaurant.compliance is not None
    assert restaurant.compliance.score == 100
    assert restaurant.compliance.grade in {"A+", "A"}
    assert plain.compliance is None
    assert all(f.category != Category.RESTAURANT for f in plain.findings)
    assert any(f.category == Category.RESTAURANT for f in restaurant.findings)


def test_compliance_score_drops_for_missing_banner_and_policy():
    html = (
        '<html lang="it"><body>'
        f"{ITALIAN_BITS}"
        '<script src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>'
        "</body></html>"
    )
    result = _scan(html, profile="restaurant")
    found = by_id(result.findings)
    assert found["cookie-consent"].status == Status.WARN
    assert found["privacy-policy"].status == Status.WARN
    assert found["vat-number"].status == Status.WARN
    # 20 + 15 + 5 = 40 -> score 60, grade C
    assert result.compliance.score == 60
    assert result.compliance.grade == "C"
    # Security grade is independent (this fixture only has HSTS, so it still loses
    # points for other security headers, but must not include the 40 above).
    plain = _scan(html)
    assert result.score == plain.score


def test_outputs_include_compliance_and_section():
    result = _scan(GOOD_RESTAURANT, profile="restaurant")
    data = result.to_dict()
    assert data["profile"] == "restaurant"
    assert data["compliance"]["score"] == 100

    console = Console(file=io.StringIO(), width=120, force_terminal=False)
    render(result, console, explain=True)
    out = console.file.getvalue()
    assert "Compliance:" in out
    assert "RESTAURANT & PRIVACY COMPLIANCE" in out
    assert "not legal advice" in out.lower()

    html = to_html([result])
    assert "Compliance:" in html
    assert "Restaurant &amp; privacy compliance" in html or "Restaurant & privacy" in html

    sarif = to_sarif([result])
    scan_prop = sarif["runs"][0]["properties"]["scans"][0]
    assert scan_prop["profile"] == "restaurant"
    assert scan_prop["compliance"]["score"] == 100
