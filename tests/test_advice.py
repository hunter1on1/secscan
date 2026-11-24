from secscan import headers
from secscan.advice import PLATFORMS, RULES, attach_advice, header_snippets
from secscan.cookies import check_cookies
from secscan.cors import PROBE_ORIGIN, check_cors
from secscan.mixedcontent import check_mixed_content
from secscan.models import Status
from secscan.securitytxt import check_security_txt
from secscan.tls import evaluate_tls

from .conftest import good_tls

ALL_KNOWN_CHECK_IDS = {
    "hsts", "csp", "framing", "xcto", "referrer", "permissions", "server", "powered-by",
    "aspnet-version", "aspnetmvc-version", "https-redirect", "tls", "certificate", "hostname",
    "https-downgrade", "proto-TLSv1.0", "proto-TLSv1.1", "proto-TLSv1.3", "cookie-secure",
    "cookie-httponly", "cookie-samesite", "security-txt", "cors", "mixed-content",
    "cookie-consent", "privacy-policy", "vat-number", "form-https", "form-consent",
    "booking-widgets", "contact-links", "google-maps",
}  # fmt: skip


def _every_bad_finding():
    """Produce a WARN/FAIL finding from every check."""
    bad = {
        "Server": "Apache/2.4.1",
        "X-Powered-By": "PHP/8",
        "X-AspNet-Version": "4.0",
        "X-AspNetMvc-Version": "5.2",
    }
    findings = headers.check_all(bad)
    findings += check_cookies(["sessionid=1"])
    findings.append(check_cors({"Access-Control-Allow-Origin": PROBE_ORIGIN}))
    findings.append(check_mixed_content('<script src="http://x/a.js"></script>'))
    findings.append(check_security_txt(404, "", ""))
    info = good_tls()
    info.protocols.update({"TLSv1.0": True, "TLSv1.1": True, "TLSv1.3": False})
    info.certificate.days_remaining = 3
    findings += evaluate_tls(info)
    return [f for f in findings if f.status in (Status.WARN, Status.FAIL)]


def test_catalogue_covers_every_check():
    assert set(RULES) == ALL_KNOWN_CHECK_IDS


def test_every_warning_or_failure_gets_advice():
    findings = _every_bad_finding()
    attach_advice(findings)
    missing = [f.check_id for f in findings if f.advice is None]
    assert missing == []


def test_every_rule_has_summary_snippets_and_valid_severity():
    for rule in RULES.values():
        assert rule.advice.summary
        assert rule.advice.snippets, rule.id
        assert set(rule.advice.snippets) <= set(PLATFORMS)
        assert 0 < rule.security_severity <= 10


def test_passing_findings_get_no_advice():
    findings = headers.check_all({"X-Content-Type-Options": "nosniff"})
    attach_advice(findings)
    xcto = next(f for f in findings if f.check_id == "xcto")
    assert xcto.advice is None


def test_header_snippets_cover_main_platforms():
    snippets = header_snippets("X-Frame-Options", "DENY")
    assert 'add_header X-Frame-Options "DENY" always;' in snippets["nginx"]
    assert 'Header always set X-Frame-Options "DENY"' in snippets["apache"]
    assert "X-Frame-Options: DENY" in snippets["netlify"]
    assert '"key": "X-Frame-Options"' in snippets["vercel"]
    assert "Transform Rules" in snippets["cloudflare"]
