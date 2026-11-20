import ssl

import pytest

from secscan import tls
from secscan.models import CertificateInfo, Status, TLSInfo

from .conftest import good_tls

FAKE_CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),)),
    "notAfter": "Jan  1 00:00:00 2030 GMT",
}


def by_id(findings):
    return {f.check_id: f for f in findings}


def test_parse_certificate():
    now = ssl.cert_time_to_seconds("Dec 22 00:00:00 2029 GMT")
    info = tls.parse_certificate(FAKE_CERT, now=now)
    assert info.issuer == "Let's Encrypt"
    assert info.subject == "example.com"
    assert info.not_after == "2030-01-01"
    assert info.days_remaining == 10


def test_good_tls_has_no_deductions():
    findings = tls.evaluate_tls(good_tls())
    assert sum(f.deduction for f in findings) == 0
    assert not any(f.critical for f in findings)


def test_unreachable_is_critical():
    findings = tls.evaluate_tls(TLSInfo(host="x.test", error="refused"))
    assert findings[0].critical


def test_untrusted_certificate_and_hostname_mismatch():
    info = good_tls()
    info.certificate = CertificateInfo(
        valid=False, error="Hostname mismatch, certificate is not valid for 'x.test'."
    )
    found = by_id(tls.evaluate_tls(info))
    assert found["certificate"].critical
    assert found["hostname"].status == Status.FAIL


@pytest.mark.parametrize(
    ("days", "status", "deduction"),
    [(5, Status.FAIL, 10), (20, Status.WARN, 5), (90, Status.PASS, 0)],
)
def test_expiry_windows(days, status, deduction):
    info = good_tls()
    info.certificate.days_remaining = days
    cert = by_id(tls.evaluate_tls(info))["certificate"]
    assert (cert.status, cert.deduction) == (status, deduction)


def test_legacy_protocols_are_penalised():
    info = good_tls()
    info.protocols.update({"TLSv1.0": True, "TLSv1.1": None, "TLSv1.3": False})
    found = by_id(tls.evaluate_tls(info))
    assert found["proto-TLSv1.0"].deduction == 10
    assert found["proto-TLSv1.1"].status == Status.INFO  # untestable is not penalised
    assert found["proto-TLSv1.3"].deduction == 5


def test_probe_tls_with_mocked_handshake(monkeypatch):
    """Exercise the real probing code with the network replaced."""

    def fake_handshake(host, port, context, timeout):
        if context.maximum_version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            raise ssl.SSLError("tlsv1 alert protocol version")
        return "TLSv1.3", FAKE_CERT

    monkeypatch.setattr(tls, "_handshake", fake_handshake)
    info = tls.probe_tls("example.com")
    assert info.reachable and info.certificate.valid
    assert info.protocols == {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}


def test_probe_tls_untrusted_certificate(monkeypatch):
    def fake_handshake(host, port, context, timeout):
        if context.verify_mode == ssl.CERT_REQUIRED:
            err = ssl.SSLCertVerificationError("verify failed")
            err.verify_message = "certificate has expired"
            raise err
        return "TLSv1.2", {}

    monkeypatch.setattr(tls, "_handshake", fake_handshake)
    info = tls.probe_tls("expired.example")
    assert info.reachable and not info.certificate.valid
    assert info.certificate.error == "certificate has expired"


def test_probe_tls_connection_refused(monkeypatch):
    def fake_handshake(*args):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(tls, "_handshake", fake_handshake)
    info = tls.probe_tls("down.example")
    assert not info.reachable and "refused" in info.error


def test_probe_tls_legacy_only_server(monkeypatch):
    """A server that only speaks TLS 1.0 fails the modern handshake."""

    def fake_handshake(host, port, context, timeout):
        if context.maximum_version == ssl.TLSVersion.TLSv1:
            return "TLSv1", {}
        raise ssl.SSLError("handshake failure")

    monkeypatch.setattr(tls, "_handshake", fake_handshake)
    info = tls.probe_tls("old.example")
    assert info.reachable and info.protocols["TLSv1.0"] is True
    found = by_id(tls.evaluate_tls(info))
    assert found["certificate"].critical
    assert found["proto-TLSv1.0"].deduction == 10
