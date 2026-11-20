"""TLS (HTTPS) checks: certificate, hostname, and supported protocol versions.

The module is split in two halves:

* **Probing** (`probe_tls`, `_handshake`) talks to the network using Python's
  built-in :mod:`ssl` module and fills a :class:`TLSInfo`.
* **Evaluating** (`evaluate_tls`) is pure: it turns a :class:`TLSInfo` into
  findings. Tests feed it hand-made ``TLSInfo`` objects, no network needed.
"""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from datetime import datetime, timezone

from secscan.models import Category, CertificateInfo, Finding, Status, TLSInfo

# Protocol versions we try one at a time, oldest first.
PROTOCOLS: dict[str, ssl.TLSVersion] = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}
LEGACY_PROTOCOLS = ("TLSv1.0", "TLSv1.1")


def _handshake(host: str, port: int, context: ssl.SSLContext, timeout: float) -> tuple[str, dict]:
    """Open a TCP connection, perform a TLS handshake, return (version, peer cert).

    This is the only function that touches the network; tests replace it.
    """
    # server_hostname enables SNI (so the server picks the right certificate)
    # and lets Python verify that the certificate matches the hostname.
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls_sock,
    ):
        return tls_sock.version() or "", tls_sock.getpeercert() or {}


def _name_from_rdns(rdns: tuple) -> str:
    """getpeercert() returns names as nested tuples; pull out a readable one."""
    fields = {key: value for rdn in rdns for (key, value) in rdn}
    return fields.get("organizationName") or fields.get("commonName") or ""


def parse_certificate(cert: dict, now: float | None = None) -> CertificateInfo:
    """Convert the dict from ``SSLSocket.getpeercert()`` into CertificateInfo."""
    now = time.time() if now is None else now
    info = CertificateInfo(valid=True)
    info.subject = _name_from_rdns(cert.get("subject", ()))
    info.issuer = _name_from_rdns(cert.get("issuer", ()))
    if "notAfter" in cert:
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        info.not_after = datetime.fromtimestamp(expires, tz=timezone.utc).date().isoformat()
        info.days_remaining = int((expires - now) // 86400)
    return info


def _protocol_context(version: ssl.TLSVersion) -> ssl.SSLContext:
    """A context that can *only* speak one TLS version.

    Certificate checks are disabled here on purpose: we only want to know
    whether the server accepts the protocol, not whether the cert is valid.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        # Modern OpenSSL refuses old protocols by default (security level 1+).
        # Lowering it lets us *detect* servers that still accept them.
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    # Python warns that TLS 1.0/1.1 are deprecated - that is exactly what we
    # are testing for, so silence the warning here.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = version
        ctx.maximum_version = version
    return ctx


def probe_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool | None:
    """True if the server accepts `version`, False if it refuses, None if unknown."""
    try:
        ctx = _protocol_context(version)
        _handshake(host, port, ctx, timeout)
        return True
    except ssl.SSLError as exc:
        # NO_PROTOCOLS_AVAILABLE means *our* OpenSSL cannot offer this version,
        # so we learned nothing about the server.
        if getattr(exc, "reason", "") == "NO_PROTOCOLS_AVAILABLE":
            return None
        return False
    except (ConnectionResetError, ConnectionAbortedError):
        return False  # many servers just hang up on old protocols
    except (OSError, ValueError):
        return None  # timeout, DNS failure, or unsupported locally


def probe_tls(host: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    """Collect certificate and protocol information for host:port."""
    info = TLSInfo(host=host, port=port)

    # 1. A normal, fully verified handshake - exactly what a browser does.
    try:
        version, cert = _handshake(host, port, ssl.create_default_context(), timeout)
        info.reachable = True
        info.negotiated_version = version
        info.certificate = parse_certificate(cert)
    except ssl.SSLCertVerificationError as exc:
        # The server speaks TLS, but its certificate is not trusted
        # (expired, self-signed, wrong hostname...).
        info.reachable = True
        info.certificate = CertificateInfo(valid=False, error=exc.verify_message or str(exc))
    except ssl.SSLError as exc:
        # The handshake failed for another reason, e.g. the server only speaks
        # protocols that modern clients refuse. Keep going: the per-protocol
        # probes below tell us what it *does* accept.
        info.error = f"Modern TLS handshake failed: {exc}"
    except OSError as exc:
        info.error = f"TLS connection failed: {exc}"
        return info

    # 2. Try each protocol version on its own.
    for name, version in PROTOCOLS.items():
        info.protocols[name] = probe_protocol(host, port, version, timeout)

    if not info.reachable and any(info.protocols.values()):
        # Only legacy protocols work: browsers will refuse this site.
        info.reachable = True
        info.certificate = CertificateInfo(valid=False, error=info.error)
    return info


def _finding(check_id: str, title: str, status: Status, detail: str, **kw) -> Finding:
    return Finding(check_id, title, Category.TLS, status, detail, **kw)


def evaluate_tls(info: TLSInfo) -> list[Finding]:
    """Turn raw TLS facts into scored findings."""
    if not info.reachable:
        return [
            _finding(
                "tls",
                "HTTPS available",
                Status.FAIL,
                info.error or "Could not establish a TLS connection.",
                recommendation="Serve the site over HTTPS (e.g. free certificates "
                "from Let's Encrypt).",
                critical=True,
            )
        ]

    findings: list[Finding] = []
    cert = info.certificate

    # --- Certificate validity and expiry -----------------------------------
    if not cert.valid:
        findings.append(
            _finding(
                "certificate",
                "Certificate",
                Status.FAIL,
                f"Not trusted: {cert.error}",
                recommendation="Install a valid certificate from a trusted CA "
                "that covers this hostname.",
                critical=True,
            )
        )
    else:
        detail = f"Issued by {cert.issuer or 'unknown'}, expires {cert.not_after}"
        days = cert.days_remaining
        if days is not None:
            detail += f" ({days} days left)"
        if days is not None and days < 14:
            findings.append(
                _finding(
                    "certificate",
                    "Certificate",
                    Status.FAIL,
                    detail,
                    recommendation="Renew now and automate renewal.",
                    deduction=10,
                )
            )
        elif days is not None and days < 30:
            findings.append(
                _finding(
                    "certificate",
                    "Certificate",
                    Status.WARN,
                    detail,
                    recommendation="Renew soon; automate renewal (e.g. certbot).",
                    deduction=5,
                )
            )
        else:
            findings.append(_finding("certificate", "Certificate", Status.PASS, detail))

    # --- Hostname match ---------------------------------------------------------
    # ssl.create_default_context() checks the hostname during the handshake, so
    # a trusted certificate already implies a match.
    if cert.valid:
        findings.append(
            _finding("hostname", "Hostname match", Status.PASS, f"Certificate covers {info.host}")
        )
    elif "hostname" in cert.error.lower():
        findings.append(
            _finding(
                "hostname",
                "Hostname match",
                Status.FAIL,
                f"Certificate does not cover {info.host}",
                recommendation="Add the hostname to the certificate's SAN list.",
                critical=True,
            )
        )

    # --- Legacy protocols (TLS 1.0 / 1.1) -----------------------------------
    for name in LEGACY_PROTOCOLS:
        state = info.protocols.get(name)
        if state:
            findings.append(
                _finding(
                    f"proto-{name}",
                    f"{name} disabled",
                    Status.FAIL,
                    f"Server still accepts {name} (deprecated by RFC 8996).",
                    recommendation=f"Disable {name}; allow only TLS 1.2 and 1.3.",
                    deduction=10,
                )
            )
        elif state is False:
            findings.append(_finding(f"proto-{name}", f"{name} disabled", Status.PASS, "Refused"))
        else:
            findings.append(
                _finding(
                    f"proto-{name}",
                    f"{name} disabled",
                    Status.INFO,
                    "Could not be tested from this machine.",
                )
            )

    # --- Modern protocol (TLS 1.3) ------------------------------------------
    tls13 = info.protocols.get("TLSv1.3")
    if tls13:
        findings.append(_finding("proto-TLSv1.3", "TLSv1.3 supported", Status.PASS, "Accepted"))
    elif tls13 is False:
        findings.append(
            _finding(
                "proto-TLSv1.3",
                "TLSv1.3 supported",
                Status.WARN,
                "TLS 1.3 not offered.",
                recommendation="Enable TLS 1.3 (faster and safer handshakes).",
                deduction=5,
            )
        )
    return findings
