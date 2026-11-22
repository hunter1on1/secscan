"""CORS (Cross-Origin Resource Sharing) misconfiguration.

Browsers normally stop JavaScript on site A from *reading* responses from
site B (the Same-Origin Policy). CORS headers let site B relax that rule:

* ``Access-Control-Allow-Origin`` (ACAO) - which origin may read the response.
* ``Access-Control-Allow-Credentials`` (ACAC) - whether the request may carry
  the user's cookies.

The dangerous combination is "any origin may read this, *with* the user's
cookies": then any website the victim visits can read their private data.

How we test it: we send a request with an ``Origin`` header of a site that
does not exist (exactly what a browser sends for a cross-origin fetch) and
see whether the server trusts it.
"""

from __future__ import annotations

from collections.abc import Mapping

from secscan.models import Category, Finding, Status

# A reserved .invalid domain (RFC 2606) can never belong to anyone.
PROBE_ORIGIN = "https://secscan-cors-probe.invalid"


def _get(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _finding(status: Status, detail: str, **kw) -> Finding:
    return Finding("cors", "CORS policy", Category.CORS, status, detail, **kw)


def check_cors(headers: Mapping[str, str], sent_origin: str = PROBE_ORIGIN) -> Finding:
    """Evaluate the response to a request that carried ``Origin: sent_origin``."""
    acao = (_get(headers, "Access-Control-Allow-Origin") or "").strip()
    credentials = (_get(headers, "Access-Control-Allow-Credentials") or "").strip().lower()
    with_creds = credentials == "true"
    fix = "Only allow a fixed list of trusted origins; never reflect the Origin header."

    if not acao:
        return _finding(Status.PASS, "No cross-origin read access granted.")

    if acao == sent_origin:
        if with_creds:
            return _finding(
                Status.FAIL,
                "Reflects any Origin AND allows credentials: any website can read "
                "logged-in users' responses.",
                recommendation=fix,
                deduction=20,
            )
        return _finding(
            Status.WARN,
            "Reflects any Origin sent to it (an allow-list that trusts everyone).",
            recommendation=fix,
            deduction=5,
        )

    if acao == "null":
        # Sandboxed iframes and local files send "Origin: null", and an
        # attacker can create those at will.
        return _finding(
            Status.FAIL if with_creds else Status.WARN,
            "Trusts the 'null' origin" + (" with credentials." if with_creds else "."),
            recommendation=fix,
            deduction=20 if with_creds else 5,
        )

    if acao == "*":
        if with_creds:
            # Browsers refuse this combination, but it shows the intent was
            # "everyone, with cookies", which usually turns into reflection.
            return _finding(
                Status.WARN,
                "Wildcard origin combined with Allow-Credentials: true (invalid, "
                "and a sign of a risky policy).",
                recommendation=fix,
                deduction=5,
            )
        return _finding(
            Status.INFO,
            "Public resource (Access-Control-Allow-Origin: *, no credentials).",
        )

    return _finding(Status.PASS, f"Restricted to {acao}.")
