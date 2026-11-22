"""security.txt (RFC 9116): how should a researcher report a vulnerability?

A small text file at ``/.well-known/security.txt`` tells people who find a
security bug where to send it. Without it, reports get lost or end up on
social media. Two fields are required by the RFC:

* ``Contact:`` - an email (``mailto:``) or URL for reports.
* ``Expires:`` - a date after which the file should be considered stale, so
  outdated contacts don't linger forever.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from secscan.models import Category, Finding, Status

PATH = "/.well-known/security.txt"


def parse_security_txt(body: str) -> dict[str, list[str]]:
    """Return {"contact": [...], "expires": [...], ...} (field names lower-cased)."""
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    return fields


# RFC 3339: 2027-01-01T00:00:00Z, with optional fractions and a "z"/"t" in
# any case, or a numeric offset such as +01:00.
_RFC3339_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}:\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)


def parse_expires(value: str) -> datetime | None:
    """Parse an RFC 3339 timestamp; return None if it isn't one.

    Written by hand because datetime.fromisoformat() on Python 3.10 rejects
    valid forms such as a trailing "Z" or more than 6 fractional digits.
    """
    match = _RFC3339_RE.match(value.strip())
    if not match:
        return None
    day, clock, offset = match.groups()
    try:
        parsed = datetime.strptime(f"{day} {clock}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None  # e.g. month 13
    if offset in ("Z", "z"):
        return parsed.replace(tzinfo=timezone.utc)
    sign = 1 if offset[0] == "+" else -1
    hours, minutes = int(offset[1:3]), int(offset[4:6])
    return parsed.replace(tzinfo=timezone(sign * timedelta(hours=hours, minutes=minutes)))


def _finding(status: Status, detail: str, **kw) -> Finding:
    return Finding("security-txt", "security.txt", Category.DISCLOSURE, status, detail, **kw)


def check_security_txt(
    status_code: int | None,
    content_type: str,
    body: str,
    now: datetime | None = None,
) -> Finding:
    """Evaluate the response to GET /.well-known/security.txt."""
    now = now or datetime.now(timezone.utc)
    fix = f"Publish {PATH} with Contact: and Expires: fields (see securitytxt.org)."

    # Many sites answer unknown paths with their HTML homepage and status 200,
    # so we also require a text/plain response before believing it.
    is_text = content_type.split(";")[0].strip().lower() == "text/plain"
    if status_code != 200 or not is_text:
        return _finding(Status.WARN, "Not published.", recommendation=fix, deduction=2)

    fields = parse_security_txt(body)
    problems: list[str] = []
    if not fields.get("contact"):
        problems.append("no Contact field")

    expires_raw = fields.get("expires", [])
    expires = parse_expires(expires_raw[0]) if expires_raw else None
    if not expires_raw:
        problems.append("no Expires field")
    elif expires is None:
        problems.append(f"unreadable Expires date {expires_raw[0]!r}")
    elif expires < now:
        problems.append(f"expired on {expires.date().isoformat()}")

    if problems:
        return _finding(
            Status.WARN,
            "Published but invalid: " + "; ".join(problems) + ".",
            recommendation=fix,
            deduction=2,
        )

    contact = fields["contact"][0]
    detail = f"Contact {contact}"
    if expires:
        detail += f", expires {expires.date().isoformat()}"
    return _finding(Status.PASS, detail)
