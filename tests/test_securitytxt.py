from datetime import datetime, timezone

import pytest

from secscan.models import Status
from secscan.securitytxt import check_security_txt, parse_expires, parse_security_txt

NOW = datetime(2026, 11, 22, tzinfo=timezone.utc)
TEXT = "text/plain; charset=utf-8"


def test_parse_fields_ignores_comments():
    fields = parse_security_txt(
        "# comment\nContact: mailto:a@b.c\nContact: https://b.c/report\n\nExpires: x\n"
    )
    assert fields["contact"] == ["mailto:a@b.c", "https://b.c/report"]
    assert fields["expires"] == ["x"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2027-01-01T00:00:00.000Z", datetime(2027, 1, 1, tzinfo=timezone.utc)),
        ("2026-12-22T18:20:21z", datetime(2026, 12, 22, 18, 20, 21, tzinfo=timezone.utc)),
        ("2027-01-01T02:00:00+02:00", datetime(2027, 1, 1, tzinfo=timezone.utc)),
        ("2027-13-01T00:00:00Z", None),
        ("next year", None),
    ],
)
def test_parse_expires(value, expected):
    assert parse_expires(value) == expected


def test_valid_file_passes():
    body = "Contact: mailto:security@example.com\nExpires: 2027-06-01T00:00:00Z\n"
    finding = check_security_txt(200, TEXT, body, now=NOW)
    assert finding.status == Status.PASS
    assert "mailto:security@example.com" in finding.detail


@pytest.mark.parametrize(
    ("status_code", "content_type", "body", "fragment"),
    [
        (404, "text/html", "", "Not published"),
        (None, "", "", "Not published"),
        # soft-404: the homepage served for any path
        (200, "text/html", "<html>Contact: us</html>", "Not published"),
        (200, TEXT, "Expires: 2027-06-01T00:00:00Z", "no Contact"),
        (200, TEXT, "Contact: mailto:a@b.c", "no Expires"),
        (
            200,
            TEXT,
            "Contact: mailto:a@b.c\nExpires: 2020-01-01T00:00:00Z",
            "expired on 2020-01-01",
        ),
        (200, TEXT, "Contact: mailto:a@b.c\nExpires: soon", "unreadable Expires"),
    ],
)
def test_problems_are_minor_warnings(status_code, content_type, body, fragment):
    finding = check_security_txt(status_code, content_type, body, now=NOW)
    assert finding.status == Status.WARN and finding.deduction == 2
    assert fragment in finding.detail
