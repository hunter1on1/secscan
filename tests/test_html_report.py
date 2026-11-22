import re
from datetime import datetime, timezone

from secscan.html_report import to_html, write_html
from secscan.scanner import scan

from .conftest import good_tls, make_client

FIXED_TIME = datetime(2026, 11, 22, 18, 0, tzinfo=timezone.utc)


def _scan(headers, **kw):
    return scan("example.com", client=make_client(headers, **kw), tls_probe=good_tls)


def test_report_structure(secure_headers):
    page = to_html([_scan(secure_headers)], generated=FIXED_TIME)
    assert page.startswith("<!doctype html>")
    assert "secscan report: example.com" in page
    assert ">A+<" in page
    assert "2026-11-22 18:00 UTC" in page


def test_report_is_self_contained(secure_headers):
    page = to_html([_scan({"X-Powered-By": "PHP/8"})])
    # no external scripts, stylesheets, images or fonts
    assert "<script" not in page
    assert not re.search(r"<link[^>]+stylesheet", page)
    assert not re.search(r"""(src|url)\s*[=(]\s*["']?https?://""", page)


def test_report_includes_fix_snippets():
    page = to_html([_scan({})])
    assert "How to fix" in page
    assert "add_header Strict-Transport-Security" in page  # nginx snippet
    assert "Vercel" in page and "Netlify" in page


def test_scanned_content_is_escaped():
    """A malicious site must not be able to inject HTML into our report."""
    evil = '<script>alert("xss")</script>'
    page = to_html([_scan({"X-Powered-By": evil})])
    assert evil not in page
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in page


def test_multiple_targets_get_an_overview(secure_headers, tmp_path):
    out = tmp_path / "r.html"
    write_html(str(out), [_scan(secure_headers), _scan({})])
    page = out.read_text()
    assert 'href="#target-1"' in page and 'id="target-2"' in page
