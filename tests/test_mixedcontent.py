import pytest

from secscan.mixedcontent import check_mixed_content, find_mixed_content
from secscan.models import Status


def test_finds_active_and_passive_resources():
    html = """
    <html><head>
      <script src="http://cdn.example.com/app.js"></script>
      <link rel="stylesheet" href="HTTP://cdn.example.com/site.css">
      <link rel="canonical" href="http://example.com/">  <!-- metadata, ignored -->
    </head><body>
      <img src="http://img.example.com/a.png" srcset="b.png 1x, http://img.example.com/c.png 2x">
      <iframe src="http://widgets.example.com/"></iframe>
      <a href="http://example.org/">links are navigation, not mixed content</a>
      <img src="https://img.example.com/ok.png"><script src="//cdn.example.com/ok.js"></script>
    </body></html>
    """
    found = {(r.tag, r.url, r.active) for r in find_mixed_content(html)}
    assert found == {
        ("script", "http://cdn.example.com/app.js", True),
        ("link", "HTTP://cdn.example.com/site.css", True),
        ("img", "http://img.example.com/a.png", False),
        ("img", "http://img.example.com/c.png", False),
        ("iframe", "http://widgets.example.com/", True),
    }


def test_duplicates_removed():
    html = '<img src="http://x/a.png">' * 5
    assert len(find_mixed_content(html)) == 1


@pytest.mark.parametrize(
    ("html", "status", "deduction"),
    [
        ("<p>nothing</p>", Status.PASS, 0),
        ('<img src="http://x/a.png">', Status.WARN, 5),
        ('<img src="http://x/a.png"><script src="http://x/a.js"></script>', Status.FAIL, 15),
    ],
)
def test_grading(html, status, deduction):
    finding = check_mixed_content(html)
    assert (finding.status, finding.deduction) == (status, deduction)


def test_upgrade_insecure_requests_mitigates():
    finding = check_mixed_content(
        '<script src="http://x/a.js"></script>', csp="default-src 'self'; upgrade-insecure-requests"
    )
    assert finding.status == Status.INFO and finding.deduction == 0


def test_broken_html_does_not_crash():
    assert check_mixed_content("<img src='http://x/a.png' <script").status in Status
