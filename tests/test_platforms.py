"""Platform detection, responsibility tagging and the "your part" summary."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from secscan.html_report import to_html
from secscan.models import Category, Finding, Status
from secscan.platforms import (
    CAPABILITIES,
    GROUPS,
    PLATFORM,
    PLATFORMS,
    SETTINGS,
    YOU,
    capability_for,
    describe,
    detect_platforms,
    detection_for,
    snippet_platforms,
    tag_findings,
    your_part,
)
from secscan.report import render
from secscan.sarif import to_sarif
from secscan.scanner import scan
from tests.conftest import good_tls, make_client

WIX_HTML = (
    '<html><head><meta name="generator" content="Wix.com Website Builder"/>'
    '<link href="https://static.parastorage.com/x.css"></head><body></body></html>'
)


def ids(detections):
    return [d.platform for d in detections]


# --------------------------------------------------------------------------- #
# Detection from synthetic responses (example.com with each platform's signals)
# --------------------------------------------------------------------------- #
def test_wix_behind_cloudflare():
    found = detect_platforms(
        "example.com",
        {"X-Wix-Request-Id": "1.2", "Server": "cloudflare", "CF-Ray": "abc"},
        ["ssr-caching=cache#desc=hit; max-age=20", "__cf_bm=x; HttpOnly; Secure"],
        WIX_HTML,
    )
    assert ids(found) == ["wix", "cloudflare"]
    assert found[0].confidence == "high"
    assert "X-Wix-Request-Id header" in found[0].evidence
    assert describe(found) == "Wix (high confidence) behind Cloudflare"


@pytest.mark.parametrize(
    ("host", "headers", "cookies", "html", "expected"),
    [
        ("example.com", {"Server": "Squarespace"}, ["crumb=1"], "", "squarespace"),
        ("shop.example", {"Powered-By": "Shopify"}, ["_shopify_y=1"], "", "shopify"),
        ("x.example", {"X-Wf-Region": "us"}, [], '<html data-wf-site="1">', "webflow"),
        ("x.example", {"Host-Header": "WordPress.com"}, [], "", "wordpress-com"),
        ("x.example", {}, [], '<meta name="generator" content="WordPress 6.5">', "wordpress"),
        ("me.github.io", {}, [], "", "github-pages"),
        ("x.example", {"Server": "GitHub.com", "X-GitHub-Request-Id": "1",
                       "X-Fastly-Request-Id": "2"}, [], "", "github-pages"),
        ("x.example", {"Server": "Netlify", "X-NF-Request-Id": "1"}, [], "", "netlify"),
        ("x.example", {"Server": "Vercel", "X-Vercel-Id": "1"}, [], "", "vercel"),
        ("x.example", {"Server": "cloudflare", "CF-Ray": "1"}, [], "", "cloudflare"),
    ],
)  # fmt: skip
def test_detects_each_platform(host, headers, cookies, html, expected):
    assert ids(detect_platforms(host, headers, cookies, html))[0] == expected


def test_github_com_is_not_github_pages():
    # github.com sends "Server: github.com" (lower case) and no Fastly header.
    found = detect_platforms("github.com", {"Server": "github.com", "X-GitHub-Request-Id": "1"})
    assert found == []


def test_one_weak_hint_is_not_enough():
    assert detect_platforms("x.example", {}, ["crumb=1"]) == []
    assert describe([]) == "not detected"


def test_wordpress_com_wins_over_self_hosted_wordpress():
    html = '<meta name="generator" content="WordPress.com"><link href="/wp-content/x.css">'
    found = detect_platforms("x.example", {"Link": '<https://api.w.org/>; rel="x"'}, [], html)
    assert ids(found) == ["wordpress-com"]


def test_cdn_alone_says_origin_unknown():
    found = detect_platforms("x.example", {"Server": "cloudflare", "CF-Ray": "1"})
    assert "origin server unknown" in describe(found)


def test_manual_override():
    detection = detection_for("squarespace")
    assert detection.confidence == "manual"
    assert describe([detection]) == "Squarespace (set manually)"


# --------------------------------------------------------------------------- #
# Capability tables
# --------------------------------------------------------------------------- #
def test_capability_tables_only_use_known_keys_and_real_links():
    known = set(GROUPS) | {c for ids_ in GROUPS.values() for c in ids_}
    known |= {"cors", "mixed-content", "security-txt"}
    for platform, table in CAPABILITIES.items():
        assert platform in PLATFORMS
        for key, cap in table.items():
            assert key in known, (platform, key)
            assert cap.responsibility in (YOU, SETTINGS, PLATFORM)
            assert cap.steps
            assert not cap.docs or cap.docs.startswith("https://")


def test_wix_headers_are_platform_controlled_but_referrer_is_settings():
    wix = [detection_for("wix")]
    assert capability_for("csp", wix).responsibility == PLATFORM
    assert capability_for("permissions", wix).responsibility == PLATFORM
    assert capability_for("referrer", wix).responsibility == SETTINGS
    assert capability_for("mixed-content", wix).responsibility == YOU
    assert capability_for("proto-TLSv1.0", wix).responsibility == PLATFORM


def test_self_hosted_behind_cloudflare_uses_cloudflare_for_tls():
    found = [detection_for("wordpress"), detection_for("cloudflare")]
    assert capability_for("proto-TLSv1.0", found).responsibility == SETTINGS
    assert capability_for("https-redirect", found).responsibility == SETTINGS
    assert capability_for("csp", found) is None  # self-hosted: yours


def test_unknown_platform_means_you_can_fix():
    finding = Finding("csp", "CSP", Category.HEADERS, Status.FAIL, "missing", deduction=20)
    tag_findings([finding], [])
    assert finding.responsibility == YOU
    assert finding.platform_steps == ""


def test_snippet_visibility():
    assert snippet_platforms([detection_for("wix")]) == ()
    assert snippet_platforms([detection_for("netlify")]) == ("netlify",)
    assert "nginx" in snippet_platforms([detection_for("wordpress")])
    assert "nginx" in snippet_platforms([])
    # Explicit request wins, even on a builder.
    assert snippet_platforms([detection_for("wix")], ["nginx"]) == ("nginx",)


def test_your_part_counts():
    findings = [
        Finding("csp", "CSP", Category.HEADERS, Status.FAIL, "", responsibility=PLATFORM),
        Finding("referrer", "R", Category.HEADERS, Status.WARN, "", responsibility=SETTINGS),
        Finding("mixed-content", "M", Category.CONTENT, Status.PASS, "", responsibility=YOU),
        Finding("cookies", "C", Category.COOKIES, Status.INFO, "", responsibility=PLATFORM),
    ]
    part = your_part(findings, [detection_for("wix")])
    assert (part.controllable, part.controllable_passed) == (2, 1)
    assert (part.open_you, part.open_settings, part.platform_issues) == (0, 1, 1)
    assert part.summary() == "1 of 2 checks you control pass · 1 issue controlled by Wix"


# --------------------------------------------------------------------------- #
# End to end through scan() and every output format
# --------------------------------------------------------------------------- #
def wix_scan(**kwargs):
    client = make_client(
        {"X-Wix-Request-Id": "1", "Strict-Transport-Security": "max-age=31536000"},
        body=WIX_HTML,
        set_cookies=["ssr-caching=1; max-age=20"],
        security_txt=None,
    )
    return scan("www.example.com", client=client, tls_probe=good_tls, **kwargs)


def test_scan_wix_site_keeps_grade_and_tags_findings():
    result = wix_scan()
    plain = wix_scan(detect=False)
    assert result.grade == plain.grade and result.score == plain.score  # honest grade
    assert result.primary_platform.platform == "wix"
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["csp"].responsibility == PLATFORM
    assert "Enterprise" in by_id["csp"].platform_steps
    assert by_id["csp"].platform_docs.startswith("https://support.wix.com/")
    assert by_id["security-txt"].responsibility == PLATFORM
    assert result.your_part.platform_issues >= 4
    assert plain.platforms == [] and plain.your_part.platform is None


def test_scan_with_platform_override():
    client = make_client({"Server": "nginx"})
    result = scan("example.com", client=client, tls_probe=None, platform="squarespace")
    assert result.primary_platform.confidence == "manual"
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["hsts"].responsibility == SETTINGS


def test_meta_referrer_counts_on_builders():
    html = WIX_HTML.replace(
        "</head>", '<meta name="referrer" content="strict-origin-when-cross-origin"></head>'
    )
    client = make_client({"X-Wix-Request-Id": "1"}, body=html)
    result = scan("example.com", client=client, tls_probe=None)
    referrer = next(f for f in result.findings if f.check_id == "referrer")
    assert referrer.status == Status.PASS
    assert "meta" in referrer.detail


def test_outputs_include_platform_and_your_part():
    result = wix_scan()
    data = result.to_dict()
    assert data["primary_platform"] == "wix"
    assert data["platforms"][0]["evidence"]
    assert data["your_part"]["platform"] == "Wix"
    assert {f["responsibility"] for f in data["findings"]} >= {PLATFORM, YOU}

    console = Console(file=io.StringIO(), width=120, force_terminal=False)
    render(result, console, explain=True)
    out = console.file.getvalue()
    assert "Platform: Wix (high confidence)" in out
    assert "Your part:" in out
    assert "On Wix (platform-controlled)" in out
    assert "snippets are hidden because Wix manages" in out
    assert "add_header" not in out and "Header always set" not in out  # no server snippets

    html = to_html([result])
    assert "Your part:" in html and "platform-controlled" in html and "Who fixes" in html

    sarif = to_sarif([result])
    run = sarif["runs"][0]
    assert run["properties"]["scans"][0]["platform"] == "wix"
    assert run["properties"]["scans"][0]["your_part"]["platform"] == "Wix"
    assert {r["properties"]["responsibility"] for r in run["results"]} >= {PLATFORM}
