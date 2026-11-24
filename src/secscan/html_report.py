"""Self-contained HTML report: one file, inline CSS, no JavaScript, no
external assets, so it can be emailed, archived or opened offline.

Every value that comes from the scanned site (headers, URLs, cookie names...)
is escaped with :func:`html.escape`. A security tool that writes an HTML
report must not itself be vulnerable to XSS from the sites it scans!
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from html import escape

from secscan import __version__
from secscan.advice import PLATFORM_LABELS, PLATFORMS
from secscan.models import Finding, ScanResult, Status
from secscan.platforms import RESPONSIBILITY_LABELS, describe, snippet_platforms
from secscan.report import CATEGORY_LABELS, needs_fix

_GRADE_CLASS = {"A+": "a", "A": "a", "B": "b", "C": "c", "D": "d", "F": "f"}

CSS = """
:root {
  --bg: #f6f7f9; --card: #fff; --text: #1d2330; --muted: #5d6677; --line: #e3e6eb;
  --pass: #16794c; --pass-bg: #e3f5ec; --warn: #8a5a00; --warn-bg: #fff3d6;
  --fail: #b42318; --fail-bg: #fde7e5; --info: #175cd3; --info-bg: #e6efff;
  --code-bg: #0f172a; --code-text: #e2e8f0;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --card: #161b22; --text: #e6edf3; --muted: #9aa4b2; --line: #2a313c;
    --pass-bg: #12301f; --pass: #5bd08f; --warn-bg: #3a2c06; --warn: #f0c15a;
    --fail-bg: #3d1311; --fail: #ff8a80; --info-bg: #0f2547; --info: #8ab4ff;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial,
  sans-serif; }
main { max-width: 1040px; margin: 0 auto; padding: 32px 20px 56px; }
header.top { display: flex; justify-content: space-between; align-items: baseline;
  flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }
header.top h1 { margin: 0; font-size: 24px; letter-spacing: -0.01em; }
header.top h1 span { color: var(--muted); font-weight: 500; }
.meta { color: var(--muted); font-size: 13px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px;
  padding: 22px 24px; margin-bottom: 20px; }
.summary { display: grid; grid-template-columns: auto 1fr; gap: 24px; align-items: center; }
.grade { width: 96px; height: 96px; border-radius: 16px; display: grid; place-items: center;
  font-size: 40px; font-weight: 750; color: #fff; }
.grade.a { background: #16794c; } .grade.b { background: #5f8f00; }
.grade.c { background: #c27c00; } .grade.d { background: #d14f00; }
.grade.f { background: #b42318; }
.summary h2 { margin: 0 0 4px; font-size: 20px; word-break: break-all; }
.score { margin: 10px 0 6px; height: 8px; border-radius: 4px; background: var(--line);
  overflow: hidden; }
.score > div { height: 100%; background: currentColor; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.pill { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px;
  font-weight: 650; letter-spacing: 0.02em; white-space: nowrap; }
.pill.pass { background: var(--pass-bg); color: var(--pass); }
.pill.warn { background: var(--warn-bg); color: var(--warn); }
.pill.fail { background: var(--fail-bg); color: var(--fail); }
.pill.info { background: var(--info-bg); color: var(--info); }
.error { color: var(--fail); font-weight: 600; }
.who { display: inline-block; padding: 1px 8px; border-radius: 6px; font-size: 12px;
  white-space: nowrap; border: 1px solid var(--line); }
.who-you { color: var(--pass); } .who-settings { color: var(--warn); }
.who-platform { color: var(--muted); }
.yourpart { margin-top: 10px; font-size: 14px; }
.platform-steps { border-left: 3px solid var(--info); padding: 6px 12px; margin: 10px 0;
  background: var(--bg); border-radius: 0 6px 6px 0; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.04em; }
td.pts { text-align: right; font-variant-numeric: tabular-nums; color: var(--fail);
  white-space: nowrap; }
td.detail { word-break: break-word; }
tr.cat td { background: var(--bg); font-weight: 700; font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--muted); }
h3 { margin: 26px 0 12px; font-size: 16px; }
details { border: 1px solid var(--line); border-radius: 10px; margin-bottom: 10px;
  background: var(--card); }
details > summary { cursor: pointer; padding: 12px 14px; font-weight: 600; list-style: none;
  display: flex; gap: 10px; align-items: center; }
details > summary::-webkit-details-marker { display: none; }
details > summary::after { content: "+"; margin-left: auto; color: var(--muted); }
details[open] > summary::after { content: "\\2212"; }
details .body { padding: 0 16px 14px; }
.platform { margin: 12px 0 4px; font-size: 12px; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.05em; }
pre { margin: 0; padding: 12px 14px; background: var(--code-bg); color: var(--code-text);
  border-radius: 8px; overflow-x: auto; font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo,
  Consolas, monospace; white-space: pre; }
a { color: var(--info); }
.overview td:first-child { word-break: break-all; }
footer { color: var(--muted); font-size: 12.5px; margin-top: 32px; }
@media print {
  body { background: #fff; } .card, details { break-inside: avoid; }
  details > summary::after { content: none; }
  pre { white-space: pre-wrap; word-break: break-all; }
}
@media (max-width: 640px) { .summary { grid-template-columns: 1fr; } }
"""


def _pill(status: Status) -> str:
    return f'<span class="pill {status.value}">{status.value.upper()}</span>'


def _anchor(index: int) -> str:
    return f"target-{index + 1}"


def _overview(results: Sequence[ScanResult]) -> str:
    show_compliance = any(r.compliance for r in results)
    rows = []
    for i, r in enumerate(results):
        counts = {s: sum(f.status == s for f in r.findings) for s in Status}
        extra = ""
        if show_compliance:
            if r.compliance:
                extra = (
                    f"<td><strong>{escape(r.compliance.grade)}</strong> "
                    f"{r.compliance.score}/100</td>"
                )
            else:
                extra = "<td>&mdash;</td>"
        rows.append(
            f'<tr><td><a href="#{_anchor(i)}">{escape(r.target)}</a></td>'
            f"<td><strong>{escape(r.grade)}</strong></td><td>{r.score}/100</td>"
            f"<td>{counts[Status.FAIL]}</td><td>{counts[Status.WARN]}</td>"
            f"<td>{escape(r.platforms[0].name) if r.platforms else '&mdash;'}</td>"
            f"{extra}</tr>"
        )
    compliance_head = "<th>Compliance</th>" if show_compliance else ""
    return (
        '<section class="card overview"><table><thead><tr><th>Target</th><th>Grade</th>'
        "<th>Score</th><th>Failed</th><th>Warnings</th><th>Platform</th>"
        f"{compliance_head}</tr></thead><tbody>" + "".join(rows) + "</tbody></table></section>"
    )


def _summary(r: ScanResult, index: int) -> str:
    grade_class = _GRADE_CLASS.get(r.grade, "f")
    meta = []
    if r.final_url:
        meta.append(f"Final URL: {escape(r.final_url)} (HTTP {r.status_code})")
    if r.tls and r.tls.negotiated_version:
        cert = r.tls.certificate
        tls_line = f"TLS: {escape(r.tls.negotiated_version)}"
        if cert.valid and cert.issuer:
            tls_line += f" &middot; certificate by {escape(cert.issuer)}, expires {cert.not_after}"
        meta.append(tls_line)
    counts = {s: sum(f.status == s for f in r.findings) for s in Status}
    chips = "".join(
        f'<span class="pill {s.value}">{counts[s]} {label}</span>'
        for s, label in (
            (Status.PASS, "passed"),
            (Status.WARN, "warning" if counts[Status.WARN] == 1 else "warnings"),
            (Status.FAIL, "failed"),
            (Status.INFO, "info"),
        )
    )
    error = f'<div class="error">Error: {escape(r.error)}</div>' if r.error else ""
    platform = ""
    if r.platforms:
        evidence = ", ".join(r.platforms[0].evidence)
        platform = (
            f'<div class="meta" title="Evidence: {escape(evidence)}">Platform: '
            f"<strong>{escape(describe(r.platforms))}</strong> &middot; evidence: "
            f"{escape(evidence)}</div>"
        )
        if r.your_part and r.findings:
            platform += (
                f'<div class="yourpart"><strong>Your part:</strong> '
                f"{escape(r.your_part.summary())}</div>"
            )
    if r.compliance:
        platform += (
            f'<div class="yourpart"><strong>Compliance:</strong> '
            f"{escape(r.compliance.summary())} "
            f'<span class="meta">(restaurant profile; not legal advice)</span></div>'
        )
    color = {"a": "#16794c", "b": "#5f8f00", "c": "#c27c00", "d": "#d14f00"}.get(
        grade_class, "#b42318"
    )
    return (
        f'<div class="summary"><div class="grade {grade_class}" aria-label="Grade">'
        f"{escape(r.grade)}</div><div><h2>{escape(r.target)}</h2>"
        f'<div class="meta">{"<br>".join(meta)}</div>'
        f'<div class="score" style="color:{color}" title="Score {r.score}/100">'
        f'<div style="width:{r.score}%"></div></div>'
        f'<div class="meta">Score <strong>{r.score}</strong>/100</div>'
        f'<div class="chips">{chips}</div>{platform}{error}</div></div>'
    )


def _who(f: Finding) -> str:
    label = RESPONSIBILITY_LABELS[f.responsibility]
    return f'<span class="who who-{f.responsibility}">{escape(label)}</span>'


def _findings_table(findings: Sequence[Finding], show_who: bool = False) -> str:
    rows = []
    previous = None
    columns = 5 if show_who else 4
    for f in findings:
        if f.category != previous:
            rows.append(
                f'<tr class="cat"><td colspan="{columns}">'
                f"{CATEGORY_LABELS[f.category.value]}</td></tr>"
            )
            previous = f.category
        pts = f"&minus;{f.deduction}" if f.deduction else ""
        who = f"<td>{_who(f) if needs_fix(f) else ''}</td>" if show_who else ""
        rows.append(
            f"<tr><td>{_pill(f.status)}</td><td>{escape(f.title)}</td>"
            f'<td class="detail">{escape(f.detail)}</td><td class="pts">{pts}</td>{who}</tr>'
        )
    who_head = "<th>Who fixes</th>" if show_who else ""
    return (
        "<table><thead><tr><th>Status</th><th>Check</th><th>Details</th><th>Pts</th>"
        f"{who_head}</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _link(url: str) -> str:
    return f'<a href="{escape(url)}" rel="noopener noreferrer">{escape(url)}</a>'


def _advice(f: Finding, shown: Sequence[str] = PLATFORMS, platform_name: str = "") -> str:
    if f.advice is None:
        return ""
    parts = [f"<p>{escape(f.advice.summary)}</p>"]
    if f.platform_steps:
        docs = (
            f'<br><span class="meta">Docs: {_link(f.platform_docs)}</span>'
            if f.platform_docs
            else ""
        )
        parts.append(
            f'<div class="platform-steps"><strong>On {escape(platform_name)}</strong> '
            f"{_who(f)}<br>{escape(f.platform_steps)}{docs}</div>"
        )
    for platform in PLATFORMS:
        snippet = f.advice.snippets.get(platform)
        if snippet and platform in shown:
            parts.append(
                f'<div class="platform">{escape(PLATFORM_LABELS[platform])}</div>'
                f"<pre><code>{escape(snippet)}</code></pre>"
            )
    if f.advice.references:
        links = ", ".join(_link(u) for u in f.advice.references)
        parts.append(f'<p class="meta">Learn more: {links}</p>')
    is_open = " open" if f.status == Status.FAIL else ""
    pts = f' <span class="meta">&minus;{f.deduction} pts</span>' if f.deduction else ""
    return (
        f"<details{is_open}><summary>{_pill(f.status)} {escape(f.title)}{pts}</summary>"
        f'<div class="body"><p class="meta">{escape(f.detail)}</p>{"".join(parts)}</div>'
        "</details>"
    )


def _section(r: ScanResult, index: int) -> str:
    fixes = [f for f in r.findings if needs_fix(f)]
    body = [f'<section class="card" id="{_anchor(index)}">', _summary(r, index)]
    shown = snippet_platforms(r.platforms)
    name = r.platforms[0].name if r.platforms else ""
    if r.findings:
        body += ["<h3>Findings</h3>", _findings_table(r.findings, bool(r.platforms))]
    if fixes:
        body += ["<h3>How to fix</h3>", *(_advice(f, shown, name) for f in fixes)]
    body.append("</section>")
    return "".join(body)


def to_html(results: Sequence[ScanResult], generated: datetime | None = None) -> str:
    generated = generated or datetime.now().astimezone()
    stamp = generated.strftime("%Y-%m-%d %H:%M %Z").strip()
    title = "secscan report" + (f": {results[0].target}" if len(results) == 1 else "")
    overview = _overview(results) if len(results) > 1 else ""
    sections = "".join(_section(r, i) for i, r in enumerate(results))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="secscan {__version__}">
<title>{escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<header class="top">
  <h1>secscan <span>security report</span></h1>
  <div class="meta">Generated {escape(stamp)} &middot; secscan {__version__}</div>
</header>
{overview}
{sections}
<footer>
  Grades follow the transparent scoring scheme documented at
  <a href="https://github.com/hunter1on1/secscan#how-grading-works">github.com/hunter1on1/secscan</a>.
  secscan performs passive checks only. Scan only sites you own or are authorised to test.
</footer>
</main>
</body>
</html>
"""


def write_html(path: str, results: Sequence[ScanResult]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(to_html(results))
