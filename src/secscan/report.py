"""Render scan results for the terminal and as JSON.

HTML and SARIF output live in html_report.py and sarif.py.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from secscan.advice import PLATFORM_LABELS, PLATFORMS
from secscan.models import Finding, ScanResult, Status

STATUS_STYLE = {
    Status.PASS: ("PASS", "bold green"),
    Status.WARN: ("WARN", "bold yellow"),
    Status.FAIL: ("FAIL", "bold red"),
    Status.INFO: ("INFO", "cyan"),
}

GRADE_STYLE = {
    "A+": "bold green",
    "A": "green",
    "B": "yellow",
    "C": "dark_orange",
    "D": "red",
    "F": "bold red",
}

CATEGORY_LABELS = {
    "headers": "Headers",
    "cookies": "Cookies",
    "cors": "CORS",
    "content": "Content",
    "disclosure": "Disclosure",
    "tls": "TLS",
}

# Pygments lexer used to colour each platform's snippet.
_LEXERS = {"nginx": "nginx", "apache": "apacheconf", "vercel": "javascript"}


def to_json(results: Sequence[ScanResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2)


def needs_fix(finding: Finding) -> bool:
    return finding.status in (Status.WARN, Status.FAIL)


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _summary_panel(result: ScanResult) -> Panel:
    grade_text = Text(f" {result.grade} ", style=f"reverse {GRADE_STYLE.get(result.grade, '')}")
    title = Text.assemble("Grade ", grade_text, f"  score {result.score}/100")
    lines = [f"[bold]{result.target}[/bold]"]
    if result.final_url:
        lines.append(f"Final URL: {result.final_url} (HTTP {result.status_code})")
    if result.tls and result.tls.negotiated_version:
        lines.append(f"TLS: {result.tls.negotiated_version}")
    counts = {s: sum(f.status == s for f in result.findings) for s in Status}
    if result.findings:
        lines.append(
            f"[green]{counts[Status.PASS]} passed[/green] · "
            f"[yellow]{_plural(counts[Status.WARN], 'warning')}[/yellow] · "
            f"[red]{counts[Status.FAIL]} failed[/red] · "
            f"[cyan]{counts[Status.INFO]} info[/cyan]"
        )
    if result.error:
        lines.append(f"[red]Error: {result.error}[/red]")
    return Panel("\n".join(lines), title=title, title_align="left", expand=False)


def _findings_table(result: ScanResult) -> Table:
    table = Table(show_header=True, header_style="bold", expand=False)
    table.add_column("Status", no_wrap=True)
    table.add_column("Check")
    table.add_column("Details")
    table.add_column("Pts", justify="right")
    previous = None
    for f in result.findings:
        if f.category != previous:
            if previous is not None:
                table.add_section()
            # A label row per category keeps the table narrow enough for
            # an 80-column terminal.
            label = CATEGORY_LABELS[f.category.value].upper()
            table.add_row("", Text(label, style="bold magenta"), "", "")
            previous = f.category
        status, style = STATUS_STYLE[f.status]
        table.add_row(
            Text(status, style=style),
            f.title,
            f.detail,
            f"-{f.deduction}" if f.deduction else "",
        )
    return table


def _advice_panel(finding: Finding, platforms: Sequence[str]) -> Panel:
    advice = finding.advice
    assert advice is not None
    parts: list = [Text(advice.summary)]
    for platform in PLATFORMS:
        snippet = advice.snippets.get(platform)
        if snippet is None or platform not in platforms:
            continue
        parts.append(Text(f"\n{PLATFORM_LABELS[platform]}", style="bold"))
        parts.append(
            Syntax(
                snippet,
                _LEXERS.get(platform, "text"),
                theme="ansi_dark",
                background_color="default",
                word_wrap=True,
            )
        )
    if advice.references:
        parts.append(Text("\nLearn more:\n" + "\n".join(advice.references), style="dim"))
    label, style = STATUS_STYLE[finding.status]
    title = Text.assemble((f"{label} ", style), (finding.title, "bold"))
    return Panel(Group(*parts), title=title, title_align="left", border_style="dim")


def render(
    result: ScanResult,
    console: Console,
    verbose: bool = True,
    explain: bool = False,
    platforms: Sequence[str] = PLATFORMS,
) -> None:
    """Print one result.

    * default: summary, findings table, one-line recommendations
    * ``explain``: a panel per problem with copy-paste config snippets
    * ``verbose=False`` (``--quiet``): no recommendations at all
    """
    console.print(_summary_panel(result))
    if not result.findings:
        console.print()
        return
    console.print(_findings_table(result))

    fixes = [f for f in result.findings if needs_fix(f)]
    if explain and fixes:
        console.print("[bold]How to fix[/bold]")
        for f in fixes:
            if f.advice:
                console.print(_advice_panel(f, platforms))
    elif verbose and fixes:
        console.print("[bold]Recommendations[/bold]  [dim](run with --explain for config)[/dim]")
        for f in fixes:
            console.print(f"  • [bold]{f.title}[/bold]: {f.recommendation}")
    console.print()
