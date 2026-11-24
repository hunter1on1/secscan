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
from secscan.platforms import RESPONSIBILITY_LABELS, describe, snippet_platforms

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
    "restaurant": "Restaurant & privacy compliance",
}

# Who-can-fix labels, short enough for the table.
WHO_STYLE = {
    "you": ("you", "green"),
    "settings": ("settings", "yellow"),
    "platform": ("platform", "magenta"),
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
    if result.platforms:
        primary = result.platforms[0]
        lines.append(f"Platform: {describe(result.platforms)}")
        lines.append(f"[dim]  evidence: {', '.join(primary.evidence)}[/dim]")
    if result.your_part and result.platforms and result.findings:
        lines.append(f"[bold]Your part:[/bold] {result.your_part.summary()}")
    if result.compliance:
        lines.append(
            f"[bold]Compliance:[/bold] {result.compliance.summary()}  "
            f"[dim](restaurant profile; not legal advice)[/dim]"
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
    # "Who fixes it" only means something once a platform is known.
    show_who = bool(result.platforms)
    if show_who:
        table.add_column("Who")
    previous = None
    for f in result.findings:
        if f.category != previous:
            if previous is not None:
                table.add_section()
            # A label row per category keeps the table narrow enough for
            # an 80-column terminal.
            label = CATEGORY_LABELS[f.category.value].upper()
            table.add_row("", Text(label, style="bold magenta"), "", "", *([""] * show_who))
            previous = f.category
        status, style = STATUS_STYLE[f.status]
        row = [
            Text(status, style=style),
            f.title,
            f.detail,
            f"-{f.deduction}" if f.deduction else "",
        ]
        if show_who:
            who, who_style = WHO_STYLE[f.responsibility]
            row.append(Text(who, style=who_style) if needs_fix(f) else "")
        table.add_row(*row)
    return table


def platform_line(finding: Finding, platform_name: str) -> str:
    """'On Wix (platform-controlled): ...' for recommendations."""
    label = RESPONSIBILITY_LABELS[finding.responsibility]
    return f"On {platform_name} ({label}): {finding.platform_steps}"


def _advice_panel(finding: Finding, platforms: Sequence[str], platform_name: str = "") -> Panel:
    advice = finding.advice
    assert advice is not None
    parts: list = [Text(advice.summary)]
    if finding.platform_steps:
        # Platform-specific steps come first: they are what you can actually do.
        parts.append(Text(f"\n{platform_line(finding, platform_name)}", style="bold"))
        if finding.platform_docs:
            parts.append(Text(f"Docs: {finding.platform_docs}", style="dim"))
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
    platforms: Sequence[str] | None = None,
) -> None:
    """Print one result.

    * default: summary, findings table, one-line recommendations
    * ``explain``: a panel per problem with copy-paste config snippets
    * ``verbose=False`` (``--quiet``): no recommendations at all

    `platforms` lists the snippet formats to show (nginx, apache, ...). By
    default they are chosen from the detected hosting platform.
    """
    shown = snippet_platforms(result.platforms, platforms)
    platform_name = result.platforms[0].name if result.platforms else ""
    console.print(_summary_panel(result))
    if not result.findings:
        console.print()
        return
    console.print(_findings_table(result))

    fixes = [f for f in result.findings if needs_fix(f)]
    if explain and fixes:
        console.print("[bold]How to fix[/bold]")
        if not shown:
            console.print(
                f"[dim]Server config snippets are hidden because {platform_name} manages the "
                "servers; add --platform nginx (or apache, cloudflare, ...) to show them.[/dim]"
            )
        for f in fixes:
            if f.advice:
                console.print(_advice_panel(f, shown, platform_name))
    elif verbose and fixes:
        console.print("[bold]Recommendations[/bold]  [dim](run with --explain for details)[/dim]")
        for f in fixes:
            if f.platform_steps:
                console.print(
                    f"  • [bold]{f.title}[/bold]: {platform_line(f, platform_name)}",
                    highlight=False,
                )
            else:
                console.print(f"  • [bold]{f.title}[/bold]: {f.recommendation}")
    console.print()
