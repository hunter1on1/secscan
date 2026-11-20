"""Render scan results as a rich terminal report or as JSON."""

from __future__ import annotations

import json
from collections.abc import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secscan.models import ScanResult, Status

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


def to_json(results: Sequence[ScanResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2)


def render(result: ScanResult, console: Console, verbose: bool = True) -> None:
    """Print one result: a header panel, a findings table, and fixes."""
    grade_text = Text(f" {result.grade} ", style=f"reverse {GRADE_STYLE.get(result.grade, '')}")
    title = Text.assemble("Grade ", grade_text, f"  score {result.score}/100")
    lines = [f"[bold]{result.target}[/bold]"]
    if result.final_url:
        lines.append(f"Final URL: {result.final_url} (HTTP {result.status_code})")
    if result.tls and result.tls.negotiated_version:
        lines.append(f"TLS: {result.tls.negotiated_version}")
    if result.error:
        lines.append(f"[red]Error: {result.error}[/red]")
    console.print(Panel("\n".join(lines), title=title, title_align="left", expand=False))

    if not result.findings:
        return

    table = Table(show_header=True, header_style="bold", expand=False)
    table.add_column("Status", no_wrap=True)
    table.add_column("Check")
    table.add_column("Details")
    table.add_column("Pts", justify="right")
    for f in result.findings:
        label, style = STATUS_STYLE[f.status]
        table.add_row(
            Text(label, style=style), f.title, f.detail, f"-{f.deduction}" if f.deduction else ""
        )
    console.print(table)

    fixes = [f for f in result.findings if f.recommendation and f.status != Status.PASS]
    if verbose and fixes:
        console.print("[bold]Recommendations[/bold]")
        for f in fixes:
            console.print(f"  • [bold]{f.title}[/bold]: {f.recommendation}")
    console.print()
