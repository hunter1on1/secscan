"""Command-line interface: ``secscan https://example.com``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from rich.console import Console

from secscan import __version__
from secscan.grading import GRADE_ORDER, meets_minimum
from secscan.report import render, to_json
from secscan.scanner import scan
from secscan.tls import probe_tls


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Grade a website's HTTP security headers and TLS configuration. "
        "Only scan sites you own or are authorised to test.",
    )
    parser.add_argument("targets", nargs="*", metavar="URL", help="URL(s) or hostname(s) to scan")
    parser.add_argument("-f", "--file", help="read targets from a file (one per line, # comments)")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument(
        "--no-tls", action="store_true", help="skip certificate and protocol checks (headers only)"
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds")
    parser.add_argument(
        "--min-grade",
        choices=GRADE_ORDER,
        help="exit with status 1 if any target grades below this (useful in CI)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="hide recommendations")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def read_targets(path: str) -> list[str]:
    with open(path, encoding="utf-8") as handle:
        lines = (line.split("#", 1)[0].strip() for line in handle)
        return [line for line in lines if line]


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    targets = list(args.targets)
    if args.file:
        try:
            targets += read_targets(args.file)
        except OSError as exc:
            parser.error(f"cannot read {args.file}: {exc}")
    if not targets:
        parser.error("give at least one URL or --file")

    console = Console()
    tls_probe = None if args.no_tls else probe_tls
    results = []
    for target in targets:
        if args.json:
            result = scan(target, timeout=args.timeout, tls_probe=tls_probe)
        else:
            # Show a spinner while the network calls run.
            with console.status(f"Scanning {target}..."):
                result = scan(target, timeout=args.timeout, tls_probe=tls_probe)
            render(result, console, verbose=not args.quiet)
        results.append(result)

    if args.json:
        print(to_json(results))

    if any(r.error and not r.status_code for r in results):
        exit_code = 2
    elif args.min_grade and not all(meets_minimum(r.grade, args.min_grade) for r in results):
        exit_code = 1
    else:
        exit_code = 0
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
