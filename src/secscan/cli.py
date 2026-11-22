"""Command-line interface: ``secscan https://example.com``."""

from __future__ import annotations

import argparse
import os
import ssl
import sys
from collections.abc import Sequence

from rich.console import Console

from secscan import __version__
from secscan.advice import PLATFORMS
from secscan.grading import GRADE_ORDER, meets_minimum
from secscan.html_report import write_html
from secscan.report import render, to_json
from secscan.sarif import write_sarif
from secscan.scanner import scan
from secscan.tls import create_verified_context, probe_tls, resolve_ca_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Grade a website's security headers, cookies, CORS, mixed content, "
        "security.txt and TLS configuration. Only scan sites you own or are authorised "
        "to test.",
    )
    parser.add_argument("targets", nargs="*", metavar="URL", help="URL(s) or hostname(s) to scan")
    parser.add_argument("-f", "--file", help="read targets from a file (one per line, # comments)")
    output = parser.add_argument_group("output")
    output.add_argument("--json", action="store_true", help="print results as JSON to stdout")
    output.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    output.add_argument("--sarif", metavar="PATH", help="write SARIF 2.1.0 (GitHub code scanning)")
    output.add_argument(
        "--sarif-artifact",
        metavar="PATH",
        help="repository file SARIF alerts point at (default: the --file targets file, "
        "else the scanned URL)",
    )
    output.add_argument(
        "--explain",
        action="store_true",
        help="show how to fix each problem, with config snippets",
    )
    output.add_argument(
        "--platform",
        type=_platforms,
        default=list(PLATFORMS),
        metavar="LIST",
        help=f"limit --explain snippets to these platforms, comma separated "
        f"({', '.join(PLATFORMS)})",
    )
    parser.add_argument(
        "--no-tls", action="store_true", help="skip certificate and protocol checks (headers only)"
    )
    parser.add_argument(
        "--ca-bundle",
        metavar="PATH",
        help="PEM file of trusted CA certificates (default: $SSL_CERT_FILE, else certifi)",
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


def _platforms(value: str) -> list[str]:
    chosen = [p.strip().lower() for p in value.split(",") if p.strip()]
    unknown = [p for p in chosen if p not in PLATFORMS]
    if unknown or not chosen:
        raise argparse.ArgumentTypeError(
            f"unknown platform(s) {', '.join(unknown) or value!r}; "
            f"choose from {', '.join(PLATFORMS)}"
        )
    return chosen


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
    if args.ca_bundle and not os.path.isfile(args.ca_bundle):
        parser.error(f"CA bundle not found: {args.ca_bundle}")
    try:
        # Fail early with a clear message if the bundle (or SSL_CERT_FILE) is unusable.
        create_verified_context(args.ca_bundle)
    except (ssl.SSLError, OSError) as exc:
        parser.error(f"cannot load CA bundle {resolve_ca_bundle(args.ca_bundle)}: {exc}")

    console = Console()
    tls_probe = None if args.no_tls else probe_tls
    results = []
    for target in targets:
        if args.json:
            result = scan(
                target, timeout=args.timeout, tls_probe=tls_probe, ca_bundle=args.ca_bundle
            )
        else:
            # Show a spinner while the network calls run.
            with console.status(f"Scanning {target}..."):
                result = scan(
                    target, timeout=args.timeout, tls_probe=tls_probe, ca_bundle=args.ca_bundle
                )
            render(
                result,
                console,
                verbose=not args.quiet,
                explain=args.explain,
                platforms=args.platform,
            )
        results.append(result)

    if args.json:
        print(to_json(results))
    # Report files: status messages go to stderr so --json stdout stays clean.
    if args.html:
        write_html(args.html, results)
        Console(stderr=True).print(f"[green]HTML report written to {args.html}[/green]")
    if args.sarif:
        write_sarif(args.sarif, results, args.sarif_artifact or args.file)
        Console(stderr=True).print(f"[green]SARIF written to {args.sarif}[/green]")

    if any(r.error and not r.status_code for r in results):
        exit_code = 2
    elif args.min_grade and not all(meets_minimum(r.grade, args.min_grade) for r in results):
        exit_code = 1
    else:
        exit_code = 0
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
