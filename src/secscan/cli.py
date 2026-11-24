"""Command-line interface: ``secscan https://example.com``."""

from __future__ import annotations

import argparse
import os
import ssl
import sys
from collections.abc import Sequence

from rich.console import Console

from secscan import __version__
from secscan.advice import PLATFORMS as SNIPPET_FORMATS
from secscan.grading import GRADE_ORDER, meets_minimum
from secscan.html_report import write_html
from secscan.platforms import PLATFORMS as HOSTING_PLATFORMS
from secscan.report import render, to_json
from secscan.restaurant import PROFILES
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
    platform = parser.add_argument_group("platform")
    platform.add_argument(
        "--platform",
        type=_platforms,
        default=None,
        metavar="LIST",
        help="comma separated. A hosting platform "
        f"({', '.join(HOSTING_PLATFORMS)}) overrides detection; config formats "
        f"({', '.join(SNIPPET_FORMATS)}) choose which --explain snippets to show",
    )
    platform.add_argument(
        "--no-detect",
        action="store_true",
        help="don't detect the hosting platform (generic advice, everything 'you can fix')",
    )
    parser.add_argument(
        "--profile",
        choices=PROFILES,
        help="extra checks for that kind of site. 'restaurant' adds cookie consent, "
        "privacy policy, forms and booking widgets, and a separate compliance score "
        "(the security grade does not change)",
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
    known = [*HOSTING_PLATFORMS, *(p for p in SNIPPET_FORMATS if p not in HOSTING_PLATFORMS)]
    chosen = [p.strip().lower() for p in value.split(",") if p.strip()]
    unknown = [p for p in chosen if p not in known]
    if unknown or not chosen:
        raise argparse.ArgumentTypeError(
            f"unknown platform(s) {', '.join(unknown) or value!r}; choose from {', '.join(known)}"
        )
    hosting = [p for p in chosen if p in HOSTING_PLATFORMS]
    if len(hosting) > 1:
        raise argparse.ArgumentTypeError(f"choose one hosting platform, not {', '.join(hosting)}")
    return chosen


def split_platforms(chosen: Sequence[str] | None) -> tuple[str | None, list[str] | None]:
    """Split --platform values into (hosting override, snippet formats).

    "netlify", "vercel" and "cloudflare" are both a host and a config format,
    so they count as both.
    """
    if not chosen:
        return None, None
    hosting = next((p for p in chosen if p in HOSTING_PLATFORMS), None)
    snippets = [p for p in chosen if p in SNIPPET_FORMATS]
    return hosting, snippets or None


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
    hosting, snippets = split_platforms(args.platform)

    def run(target: str):
        return scan(
            target,
            timeout=args.timeout,
            tls_probe=tls_probe,
            ca_bundle=args.ca_bundle,
            platform=hosting,
            detect=not args.no_detect,
            profile=args.profile,
        )

    results = []
    for target in targets:
        if args.json:
            result = run(target)
        else:
            # Show a spinner while the network calls run.
            with console.status(f"Scanning {target}..."):
                result = run(target)
            render(
                result,
                console,
                verbose=not args.quiet,
                explain=args.explain,
                platforms=snippets,
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
