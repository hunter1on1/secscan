"""SARIF 2.1.0 output, so findings can appear in GitHub code scanning.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard that
GitHub, Azure DevOps and many IDEs read. A SARIF log has one *run* per tool
invocation; each run lists the *rules* the tool knows about and the
*results* (problems) it found.

GitHub needs every result to point at a file in the repository. A website is
not a file, so results point at ``artifact_uri``: by default the targets file
(when ``--file`` is used), otherwise the scanned URL. Pass
``--sarif-artifact`` to point alerts at, say, your nginx.conf instead.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

from secscan import __version__
from secscan.advice import PLATFORM_LABELS, PLATFORMS, RULES, Rule
from secscan.models import Finding, ScanResult, Status

SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/hunter1on1/secscan"

_LEVELS = {Status.FAIL: "error", Status.WARN: "warning"}


def _rule_markdown(rule: Rule) -> str:
    """Help text GitHub shows next to an alert: explanation plus snippets."""
    lines = [rule.advice.summary, ""]
    for platform in PLATFORMS:
        snippet = rule.advice.snippets.get(platform)
        if snippet:
            lines += [f"**{PLATFORM_LABELS[platform]}**", "", "```", snippet, "```", ""]
    if rule.advice.references:
        lines.append("References: " + ", ".join(rule.advice.references))
    return "\n".join(lines).strip()


def _rule_descriptor(rule: Rule) -> dict:
    return {
        "id": rule.id,
        "name": "".join(word.capitalize() for word in rule.id.replace(".", "").split("-")),
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.advice.summary, "markdown": _rule_markdown(rule)},
        "helpUri": rule.advice.references[0] if rule.advice.references else INFORMATION_URI,
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["security", "web"],
            "precision": "high",
            # GitHub maps this to critical / high / medium / low.
            "security-severity": f"{rule.security_severity:.1f}",
        },
    }


def _fingerprint(target_url: str, check_id: str) -> str:
    """Stable ID so re-scans update the same alert instead of opening new ones."""
    return hashlib.sha256(f"{target_url}|{check_id}".encode()).hexdigest()


def _result(finding: Finding, scan: ScanResult, rule_index: int, artifact_uri: str) -> dict:
    url = scan.final_url or scan.target
    message = f"{url}: {finding.title}: {finding.detail}"
    if finding.platform_steps and scan.platforms:
        message += f" Fix on {scan.platforms[0].name}: {finding.platform_steps}"
    elif finding.recommendation:
        message += f" Fix: {finding.recommendation}"
    return {
        "ruleId": finding.check_id,
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.status],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"fullyQualifiedName": url, "kind": "resource"}],
            }
        ],
        "partialFingerprints": {"secscanFinding/v1": _fingerprint(url, finding.check_id)},
        "properties": {
            "target": scan.target,
            "url": url,
            "grade": scan.grade,
            "deduction": finding.deduction,
            "category": finding.category.value,
            "responsibility": finding.responsibility,
            "platform": scan.platforms[0].platform if scan.platforms else None,
        },
    }


def to_sarif(results: Sequence[ScanResult], artifact_uri: str | None = None) -> dict:
    """Build a SARIF log. Only WARN and FAIL findings become SARIF results."""
    rule_ids = list(RULES)
    sarif_results = []
    for scan in results:
        uri = artifact_uri or scan.final_url or scan.target
        for finding in scan.findings:
            if finding.status in _LEVELS and finding.check_id in RULES:
                index = rule_ids.index(finding.check_id)
                sarif_results.append(_result(finding, scan, index, uri))

    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secscan",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule_descriptor(RULES[i]) for i in rule_ids],
                    }
                },
                "results": sarif_results,
                "properties": {
                    "scans": [
                        {
                            "target": r.target,
                            "grade": r.grade,
                            "score": r.score,
                            "error": r.error,
                            "platform": r.platforms[0].platform if r.platforms else None,
                            "your_part": r.your_part.to_dict() if r.your_part else None,
                        }
                        for r in results
                    ]
                },
            }
        ],
    }


def write_sarif(path: str, results: Sequence[ScanResult], artifact_uri: str | None = None) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(to_sarif(results, artifact_uri), handle, indent=2)
        handle.write("\n")
