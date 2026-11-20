"""Data structures shared by every check.

Keeping findings as plain dataclasses means the same result can be rendered
as a terminal table, serialised to JSON, or asserted on in tests.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Status(str, Enum):
    """Outcome of a single check."""

    PASS = "pass"  # configured correctly
    WARN = "warn"  # present but weak, or a minor issue
    FAIL = "fail"  # missing or insecure
    INFO = "info"  # worth knowing, does not affect the score


class Category(str, Enum):
    HEADERS = "headers"
    TLS = "tls"


@dataclass
class Finding:
    """One result line, e.g. "HSTS missing" plus how to fix it."""

    check_id: str
    title: str
    category: Category
    status: Status
    detail: str
    recommendation: str = ""
    deduction: int = 0  # points removed from the 100-point score
    critical: bool = False  # a critical finding caps the grade at F

    def to_dict(self) -> dict:
        data = asdict(self)
        data["category"] = self.category.value
        data["status"] = self.status.value
        return data


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    not_after: str = ""  # ISO-8601 date
    days_remaining: int | None = None
    valid: bool = False
    error: str = ""  # verification error message, if any


@dataclass
class TLSInfo:
    host: str
    port: int = 443
    reachable: bool = False
    negotiated_version: str = ""
    certificate: CertificateInfo = field(default_factory=CertificateInfo)
    # protocol name -> True (accepted) / False (refused) / None (could not test)
    protocols: dict[str, bool | None] = field(default_factory=dict)
    error: str = ""


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status_code: int | None = None
    score: int = 0
    grade: str = "F"
    findings: list[Finding] = field(default_factory=list)
    tls: TLSInfo | None = None
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "score": self.score,
            "grade": self.grade,
            "error": self.error,
            "tls": asdict(self.tls) if self.tls else None,
            "findings": [f.to_dict() for f in self.findings],
        }
