"""Turn findings into a 0-100 score and a letter grade.

The scheme is intentionally simple and transparent (see README "How grading
works"): every site starts at 100 points, each finding removes a fixed number
of points, and any *critical* finding (e.g. an untrusted certificate) forces
an F no matter what the score is.
"""

from __future__ import annotations

from collections.abc import Iterable

from secscan.models import Finding

# (minimum score, grade), checked from the top down.
GRADE_BANDS: list[tuple[int, str]] = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (0, "F"),
]

GRADE_ORDER = [grade for _, grade in GRADE_BANDS]  # best first


def score_findings(findings: Iterable[Finding]) -> int:
    """100 minus every deduction, never below 0."""
    return max(0, 100 - sum(f.deduction for f in findings))


def grade_for(score: int, findings: Iterable[Finding] = ()) -> str:
    if any(f.critical for f in findings):
        return "F"
    for minimum, grade in GRADE_BANDS:
        if score >= minimum:
            return grade
    return "F"


def meets_minimum(grade: str, minimum: str) -> bool:
    """True if `grade` is at least as good as `minimum` (e.g. "A" meets "B")."""
    return GRADE_ORDER.index(grade) <= GRADE_ORDER.index(minimum)
