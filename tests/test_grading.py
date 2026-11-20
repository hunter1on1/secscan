import pytest

from secscan.grading import grade_for, meets_minimum, score_findings
from secscan.models import Category, Finding, Status


def f(deduction=0, critical=False):
    return Finding(
        "x", "x", Category.HEADERS, Status.FAIL, "", deduction=deduction, critical=critical
    )


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (100, "A+"),
        (95, "A+"),
        (94, "A"),
        (85, "A"),
        (84, "B"),
        (70, "B"),
        (69, "C"),
        (55, "C"),
        (54, "D"),
        (40, "D"),
        (39, "F"),
        (0, "F"),
    ],
)
def test_grade_bands(score, grade):
    assert grade_for(score) == grade


def test_score_never_negative():
    assert score_findings([f(60), f(60)]) == 0


def test_critical_forces_f():
    assert grade_for(100, [f(critical=True)]) == "F"


def test_meets_minimum():
    assert meets_minimum("A+", "B")
    assert meets_minimum("B", "B")
    assert not meets_minimum("C", "B")
