import json

import pytest

from secscan import cli
from secscan.models import ScanResult


@pytest.fixture
def fake_scan(monkeypatch):
    """Replace the network scan with canned grades keyed by target."""
    grades = {"good.example": "A", "bad.example": "D"}
    seen = []

    def _scan(target, **kwargs):
        seen.append((target, kwargs))
        return ScanResult(
            target=target,
            final_url=f"https://{target}/",
            status_code=200,
            score=90,
            grade=grades.get(target, "B"),
        )

    monkeypatch.setattr(cli, "scan", _scan)
    return seen


def test_json_output(fake_scan, capsys):
    assert cli.main(["good.example", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["grade"] == "A"


def test_targets_from_file(fake_scan, tmp_path, capsys):
    targets = tmp_path / "targets.txt"
    targets.write_text("# my sites\ngood.example\n\nbad.example  # staging\n")
    cli.main(["--file", str(targets), "--json"])
    assert [t for t, _ in fake_scan] == ["good.example", "bad.example"]


def test_min_grade_exit_code(fake_scan, capsys):
    assert cli.main(["good.example", "--min-grade", "B", "--json"]) == 0
    assert cli.main(["good.example", "bad.example", "--min-grade", "B", "--json"]) == 1


def test_no_tls_flag(fake_scan, capsys):
    cli.main(["good.example", "--no-tls", "--json"])
    assert fake_scan[0][1]["tls_probe"] is None


def test_table_output(fake_scan, capsys):
    cli.main(["good.example"])
    assert "good.example" in capsys.readouterr().out


def test_no_targets_is_an_error(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
