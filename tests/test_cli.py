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


def test_ca_bundle_flag(fake_scan, tmp_path, capsys):
    import certifi

    bundle = certifi.where()
    cli.main(["good.example", "--ca-bundle", str(bundle), "--json"])
    assert fake_scan[0][1]["ca_bundle"] == str(bundle)


def test_missing_ca_bundle_is_an_error(fake_scan, capsys):
    with pytest.raises(SystemExit):
        cli.main(["good.example", "--ca-bundle", "/does/not/exist.pem"])


def test_unloadable_ca_bundle_is_an_error(fake_scan, tmp_path, capsys):
    bundle = tmp_path / "empty.pem"
    bundle.write_text("")
    with pytest.raises(SystemExit):
        cli.main(["good.example", "--ca-bundle", str(bundle)])
    assert "cannot load CA bundle" in capsys.readouterr().err


def test_html_and_sarif_files(fake_scan, tmp_path, capsys):
    html, sarif = tmp_path / "r.html", tmp_path / "r.sarif"
    assert cli.main(["good.example", "--json", "--html", str(html), "--sarif", str(sarif)]) == 0
    assert html.read_text().startswith("<!doctype html>")
    assert json.loads(sarif.read_text())["version"] == "2.1.0"
    captured = capsys.readouterr()
    json.loads(captured.out)  # stdout is still pure JSON
    assert "HTML report written" in captured.err


def test_platform_option_validation(capsys):
    with pytest.raises(SystemExit):
        cli.main(["good.example", "--platform", "iis"])
    assert "unknown platform" in capsys.readouterr().err


def test_explain_shows_snippets(monkeypatch, capsys):
    from secscan import scanner

    from .conftest import good_tls, make_client

    def _scan(target, **kwargs):
        return scanner.scan(target, client=make_client({}), tls_probe=good_tls)

    monkeypatch.setattr(cli, "scan", _scan)
    cli.main(["example.com", "--explain", "--platform", "nginx"])
    out = capsys.readouterr().out
    assert "How to fix" in out
    assert "add_header Strict-Transport-Security" in out
    assert "vercel.json" not in out  # filtered out by --platform


def test_default_output_is_concise(monkeypatch, capsys):
    from secscan import scanner

    from .conftest import good_tls, make_client

    monkeypatch.setattr(
        cli, "scan", lambda t, **kw: scanner.scan(t, client=make_client({}), tls_probe=good_tls)
    )
    cli.main(["example.com"])
    out = capsys.readouterr().out
    assert "Recommendations" in out and "--explain" in out
    assert "add_header" not in out


def test_platform_option_splits_hosting_and_snippets(fake_scan):
    cli.main(["good.example", "--json", "--platform", "wix,nginx"])
    assert fake_scan[-1][1]["platform"] == "wix"
    assert cli.split_platforms(["wix", "nginx"]) == ("wix", ["nginx"])
    assert cli.split_platforms(["netlify"]) == ("netlify", ["netlify"])
    assert cli.split_platforms(["apache"]) == (None, ["apache"])
    assert cli.split_platforms(None) == (None, None)


def test_only_one_hosting_platform(capsys):
    with pytest.raises(SystemExit):
        cli.main(["good.example", "--platform", "wix,shopify"])
    assert "one hosting platform" in capsys.readouterr().err


def test_no_detect_flag(fake_scan):
    cli.main(["good.example", "--json", "--no-detect"])
    assert fake_scan[-1][1]["detect"] is False
