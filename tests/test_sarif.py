import json
from pathlib import Path

import jsonschema
import pytest

from secscan.sarif import to_sarif, write_sarif
from secscan.scanner import scan

from .conftest import good_tls, make_client

SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text())


@pytest.fixture
def weak_result():
    client = make_client(
        {"X-Powered-By": "Express"},
        set_cookies=["sessionid=1"],
        security_txt=None,
        body='<script src="http://cdn.example.com/a.js"></script>',
    )
    return scan("example.com", client=client, tls_probe=good_tls)


def test_sarif_is_valid_against_official_schema(weak_result, secure_headers):
    good = scan("good.example", client=make_client(secure_headers), tls_probe=good_tls)
    jsonschema.validate(to_sarif([weak_result, good]), SCHEMA)


def test_sarif_contents(weak_result):
    log = to_sarif([weak_result])
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert log["version"] == "2.1.0"

    # only problems become results, each pointing at a known rule
    problem_ids = {f.check_id for f in weak_result.findings if f.status.value in ("warn", "fail")}
    assert {r["ruleId"] for r in results} == problem_ids
    for r in results:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]
        assert r["level"] in ("error", "warning")
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert r["partialFingerprints"]["secscanFinding/v1"]

    # GitHub uses security-severity to rank alerts
    for rule in rules:
        assert 0 < float(rule["properties"]["security-severity"]) <= 10
        assert "security" in rule["properties"]["tags"]
        assert rule["help"]["markdown"]


def test_fingerprints_are_stable(weak_result):
    first = [r["partialFingerprints"] for r in to_sarif([weak_result])["runs"][0]["results"]]
    second = [r["partialFingerprints"] for r in to_sarif([weak_result])["runs"][0]["results"]]
    assert first == second


def test_artifact_uri_override(weak_result, tmp_path):
    out = tmp_path / "out.sarif"
    write_sarif(str(out), [weak_result], artifact_uri="deploy/nginx.conf")
    log = json.loads(out.read_text())
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in log["runs"][0]["results"]
    }
    assert uris == {"deploy/nginx.conf"}
