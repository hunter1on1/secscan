import pytest

from secscan.cors import PROBE_ORIGIN, check_cors
from secscan.models import Status

CREDS = {"Access-Control-Allow-Credentials": "true"}


@pytest.mark.parametrize(
    ("headers", "status", "deduction"),
    [
        ({}, Status.PASS, 0),
        ({"Access-Control-Allow-Origin": "https://app.example.com"}, Status.PASS, 0),
        ({"Access-Control-Allow-Origin": "*"}, Status.INFO, 0),
        ({"Access-Control-Allow-Origin": "*", **CREDS}, Status.WARN, 5),
        ({"Access-Control-Allow-Origin": PROBE_ORIGIN}, Status.WARN, 5),
        ({"Access-Control-Allow-Origin": PROBE_ORIGIN, **CREDS}, Status.FAIL, 20),
        (
            {
                "access-control-allow-origin": PROBE_ORIGIN,
                "access-control-allow-credentials": "TRUE",
            },
            Status.FAIL,
            20,
        ),
        ({"Access-Control-Allow-Origin": "null"}, Status.WARN, 5),
        ({"Access-Control-Allow-Origin": "null", **CREDS}, Status.FAIL, 20),
    ],
)
def test_cors(headers, status, deduction):
    finding = check_cors(headers)
    assert (finding.status, finding.deduction) == (status, deduction)


def test_probe_origin_is_reserved_domain():
    # .invalid can never be registered, so we never claim to be a real site.
    assert PROBE_ORIGIN.endswith(".invalid")
