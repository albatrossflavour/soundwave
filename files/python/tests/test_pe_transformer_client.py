"""Run from files/python with: python3 -m pytest tests -q"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib import pe_transformer_client as PE  # noqa: E402


@pytest.fixture
def captured(monkeypatch):
    """Capture the endpoint post_transformer_res_to_pe would call."""
    seen = {}

    def fake_call_rest_api(host, endpoint, **kwargs):
        seen["endpoint"] = endpoint
        return {"status": 201, "data": {}}

    monkeypatch.setattr(PE, "call_rest_api", fake_call_rest_api)
    return seen


def _params():
    return {
        "transformer_id": "t-1", "token": "x", "host": "pe.example.com",
        "port": 8143, "post_body_filepath": "", "cert_verify": 0,
    }


# 2026-09-16T16:19:41Z, which is 2026-09-17T02:19:41 in +10:00. That is the
# real pair from the lab: the vuls cassette's scan ended at 02:19:41 AEST and PE was told
# 2026-09-17T02:19:41Z, ten hours late.
KNOWN_EPOCH = 1789575581


@pytest.mark.parametrize("tz", ["Australia/Sydney", "UTC", "America/Los_Angeles"])
def test_scan_date_is_true_utc_whatever_the_host_timezone(tz, captured, monkeypatch):
    """The 'Z' has to mean what it says.

    `datetime.fromtimestamp` with no tz returns local time, and the upstream
    nessus_transformer stamped a literal 'Z' on it regardless. On a +10:00 host
    that told PE every scan happened ten hours after it did, which is the
    staleness this format sends a per-host scan end to expose.
    """
    monkeypatch.setenv("TZ", tz)
    time.tzset()
    PE.post_transformer_res_to_pe(_params(), [], KNOWN_EPOCH)
    assert "scan_date=2026-09-16T16:19:41Z" in captured["endpoint"]


def test_scan_date_does_not_drift_with_the_local_offset(captured, monkeypatch):
    """The same epoch must render identically in two zones ten hours apart."""
    rendered = []
    for tz in ("Australia/Sydney", "UTC"):
        monkeypatch.setenv("TZ", tz)
        time.tzset()
        PE.post_transformer_res_to_pe(_params(), [], KNOWN_EPOCH)
        rendered.append(captured["endpoint"])
    assert rendered[0] == rendered[1]
