"""What Soundwave sends to the findings API."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib import findings_api_client as client  # noqa: E402


def _push(monkeypatch, document):
    sent = []

    def fake_post(_params, payload):
        sent.append(payload)
        return {"status": 201, "data": {}}

    monkeypatch.setattr(client, "_post", fake_post)
    client.push({"host": "primary.example.com", "port": 10051}, document)
    return sent


def _document():
    return {
        "cassette": {"name": "openvas", "run_id": "r1", "scanner": "greenbone"},
        "checks": {"c1": {"name": "check one"}},
        "hosts": {"a.example.com": {"scan_end": "2026-10-01T00:00:00Z"}},
        "findings": [{"certname": "a.example.com", "check_id": "c1"}],
    }


def test_the_envelope_is_source(monkeypatch):
    sent = _push(monkeypatch, _document())
    assert all(p["source"]["name"] == "openvas" for p in sent)
    assert not any("cassette" in p for p in sent)
