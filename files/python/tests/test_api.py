"""Run from files/python with: python3 -m pytest tests -q"""

import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib import api  # noqa: E402
from lib import pe_transformer_client as PE  # noqa: E402


class _Unreachable:
    def __init__(self, *args, **kwargs):
        pass

    def request(self, *args, **kwargs):
        raise TimeoutError(110, "Connection timed out")


def test_an_unreachable_pe_is_named_with_its_host_and_port(monkeypatch, caplog):
    monkeypatch.setattr(api.http.client, "HTTPSConnection", _Unreachable)
    with caplog.at_level(logging.ERROR, logger="transformer"):
        assert api.call_rest_api("pe.example.com", "/x", port=8146) is None
    assert "Could not reach pe.example.com:8146" in caplog.text
    assert "Unexpected error" not in caplog.text


def test_registration_with_no_response_does_not_claim_pe_answered_500(monkeypatch):
    monkeypatch.setattr(PE, "call_rest_api", lambda *a, **k: None)
    res = PE.register_host({"name": "n", "description": "d", "token": "t", "host": "pe.example.com",
                            "transformer_id": "id", "port": 8146})
    assert res["status"] != 500
    assert "pe.example.com:8146" in res["data"]
