"""Run from files/python with: python3 -m pytest tests -q"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import soundwave as SW  # noqa: E402
from lib.metrics import RunMetrics  # noqa: E402

TERRAPIN = ("greenbone:1.3.6.1.4.1.25623.1.0.114238", "greenbone:1.3.6.1.4.1.25623.1.0.118572")


def _doc(name, checks, findings):
    return {"cassette": {"name": name}, "checks": checks, "findings": findings}


def _overlapping():
    """One CVE on one host, reported by both cassettes on the same package."""
    finding = {"certname": "node.lab", "packages": [{"name": "scipy"}], "kbs": [], "port": None}
    return [
        _doc("openvas", {"greenbone:1": {"cves": ["CVE-1"], "fix_type": "vendor-fix"}},
             [dict(finding, check_id="greenbone:1")]),
        _doc("vuls", {"vuls:1": {"cves": ["CVE-1"], "fix_type": "vendor-fix"}},
             [dict(finding, check_id="vuls:1")]),
    ]


# _correlation_exceptions: a misparsed pair silently stops protecting the pair
# it names, so the parsing is worth pinning.

def test_exceptions_are_empty_when_unset():
    assert SW._correlation_exceptions({}) == []


def test_exceptions_parse_a_single_pair():
    assert SW._correlation_exceptions({"correlation_exceptions": "a|b"}) == [("a", "b")]


def test_exceptions_parse_several_pairs_and_ignore_whitespace():
    parsed = SW._correlation_exceptions({"correlation_exceptions": " a | b , c|d "})
    assert parsed == [("a", "b"), ("c", "d")]


@pytest.mark.parametrize("raw", ["a", "a|b|c", "|", "a|"])
def test_exceptions_warn_and_skip_a_malformed_entry(raw, caplog):
    with caplog.at_level("WARNING", logger="transformer"):
        assert SW._correlation_exceptions({"correlation_exceptions": raw}) == []
    assert "correlation exception" in caplog.text


# report_correlations: off by default, and reports without changing anything.

def test_correlation_is_off_unless_asked_for():
    metrics = RunMetrics("")
    assert SW.report_correlations(_overlapping(), {}, metrics) is None
    assert metrics.correlated is None


def test_correlation_reports_a_cross_cassette_group():
    metrics = RunMetrics("")
    record = SW.report_correlations(_overlapping(), {"correlate": "1"}, metrics)
    assert record.groups == 1
    assert metrics.correlated["cross_cassette_groups"] == 1
    assert metrics.correlated["rule"] == SW.F.CORRELATION_RULE


def test_correlation_does_not_touch_the_documents_it_reads():
    """Report-only has to mean it. The findings API is pushed these documents verbatim
    after this runs, so a correlation that annotated them would change what a
    consumer receives without anything saying so."""
    documents = _overlapping()
    before = repr(documents)
    SW.report_correlations(documents, {"correlate": "1"}, RunMetrics(""))
    assert repr(documents) == before


def test_correlation_honours_a_configured_exception():
    metrics = RunMetrics("")
    record = SW.report_correlations(
        _overlapping(), {"correlate": "1", "correlation_exceptions": "greenbone:1|vuls:1"}, metrics)
    assert record.groups == 0
    assert metrics.correlated["exceptions_applied"] == 1


# The push state: PE 409s a repeated scan date before reading the body and
# closes, so a body past ~200 KB never sees the 409. The date PE accepted or
# already held is kept locally and a scan it has is not sent.
def _run_with(monkeypatch, tmp_path, held, status):
    calls = []
    monkeypatch.setattr(SW.F, "read_cassettes", lambda d: [_doc("openvas", {}, [])])
    monkeypatch.setattr(SW, "record_cassettes", lambda docs, m: None)
    monkeypatch.setattr(SW, "report_correlations", lambda docs, d, m: None)
    monkeypatch.setattr(SW.F, "merge", lambda docs: ({}, {}, []))
    monkeypatch.setattr(SW.F, "to_vr", lambda h, c, f, m: ([{"certname": "node.lab", "vulnerabilities": []}], 1_700_000_000))
    monkeypatch.setattr(SW, "post_transformer_res_to_pe", lambda p, d, s: calls.append(s) or {"status": status, "data": ""})
    state = tmp_path / "pe-push-state.json"
    if held is not None:
        state.write_text('{"scan_date": %d}' % held)
    defaults = {"cassette_dir": str(tmp_path / "cassettes"), "compose_findings": "0"}
    code = SW.run({"register": "0"}, defaults, RunMetrics(""))
    return code, calls, state


def test_state_path_sits_beside_the_cassette_directory_unless_configured(tmp_path):
    assert SW.state_path({"cassette_dir": "/var/lib/soundwave/cassettes/"}) == "/var/lib/soundwave/pe-push-state.json"
    assert SW.state_path({"cassette_dir": "/x/c", "state_file": "/tmp/s.json"}) == "/tmp/s.json"
    assert SW.state_path({}) == ""


def test_a_scan_pe_already_holds_is_not_pushed(monkeypatch, tmp_path):
    code, calls, _ = _run_with(monkeypatch, tmp_path, held=1_700_000_000, status=201)
    assert code == 0
    assert calls == []


def test_a_newer_scan_is_pushed_and_its_date_recorded_on_201(monkeypatch, tmp_path):
    code, calls, state = _run_with(monkeypatch, tmp_path, held=1_600_000_000, status=201)
    assert code == 0
    assert calls == [1_700_000_000]
    assert SW.read_held_scan_date(str(state)) == 1_700_000_000


def test_a_409_from_pe_is_recorded_too(monkeypatch, tmp_path):
    code, calls, state = _run_with(monkeypatch, tmp_path, held=None, status=409)
    assert code == 0 and calls == [1_700_000_000]
    assert SW.read_held_scan_date(str(state)) == 1_700_000_000


def test_a_failed_push_records_nothing_and_still_fails(monkeypatch, tmp_path):
    code, calls, state = _run_with(monkeypatch, tmp_path, held=None, status=500)
    assert code == 1 and calls == [1_700_000_000]
    assert not state.exists()


def test_unreadable_state_is_ignored_not_fatal(tmp_path, caplog):
    bad = tmp_path / "s.json"
    bad.write_text("not json")
    assert SW.read_held_scan_date(str(bad)) is None
    assert "Ignoring unreadable push state" in caplog.text
