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


# Each output stands on its own. The VR push, the findings API push and the
# cassette metrics answer to different things, and 0.2.1 let a pending
# transformer stop the run before the other two happened. A pending transformer
# is a person who hasn't clicked accept yet; it says nothing about whether the
# findings API or the metrics should hear about the scan.
ACTIVE = {"status": 409, "data": {"message": SW.TRANSFORMER_MESSAGE_CREATED}}
PENDING = {"status": 202, "data": ""}
CONFLICT = {"status": 409, "data": {"message": SW.TRANSFORMER_MESSAGE_OTHER}}


def _cassette(name):
    return {
        "cassette": {"name": name, "generated_at": "2026-11-19T08:50:00Z"},
        "hosts": {"node.lab": {"status": "scanned", "scan_end": "2026-11-19T08:00:00Z"}},
        "checks": {}, "findings": [],
    }


def _independent_run(monkeypatch, tmp_path, registration, findings_api=lambda p, d: 1, vr_status=201):
    pushed = {"findings_api": [], "vr": []}
    monkeypatch.setattr(SW.time, "sleep", lambda s: None)
    monkeypatch.setattr(SW.F, "read_cassettes", lambda d: [_cassette("openvas"), _cassette("vuls")])
    vr_data = [{"certname": "node.lab", "vulnerabilities": []}]
    monkeypatch.setattr(SW.F, "to_vr", lambda h, c, f, m: (vr_data, 1_700_000_000))

    def register_host(params):
        if isinstance(registration, Exception):
            raise registration
        return registration

    def push_findings(params, document):
        pushed["findings_api"].append(document["cassette"]["name"])
        return findings_api(params, document)

    monkeypatch.setattr(SW, "register_host", register_host)
    monkeypatch.setattr(SW, "push_findings", push_findings)
    monkeypatch.setattr(SW, "post_transformer_res_to_pe",
                        lambda p, d, s: pushed["vr"].append(s) or {"status": vr_status, "data": ""})
    defaults = {"cassette_dir": str(tmp_path / "cassettes"), "findings_api_host": "findings.example.com"}
    metrics = RunMetrics(str(tmp_path / "soundwave.prom"), clock=lambda: 2_000_000_000)
    code = SW.run({"register": "1", "max_retries": "1"}, defaults, metrics)
    return code, pushed, _metric_lines(metrics.render(code == 0))


def _metric_lines(text):
    return [line for line in text.splitlines() if not line.startswith("#")]


def _has_cassette_metrics(lines):
    return ('soundwave_cassette_generated_timestamp_seconds{cassette="openvas"} 1795078200' in lines
            and 'soundwave_cassette_generated_timestamp_seconds{cassette="vuls"} 1795078200' in lines)


def test_pending_pushes_to_the_findings_api_and_writes_metrics_but_skips_vr(monkeypatch, tmp_path, caplog):
    with caplog.at_level("INFO", logger="transformer"):
        code, pushed, lines = _independent_run(monkeypatch, tmp_path, PENDING)
    assert code == 0
    assert pushed["vr"] == []
    assert pushed["findings_api"] == ["openvas", "vuls"]
    assert _has_cassette_metrics(lines)
    assert 'soundwave_vr_transformer_state{state="pending"} 1' in lines
    assert 'soundwave_vr_transformer_state{state="active"} 0' in lines
    assert "soundwave_last_run_success 1" in lines
    assert not any(line.startswith("soundwave_push_status_code") for line in lines)
    assert "Skipping the VR push until the transformer is accepted in the PE console" in caplog.text


def test_active_does_all_three(monkeypatch, tmp_path):
    code, pushed, lines = _independent_run(monkeypatch, tmp_path, ACTIVE)
    assert code == 0
    assert pushed["vr"] == [1_700_000_000]
    assert pushed["findings_api"] == ["openvas", "vuls"]
    assert _has_cassette_metrics(lines)
    assert 'soundwave_vr_transformer_state{state="active"} 1' in lines
    assert 'soundwave_vr_transformer_state{state="pending"} 0' in lines
    assert "soundwave_push_status_code 201" in lines


def test_findings_api_down_still_writes_metrics_and_pushes_vr(monkeypatch, tmp_path):
    code, pushed, lines = _independent_run(monkeypatch, tmp_path, ACTIVE, findings_api=lambda p, d: None)
    assert code == 0
    assert pushed["vr"] == [1_700_000_000]
    assert pushed["findings_api"] == ["openvas", "vuls"]
    assert _has_cassette_metrics(lines)
    assert "soundwave_findings_api_hosts_accepted 0" in lines


def test_findings_api_raising_still_writes_metrics_and_pushes_vr(monkeypatch, tmp_path):
    def boom(params, document):
        raise ConnectionError("findings API unreachable")
    code, pushed, lines = _independent_run(monkeypatch, tmp_path, ACTIVE, findings_api=boom)
    assert code == 0
    assert pushed["vr"] == [1_700_000_000]
    # One cassette failing doesn't stop the next being tried.
    assert pushed["findings_api"] == ["openvas", "vuls"]
    assert _has_cassette_metrics(lines)


def test_another_transformer_fails_the_run_but_not_the_other_outputs(monkeypatch, tmp_path):
    code, pushed, lines = _independent_run(monkeypatch, tmp_path, CONFLICT)
    assert code == 1
    assert pushed["vr"] == []
    assert pushed["findings_api"] == ["openvas", "vuls"]
    assert _has_cassette_metrics(lines)
    assert 'soundwave_vr_transformer_state{state="conflict"} 1' in lines
    assert "soundwave_last_run_success 0" in lines


def test_registration_raising_fails_the_run_but_not_the_other_outputs(monkeypatch, tmp_path):
    code, pushed, lines = _independent_run(monkeypatch, tmp_path, ConnectionError("PE unreachable"))
    assert code == 1
    assert pushed["vr"] == []
    assert pushed["findings_api"] == ["openvas", "vuls"]
    assert _has_cassette_metrics(lines)
    assert 'soundwave_vr_transformer_state{state="error"} 1' in lines


def test_registration_still_happens_with_no_cassettes(monkeypatch, tmp_path):
    """A fresh install registers on its first run even before a cassette has written,
    so the transformer is waiting in the console by the time the scans land."""
    registered = []
    monkeypatch.setattr(SW.time, "sleep", lambda s: None)
    monkeypatch.setattr(SW.F, "read_cassettes", lambda d: [])
    monkeypatch.setattr(SW, "register_host", lambda p: registered.append(1) or PENDING)
    metrics = RunMetrics("")
    assert SW.run({"register": "1", "max_retries": "1"}, {"cassette_dir": str(tmp_path)}, metrics) == 1
    assert registered == [1]
    assert metrics.vr_state == "pending"
