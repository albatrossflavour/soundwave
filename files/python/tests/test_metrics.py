"""Run from files/python with: python3 -m pytest tests -q"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib.metrics import RunMetrics, _label  # noqa: E402


def _lines(text):
    return [line for line in text.splitlines() if not line.startswith("#")]


def _cassettes():
    return {
        "vuls": {
            "generated_at": 1600, "scan_end": 1500, "findings": 0,
            "hosts": {"scanned": 12, "unreachable": 11},
            "dropped": {"running-kernel": 4263, "unfixed": 71495}, "unmapped": 0,
        },
        "openvas": {
            "generated_at": 1900, "scan_end": 1800, "findings": 87,
            "hosts": {"scanned": 20, "partial": 4},
            "dropped": {}, "unmapped": 1,
        },
    }


def test_failed_run_before_anything_is_known(tmp_path):
    # A failed run must not publish zeros that read as "nothing found".
    text = RunMetrics(str(tmp_path / "soundwave.prom"), clock=lambda: 1000).render(False)
    assert _lines(text) == [
        "soundwave_last_run_timestamp_seconds 1000",
        "soundwave_last_run_success 0",
    ]


def test_full_run(tmp_path):
    metrics = RunMetrics(str(tmp_path / "soundwave.prom"), clock=lambda: 2000)
    metrics.push_status = 201
    metrics.findings = 87
    metrics.hosts_pushed = 24
    metrics.hosts_clean = 3
    metrics.cassettes = _cassettes()
    metrics.host_scan_ends = {("openvas", "a.lab"): 1800, ("vuls", "a.lab"): 1500}

    assert _lines(metrics.render(True)) == [
        "soundwave_last_run_timestamp_seconds 2000",
        "soundwave_last_run_success 1",
        "soundwave_last_success_timestamp_seconds 2000",
        "soundwave_push_status_code 201",
        "soundwave_findings 87",
        "soundwave_hosts_pushed 24",
        "soundwave_hosts_clean 3",
        'soundwave_cassette_generated_timestamp_seconds{cassette="openvas"} 1900',
        'soundwave_cassette_generated_timestamp_seconds{cassette="vuls"} 1600',
        'soundwave_cassette_scan_end_timestamp_seconds{cassette="openvas"} 1800',
        'soundwave_cassette_scan_end_timestamp_seconds{cassette="vuls"} 1500',
        'soundwave_cassette_findings{cassette="openvas"} 87',
        'soundwave_cassette_findings{cassette="vuls"} 0',
        'soundwave_cassette_hosts{cassette="openvas",status="partial"} 4',
        'soundwave_cassette_hosts{cassette="openvas",status="scanned"} 20',
        'soundwave_cassette_hosts{cassette="vuls",status="scanned"} 12',
        'soundwave_cassette_hosts{cassette="vuls",status="unreachable"} 11',
        'soundwave_cassette_dropped{cassette="vuls",filter="running-kernel"} 4263',
        'soundwave_cassette_dropped{cassette="vuls",filter="unfixed"} 71495',
        'soundwave_cassette_unmapped{cassette="openvas"} 1',
        'soundwave_cassette_unmapped{cassette="vuls"} 0',
        'soundwave_host_scan_end_timestamp_seconds{cassette="openvas",certname="a.lab"} 1800',
        'soundwave_host_scan_end_timestamp_seconds{cassette="vuls",certname="a.lab"} 1500',
    ]


def test_a_cassette_that_has_never_scanned_omits_its_scan_end(tmp_path):
    # None means not known, and a gap in the series is honest where a zero is not.
    metrics = RunMetrics(str(tmp_path / "soundwave.prom"), clock=lambda: 2000)
    metrics.cassettes = {
        "vuls": {"generated_at": 1600, "scan_end": None, "findings": 0,
                   "hosts": {"unreachable": 23}, "dropped": {}, "unmapped": 0},
    }
    lines = _lines(metrics.render(True))
    assert "soundwave_cassette_scan_end_timestamp_seconds" not in "\n".join(lines)
    assert 'soundwave_cassette_generated_timestamp_seconds{cassette="vuls"} 1600' in lines


def test_last_success_survives_a_failure(tmp_path):
    path = str(tmp_path / "soundwave.prom")
    RunMetrics(path, clock=lambda: 2000).write(True)
    RunMetrics(path, clock=lambda: 3000).write(False)

    lines = _lines(open(path).read())
    assert "soundwave_last_success_timestamp_seconds 2000" in lines
    assert "soundwave_last_run_success 0" in lines
    assert oct(os.stat(path).st_mode & 0o777) == "0o644"
    # node_exporter must never see a half-written file beside the real one.
    assert [p.name for p in tmp_path.iterdir()] == ["soundwave.prom"]


def test_no_path_writes_nothing(tmp_path):
    RunMetrics("").write(True)
    assert list(tmp_path.iterdir()) == []


def test_label_escaping():
    # Prometheus label values escape backslash, double quote and newline, and a
    # certname or filter name arriving with one must not break the file.
    assert _label('odd "name"') == 'odd \\"name\\"'
    assert _label("back\\slash") == "back\\\\slash"
    assert _label("two\nlines") == "two\\nlines"
