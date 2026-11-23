"""Run from files/python with: python3 -m pytest tests -q"""

import gzip
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import soundwave as SW  # noqa: E402
from lib import findings as F  # noqa: E402
from lib import threat_intel as T  # noqa: E402
from lib.metrics import RunMetrics  # noqa: E402

EPSS_CSV = ("#model_version:v2025.03.14,score_date:2026-11-22T12:55:00Z\n"
            "cve,epss,percentile\n"
            "CVE-2024-3094,0.90900,0.99809\n"
            "CVE-2023-0001,0.00100,0.10000\n")
KEV_JSON = {"dateReleased": "2026-11-21T14:01:22.1234Z",
            "vulnerabilities": [{"cveID": "CVE-2024-3094"}, {"cveID": "CVE-2021-44228"}]}


def _feeds(directory, gz=True):
    (directory / T.KEV_FILE).write_text(json.dumps(KEV_JSON))
    if gz:
        (directory / T.EPSS_FILE).write_bytes(gzip.compress(EPSS_CSV.encode()))
    else:
        (directory / "epss_scores-current.csv").write_text(EPSS_CSV)


def _doc(checks):
    return {"cassette": {"name": "openvas"}, "checks": checks, "findings": []}


def test_feeds_load_with_their_publish_dates(tmp_path):
    _feeds(tmp_path)
    kev, epss, feeds = T.load({"threat_intel": "directory", "threat_intel_dir": str(tmp_path)})
    assert kev == {"CVE-2024-3094", "CVE-2021-44228"}
    assert epss["CVE-2024-3094"] == (0.909, 0.99809)
    assert feeds == {"kev": 1795269682, "epss": 1795305600}


def test_an_unpacked_epss_csv_is_read_too(tmp_path):
    _feeds(tmp_path, gz=False)
    _, epss, feeds = T.load({"threat_intel": "directory", "threat_intel_dir": str(tmp_path)})
    assert epss["CVE-2023-0001"] == (0.001, 0.1)
    assert "epss" in feeds


def test_off_reads_nothing(tmp_path):
    _feeds(tmp_path)
    assert T.load({"threat_intel": "off", "threat_intel_dir": str(tmp_path)}) == (set(), {}, {})


def test_a_missing_feed_leaves_the_other_working(tmp_path):
    (tmp_path / T.KEV_FILE).write_text(json.dumps(KEV_JSON))
    kev, epss, feeds = T.load({"threat_intel": "directory", "threat_intel_dir": str(tmp_path)})
    assert kev and not epss and list(feeds) == ["kev"]


def test_enrich_marks_kev_and_takes_the_worst_epss():
    doc = _doc({
        "greenbone:1": {"cves": ["CVE-2023-0001", "cve-2024-3094"], "kev": False},
        "vuls:2": {"cves": ["CVE-2099-9999"], "kev": True},
        "greenbone:3": {"cves": []},
    })
    kev = {"CVE-2024-3094"}
    epss = {"CVE-2024-3094": (0.909, 0.998), "CVE-2023-0001": (0.001, 0.1)}
    marked = T.enrich([doc], kev, epss)
    checks = doc["checks"]
    assert checks["greenbone:1"]["kev"] is True
    assert (checks["greenbone:1"]["epss"], checks["greenbone:1"]["epss_percentile"]) == (0.909, 0.998)
    # A scanner's own true is never overruled by the catalogue.
    assert checks["vuls:2"]["kev"] is True and "epss" not in checks["vuls:2"]
    assert "epss" not in checks["greenbone:3"]
    assert marked == {"kev": 1, "epss": 1}


def test_a_failed_download_keeps_the_previous_file(tmp_path):
    (tmp_path / T.KEV_FILE).write_text("previous")
    T.refresh({"threat_intel": "download", "threat_intel_dir": str(tmp_path),
               "kev_url": "file:///nonexistent/kev.json", "epss_url": "file:///nonexistent/epss.csv.gz"})
    assert (tmp_path / T.KEV_FILE).read_text() == "previous"
    assert [p.name for p in tmp_path.iterdir()] == [T.KEV_FILE]


def test_download_fetches_both_feeds(tmp_path):
    source = tmp_path / "mirror"
    source.mkdir()
    _feeds(source)
    target = tmp_path / "intel"
    target.mkdir()
    T.refresh({"threat_intel": "download", "threat_intel_dir": str(target),
               "kev_url": (source / T.KEV_FILE).as_uri(), "epss_url": (source / T.EPSS_FILE).as_uri()})
    kev, epss, _ = T.load({"threat_intel": "directory", "threat_intel_dir": str(target)})
    assert "CVE-2021-44228" in kev and "CVE-2024-3094" in epss


def test_composition_keeps_the_highest_epss():
    members = [("openvas", {"check_id": "g:1"}, {"cves": ["CVE-1"], "epss": 0.2, "epss_percentile": 0.5}),
               ("vuls", {"check_id": "v:1"}, {"cves": ["CVE-1"], "epss": 0.7, "epss_percentile": 0.9})]
    check = F.compose_check(members)
    assert (check["epss"], check["epss_percentile"]) == (0.7, 0.9)


def test_run_applies_threat_intel_and_records_the_feeds(tmp_path):
    _feeds(tmp_path)
    doc = _doc({"greenbone:1": {"cves": ["CVE-2024-3094"], "kev": False}})
    metrics = RunMetrics("")
    SW.apply_threat_intel({"threat_intel": "directory", "threat_intel_dir": str(tmp_path)}, [doc], metrics)
    assert doc["checks"]["greenbone:1"]["kev"] is True
    assert metrics.threat_intel["marked"] == {"kev": 1, "epss": 1}
    rendered = metrics.render(True)
    assert 'soundwave_threat_intel_feed_timestamp_seconds{feed="kev"} 1795269682' in rendered
    assert 'soundwave_threat_intel_checks_marked{feed="epss"} 1' in rendered
