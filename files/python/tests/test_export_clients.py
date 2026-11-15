"""Run from files/python with: python3 -m pytest tests -q

The scanner APIs are faked at lib.scanner_http, so these check the calls made
and the decisions taken on the answers, not that a real scanner agrees.
"""

import gzip
import http.client
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib import export_cassette as X  # noqa: E402
from lib import rapid7_client as R  # noqa: E402
from lib import scanner_http as H  # noqa: E402
from lib import tenable_client as T  # noqa: E402


class FakeAPI:
    """Answers call_json from a {(method, path): reply} table and records each call."""

    def __init__(self, base, replies):
        self.base = base
        self.replies = replies
        self.calls = []
        self.downloads = []

    def call_json(self, url, method="GET", auth_headers=None, body=None, ca_cert=None):
        path = url[len(self.base):]
        self.calls.append((method, path, body))
        reply = self.replies[(method, path)]
        return reply() if callable(reply) else reply

    def download(self, url, path, auth_headers=None, ca_cert=None, headers=None):
        self.downloads.append(url[len(self.base):])
        with open(path, "wb") as out:
            out.write(self.replies[("DOWNLOAD", url[len(self.base):])])
        return os.path.getsize(path)


@pytest.fixture
def no_wait(monkeypatch):
    monkeypatch.setattr(H, "wait_for", lambda probe, what, timeout, interval=10: probe() or pytest.fail(what))


def _install(monkeypatch, api):
    monkeypatch.setattr(H, "call_json", api.call_json)
    monkeypatch.setattr(H, "download", api.download)


# Tenable


BASE = "https://nessus.example.com:8834"


def test_tenable_exports_a_completed_scan(tmp_path, monkeypatch, no_wait):
    api = FakeAPI(BASE, {
        ("GET", "/scans"): {"scans": [{"id": 5, "name": "Weekly", "status": "completed"}]},
        ("POST", "/scans/5/export"): {"file": 99, "temp_token": "x"},
        ("GET", "/scans/5/export/99/status"): {"status": "ready"},
        ("DOWNLOAD", "/scans/5/export/99/download"): b"<NessusClientData_v2/>",
    })
    _install(monkeypatch, api)
    paths = T.export_scans(BASE + "/", "ak", "sk", ["Weekly"], str(tmp_path))
    assert paths == [str(tmp_path / "scan-5.nessus")]
    assert ("POST", "/scans/5/export", {"format": "nessus"}) in api.calls


def test_tenable_exports_the_last_completed_run_of_a_running_scan(tmp_path, monkeypatch, no_wait):
    """A running scan exports what it has so far, which would push half an estate."""
    api = FakeAPI(BASE, {
        ("GET", "/scans"): {"scans": [{"id": 5, "name": "Weekly", "status": "running"}]},
        ("GET", "/scans/5"): {"history": [
            {"history_id": 1, "status": "completed", "last_modification_date": 100},
            {"history_id": 2, "status": "completed", "last_modification_date": 200},
            {"history_id": 3, "status": "running", "last_modification_date": 300}]},
        ("POST", "/scans/5/export?history_id=2"): {"file": 99},
        ("GET", "/scans/5/export/99/status"): {"status": "ready"},
        ("DOWNLOAD", "/scans/5/export/99/download"): b"x",
    })
    _install(monkeypatch, api)
    assert T.export_scans(BASE, "ak", "sk", ["Weekly"], str(tmp_path))


def test_tenable_one_scan_failing_fails_the_export(tmp_path, monkeypatch, no_wait, caplog):
    """Written from the scans that worked, the file would drop the others' hosts with a fresh timestamp."""
    api = FakeAPI(BASE, {
        ("GET", "/scans"): {"scans": [{"id": 5, "name": "Weekly", "status": "completed"},
                                      {"id": 6, "name": "Never", "status": "empty"}]},
        ("GET", "/scans/6"): {"history": []},
        ("POST", "/scans/5/export"): {"file": 99},
        ("GET", "/scans/5/export/99/status"): {"status": "ready"},
        ("DOWNLOAD", "/scans/5/export/99/download"): b"x",
    })
    _install(monkeypatch, api)
    with caplog.at_level("ERROR", logger="transformer"), \
            pytest.raises(H.FetchError, match=r"2 of 3 scan\(s\) not exported \('Missing', 'Never'\)"):
        T.export_scans(BASE, "ak", "sk", ["Missing", "Never", "Weekly"], str(tmp_path))
    assert ("DOWNLOAD", "/scans/5/export/99/download") in [("DOWNLOAD", d) for d in api.downloads]
    assert "No scan called 'Missing'" in caplog.text
    assert "no completed run" in caplog.text


def test_tenable_export_error_is_not_waited_out(tmp_path, monkeypatch, no_wait, caplog):
    api = FakeAPI(BASE, {
        ("GET", "/scans"): {"scans": [{"id": 5, "name": "Weekly", "status": "completed"}]},
        ("POST", "/scans/5/export"): {"file": 99},
        ("GET", "/scans/5/export/99/status"): {"status": "error"},
    })
    _install(monkeypatch, api)
    with caplog.at_level("ERROR", logger="transformer"), pytest.raises(H.FetchError):
        T.export_scans(BASE, "ak", "sk", ["Weekly"], str(tmp_path))
    assert "export of 'Weekly' failed" in caplog.text


def test_find_scan_takes_the_newest_of_duplicates():
    scans = [{"id": 1, "name": "W", "last_modification_date": 5}, {"id": 2, "name": "W", "last_modification_date": 9}]
    assert T.find_scan(scans, "W")["id"] == 2
    assert T.find_scan(scans, "w") is None


# Rapid7


CONSOLE = "https://insightvm.example.com:3780"


def _rapid7_api(fmt="xml-export-v2", status="complete", body=b"<NexposeReport/>"):
    return FakeAPI(CONSOLE, {
        ("GET", "/api/3/reports?page=0&size=500"): {"resources": [{"id": 1, "name": "Other", "format": fmt}],
                                                    "page": {"totalPages": 2}},
        ("GET", "/api/3/reports?page=1&size=500"): {"resources": [{"id": 42, "name": "Soundwave", "format": fmt}],
                                                    "page": {"totalPages": 2}},
        ("POST", "/api/3/reports/42/generate"): {"id": 7, "links": []},
        ("GET", "/api/3/reports/42/history/7"): {"status": status},
        ("DOWNLOAD", "/api/3/reports/42/history/7/output"): body,
    })


def test_rapid7_generates_the_named_report_and_unzips_it(tmp_path, monkeypatch, no_wait):
    api = _rapid7_api(body=gzip.compress(b"<NexposeReport/>"))
    _install(monkeypatch, api)
    path = R.generate_report(CONSOLE, "u", "p", "Soundwave", str(tmp_path))
    assert open(path, "rb").read() == b"<NexposeReport/>"
    assert os.listdir(tmp_path) == ["report-42.xml"]


def test_rapid7_takes_an_uncompressed_report_too(tmp_path, monkeypatch, no_wait):
    _install(monkeypatch, _rapid7_api())
    assert open(R.generate_report(CONSOLE, "u", "p", "Soundwave", str(tmp_path)), "rb").read() == b"<NexposeReport/>"


def test_rapid7_refuses_a_report_in_another_format(tmp_path, monkeypatch, no_wait):
    """Any other format parses as no hosts at all."""
    _install(monkeypatch, _rapid7_api(fmt="csv-export"))
    with pytest.raises(H.FetchError, match="not xml-export-v2"):
        R.generate_report(CONSOLE, "u", "p", "Soundwave", str(tmp_path))


def test_rapid7_failed_generation_raises(tmp_path, monkeypatch, no_wait):
    _install(monkeypatch, _rapid7_api(status="failed"))
    with pytest.raises(H.FetchError, match="failed"):
        R.generate_report(CONSOLE, "u", "p", "Soundwave", str(tmp_path))


def test_rapid7_missing_report_raises(tmp_path, monkeypatch, no_wait):
    _install(monkeypatch, _rapid7_api())
    with pytest.raises(H.FetchError, match="no report called 'Nope'"):
        R.generate_report(CONSOLE, "u", "p", "Nope", str(tmp_path))


# scanner_http


def test_wait_for_gives_up_at_the_deadline():
    now = [0]
    with pytest.raises(H.FetchError, match="not ready after 30s"):
        H.wait_for(lambda: None, "thing", 30, interval=10, clock=lambda: now[0],
                   sleep=lambda s: now.__setitem__(0, now[0] + s))
    assert now[0] == 30


def _fake_clock():
    now = [0]
    return now, (lambda: now[0]), (lambda s: now.__setitem__(0, now[0] + s))


def test_wait_for_rides_out_a_failed_check():
    """One 503 in a twenty-minute export is a failed look, not a failed export."""
    _, clock, sleep = _fake_clock()
    answers = iter([H.FetchError("503"), None, "done"])

    def probe():
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer
    assert H.wait_for(probe, "thing", 60, interval=10, clock=clock, sleep=sleep) == "done"


def test_wait_for_stops_when_the_scanner_says_it_failed():
    now, clock, sleep = _fake_clock()

    def probe():
        raise H.ExportFailed("scanner says no")
    with pytest.raises(H.ExportFailed):
        H.wait_for(probe, "thing", 60, interval=10, clock=clock, sleep=sleep)
    assert now[0] == 0


def test_a_connection_dropped_mid_body_is_a_fetch_error(tmp_path, monkeypatch):
    class Broken:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            raise http.client.IncompleteRead(b"partial")
    monkeypatch.setattr(H, "_open", lambda *a, **k: Broken())
    with pytest.raises(H.FetchError, match="broke off"):
        H.download("https://x/f", str(tmp_path / "f"))
    with pytest.raises(H.FetchError, match="broke off"):
        H.call_json("https://x/j")


def test_credentials_are_not_forwarded_on_a_redirect():
    request = H._request("https://x/", "GET", {"X-ApiKeys": "secret"}, None, None)
    assert request.unredirected_hdrs == {"X-apikeys": "secret"}
    assert "X-apikeys" not in request.headers


# export_cassette.run


def _config(monkeypatch, tmp_path, section_params):
    cassette_dir = tmp_path / "cassettes"
    cassette_dir.mkdir()

    def load(section=None, **_):
        return {"cassette_dir": str(cassette_dir), **section_params}
    monkeypatch.setattr(X, "load_transformer_parameters", load)
    return cassette_dir


class _Doc:
    def __init__(self, hosts):
        self.hosts = hosts

    def write(self, path):
        with open(path, "w") as fh:
            json.dump(self.hosts, fh)


def test_run_reads_the_export_directory(tmp_path, monkeypatch):
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "a.nessus").write_text("x")
    (drop / ".partial.nessus").write_text("x")
    (drop / "notes.txt").write_text("x")
    cassette_dir = _config(monkeypatch, tmp_path, {"export_dir": str(drop)})
    seen = []

    def parse(paths, mapping, params):
        seen.extend(os.path.basename(p) for p in paths)
        return _Doc({"web1": {}})
    assert X.run("nessus", "NESSUS", (".nessus",), None, parse) == 0
    assert seen == ["a.nessus"]
    assert sorted(os.listdir(tmp_path)) == ["cassettes", "drop"]  # no work directory in file mode
    assert json.load(open(cassette_dir / "nessus.json")) == {"web1": {}}


def test_run_with_nothing_to_read_leaves_the_previous_file(tmp_path, monkeypatch):
    """An empty cassette would claim the scanner saw no hosts. Its age says more."""
    drop = tmp_path / "drop"
    drop.mkdir()
    cassette_dir = _config(monkeypatch, tmp_path, {"export_dir": str(drop)})
    (cassette_dir / "nessus.json").write_text("previous")
    assert X.run("nessus", "NESSUS", (".nessus",), None, lambda *a: pytest.fail("parsed nothing")) == 1
    assert (cassette_dir / "nessus.json").read_text() == "previous"


def test_run_with_no_hosts_leaves_the_previous_file(tmp_path, monkeypatch):
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "a.xml").write_text("x")
    cassette_dir = _config(monkeypatch, tmp_path, {"export_dir": str(drop)})
    (cassette_dir / "rapid7.json").write_text("previous")
    assert X.run("rapid7", "RAPID7", (".xml",), None, lambda *a: _Doc({})) == 1
    assert (cassette_dir / "rapid7.json").read_text() == "previous"


def test_run_fetches_when_a_url_is_set_and_cleans_up(tmp_path, monkeypatch):
    cassette_dir = _config(monkeypatch, tmp_path, {"url": "https://x"})
    workdirs = []

    def fetch(params, workdir):
        workdirs.append(workdir)
        path = os.path.join(workdir, "scan.nessus")
        open(path, "w").write("x")
        return [path]
    assert X.run("nessus", "NESSUS", (".nessus",), fetch, lambda *a: _Doc({"web1": {}})) == 0
    assert os.path.dirname(workdirs[0]) == str(tmp_path)
    assert not os.path.exists(workdirs[0])
    assert (cassette_dir / "nessus.json").exists()


def test_run_survives_a_fetch_error(tmp_path, monkeypatch):
    _config(monkeypatch, tmp_path, {"url": "https://x"})

    def fetch(params, workdir):
        raise H.FetchError("console down")
    assert X.run("rapid7", "RAPID7", (".xml",), fetch, None) == 1
