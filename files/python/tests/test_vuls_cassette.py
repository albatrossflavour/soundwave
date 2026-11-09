"""Run from files/python with: python3 -m pytest tests -q"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cassettes import vuls as V  # noqa: E402


def _layout(tmp_path):
    results = tmp_path / "results"
    first, second = results / "2026-11-08T22-00-00+1100", results / "2026-11-09T22-00-00+1100"
    first.mkdir(parents=True)
    second.mkdir()
    os.utime(first, (1_000, 1_000))
    os.utime(second, (2_000, 2_000))
    config = tmp_path / "config.toml"
    config.write_text("[default]\nport = \"22\"\n")
    windows = tmp_path / "windows.json"
    windows.write_text("[]")
    return results, first, second, config, windows


def _argv(tmp_path, results, config, windows, complete, out):
    return ["vuls.py", f"--results-dir={results}", f"--config={config}", f"--windows-config={windows}",
            f"--database={tmp_path / 'vuls.db'}", f"--complete-file={complete}", f"--out={out}"]


def test_the_cassette_is_named_for_its_scanner():
    assert V.CASSETTE == "vuls"


def test_reads_the_run_recorded_as_complete_not_the_newest(tmp_path, monkeypatch):
    results, first, _second, config, windows = _layout(tmp_path)
    complete = tmp_path / "last-complete-run"
    complete.write_text(f"{first}\n")
    out = tmp_path / "cassettes" / "vuls.json"
    monkeypatch.setattr(sys, "argv", _argv(tmp_path, results, config, windows, complete, out))

    assert V.main() == 0

    document = json.loads(out.read_text())
    assert document["cassette"]["name"] == "vuls"
    assert document["cassette"]["run_id"] == first.name


def test_with_no_complete_run_keeps_the_previous_cassette(tmp_path, monkeypatch):
    results, _first, _second, config, windows = _layout(tmp_path)
    out = tmp_path / "vuls.json"
    out.write_text('{"previous": true}\n')
    monkeypatch.setattr(sys, "argv", _argv(tmp_path, results, config, windows, tmp_path / "missing", out))

    assert V.main() == 0
    assert out.read_text() == '{"previous": true}\n'


def test_a_complete_run_that_has_been_removed_keeps_the_previous_cassette(tmp_path, monkeypatch):
    results, _first, _second, config, windows = _layout(tmp_path)
    complete = tmp_path / "last-complete-run"
    complete.write_text(f"{results / 'gone'}\n")
    out = tmp_path / "vuls.json"
    out.write_text('{"previous": true}\n')
    monkeypatch.setattr(sys, "argv", _argv(tmp_path, results, config, windows, complete, out))

    assert V.main() == 0
    assert out.read_text() == '{"previous": true}\n'


def test_expects_the_hosts_the_run_was_configured_with_not_todays(tmp_path, monkeypatch):
    """The cassette runs nightly against a run that can be a week old, so a node
    added since must not read as unreachable in that old run."""
    results, first, _second, config, windows = _layout(tmp_path)
    config.write_text('[servers."added-since.example.com"]\nhost = "192.0.2.9"\n')
    scanned = first / ".scanned"
    scanned.mkdir()
    (scanned / "config.toml").write_text('[servers."was-there.example.com"]\nhost = "192.0.2.1"\n')
    (scanned / "windows.json").write_text("[]")
    complete = tmp_path / "last-complete-run"
    complete.write_text(f"{first}\n")
    out = tmp_path / "vuls.json"
    monkeypatch.setattr(sys, "argv", _argv(tmp_path, results, config, windows, complete, out))

    assert V.main() == 0

    hosts = json.loads(out.read_text())["hosts"]
    assert "was-there.example.com" in hosts
    assert "added-since.example.com" not in hosts


def test_expected_servers_without_tomllib(tmp_path, monkeypatch):
    # EL8 and EL9 run Python 3.9, which has no tomllib. The server names still
    # come out of the config Puppet writes.
    monkeypatch.setattr(V, "tomllib", None)
    config = tmp_path / "config.toml"
    config.write_text('[default]\nport = "22"\n\n[servers."a.example.com"]\nhost = "192.0.2.1"\n'
                      '[servers."b.example.com"]\nhost = "192.0.2.2"\n')
    assert V.expected_servers(str(config), None) == ["a.example.com", "b.example.com"]
