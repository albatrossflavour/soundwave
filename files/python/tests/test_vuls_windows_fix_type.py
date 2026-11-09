"""Run from files/python with: python3 -m pytest tests -q"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cassettes import vuls as V  # noqa: E402


def _build(tmp_path, cve_id, kbs):
    results = tmp_path / "results"
    results.mkdir()
    (results / "win.example.com.json").write_text(json.dumps({
        "family": "windows",
        "serverName": "win.example.com",
        "release": "Windows Server 2022",
        "scannedCves": {cve_id: {"windowsKBFixedIns": kbs, "cveContents": {}}},
    }))
    config = tmp_path / "config.toml"
    config.write_text("[default]\n")
    windows = tmp_path / "windows.json"
    windows.write_text("[]")
    _hosts, checks, findings, _drops, _unmapped = V.build(str(results), str(config), str(windows))
    return next(iter(checks.values())), findings[0]


# POBS only offers mitigation and workaround as things Puppet can act on, so a
# documented opt-in setting labelled none-available disappears from its summary.
@pytest.mark.parametrize("cve_id", ["ADV190023", "CVE-2013-3900"])
def test_a_documented_opt_in_setting_is_a_mitigation(tmp_path, cve_id):
    check, finding = _build(tmp_path, cve_id, [])

    assert check["fix_type"] == "mitigation"
    assert "configuration change" in check["solution"]
    assert "configuration change" in finding["evidence"]


# CVE-2022-37966 is why no KB can't mean a setting exists: the feed just has no
# KB for it, so the cassette must not claim a configuration change closes it.
def test_a_cve_with_no_kb_and_no_known_setting_claims_nothing(tmp_path):
    check, finding = _build(tmp_path, "CVE-2022-37966", [])

    assert check["fix_type"] == "none-available"
    assert "configuration change" not in check["solution"]
    assert "configuration change" not in finding["evidence"]


def test_a_cve_with_a_kb_stays_a_patch_even_on_an_opt_in_id(tmp_path):
    check, _finding = _build(tmp_path, "CVE-2013-3900", ["5000001"])

    assert check["fix_type"] == "vendor-fix"
