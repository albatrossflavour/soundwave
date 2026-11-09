"""Run from files/python with: python3 -m pytest tests -q"""

import inspect
import os
import sys
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib import openvas_client  # noqa: E402
from lib.openvas_client import (  # noqa: E402
    _build_gmp_command,
    _fetch_report,
    _latest_report_ids,
    _merge_reports,
    _select_last_reports,
    get_latest_report,
)

PARAMS = {
    "compose_file": "/opt/greenbone-community-container/compose.yaml",
    "gmp_config_file": "/opt/puppetlabs/soundwave/python/gvm-tools.conf",
    "gmp_service": "gvm-tools",
    "gmp_socket_path": "/run/gvmd/gvmd.sock",
    # Stale keys from an old config.ini must not leak back into the argv.
    "gmp_username": "admin",
    "gmp_password": "hunter2",
}


@pytest.fixture
def cmd():
    return _build_gmp_command(PARAMS, "<get_version/>")


def test_no_credentials_in_argv(cmd):
    assert "hunter2" not in " ".join(cmd)
    assert "--gmp-password" not in cmd
    assert "--gmp-username" not in cmd


def test_does_not_start_dependencies(cmd):
    run = cmd.index("run")
    assert "--no-deps" in cmd[run : cmd.index("gvm-tools")]


def test_mounts_config_read_only(cmd):
    mount = cmd[cmd.index("-v") + 1]
    assert mount == f"{PARAMS['gmp_config_file']}:/run/secrets/gvm-tools.conf:ro"


def test_wrapper_drops_to_gvm_and_passes_args_through(cmd):
    assert cmd[cmd.index("--entrypoint") + 1] == "sh"
    script = cmd[cmd.index("-c") + 1]
    assert "exec gosu gvm gvm-cli --config /tmp/gvm-tools.conf" in script
    assert script.endswith('"$@"')
    # gvm-cli's own arguments follow $0 and are never part of the script.
    assert "<get_version/>" not in script
    dollar0 = cmd.index("-c") + 2
    assert cmd[dollar0 : dollar0 + 2] == ["gvm-cli", "socket"]


def test_xml_is_last(cmd):
    assert cmd[-2:] == ["--xml", "<get_version/>"]


def test_report_fetch_takes_no_metrics_argument():
    # The per-task metrics plumbing went when per-host scan ends replaced it.
    assert list(inspect.signature(get_latest_report).parameters) == ["params"]
    assert list(inspect.signature(_latest_report_ids).parameters) == ["params"]


# Trimmed from a real get_tasks response: an older task, the newest task, a task
# that has never finished a scan, and a similarly named task.
TASKS = ET.fromstring(
    """<get_tasks_response status="200" status_text="OK">
  <task id="t1"><name>Nightly</name>
    <last_report><report id="r-aug"><scan_end>2026-08-22T18:17:12Z</scan_end></report></last_report>
  </task>
  <task id="t2"><name>Test</name>
    <last_report><report id="r-sep"><scan_end>2026-09-12T17:40:32Z</scan_end></report></last_report>
  </task>
  <task id="t3"><name>New</name></task>
  <task id="t4"><name>Test copy</name>
    <last_report><report id="r-oct"><scan_end>2026-10-01T00:00:00Z</scan_end></report></last_report>
  </task>
</get_tasks_response>"""
)


def test_every_task_oldest_first():
    assert _select_last_reports(TASKS) == [
        ("r-aug", "2026-08-22T18:17:12Z"),
        ("r-sep", "2026-09-12T17:40:32Z"),
        ("r-oct", "2026-10-01T00:00:00Z"),
    ]


def test_scan_name_is_exact():
    assert _select_last_reports(TASKS, "Test") == [("r-sep", "2026-09-12T17:40:32Z")]


def test_task_without_report():
    assert _select_last_reports(TASKS, "New") == []


def test_unknown_task():
    assert _select_last_reports(TASKS, "Nope") == []


def _report(end, *result_ids, hosts=(), errors=()):
    results = "".join(f'<result id="{r}"><host>10.0.0.1</host></result>' for r in result_ids)
    host_xml = "".join(f"<host><ip>{ip}</ip><end>{end}</end></host>" for ip in hosts)
    error_xml = "".join(
        f"<error><host>{ip}</host><description>{text}</description></error>" for ip, text in errors
    )
    errors_el = f"<errors>{error_xml}</errors>" if errors else ""
    return ET.fromstring(
        f'<get_reports_response><report id="x"><report id="x"><scan_end>{end}</scan_end>'
        f"{host_xml}{errors_el}<results>{results}</results></report></report></get_reports_response>"
    )


def _hosts_of(merged):
    return [h.findtext("ip") for h in merged.find(".//report/report").findall("host")]


def test_single_report_unchanged():
    merged = _merge_reports([_report("2026-09-12T17:40:32Z", "a", "b")])
    assert [r.get("id") for r in merged.iter("result")] == ["a", "b"]
    assert merged.findtext(".//report/report/scan_end") == "2026-09-12T17:40:32Z"


def test_results_combined_and_deduplicated():
    merged = _merge_reports([
        _report("2026-09-12T17:40:32Z", "a", "b"),
        _report("2026-09-13T01:00:00Z", "b", "c"),
    ])
    assert [r.get("id") for r in merged.iter("result")] == ["a", "b", "c"]


def test_latest_scan_end_wins():
    merged = _merge_reports([
        _report("2026-09-13T01:00:00Z", "a"),
        _report("2026-09-12T17:40:32Z", "b"),
    ])
    assert merged.findtext(".//report/report/scan_end") == "2026-09-13T01:00:00Z"


def test_host_blocks_from_later_reports_are_merged():
    # Merging only results left every task but the first with no host blocks, so
    # two thirds of the estate read as never scanned.
    merged = _merge_reports([
        _report("2026-09-12T17:40:32Z", "a", hosts=["10.0.0.1"]),
        _report("2026-09-13T01:00:00Z", "b", hosts=["10.0.0.2", "10.0.0.3"]),
    ])
    assert _hosts_of(merged) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_a_host_in_both_reports_is_not_duplicated():
    merged = _merge_reports([
        _report("2026-09-12T17:40:32Z", hosts=["10.0.0.1"]),
        _report("2026-09-13T01:00:00Z", hosts=["10.0.0.1", "10.0.0.2"]),
    ])
    assert _hosts_of(merged) == ["10.0.0.1", "10.0.0.2"]


def test_errors_from_a_later_report_are_merged_into_a_new_container():
    merged = _merge_reports([
        _report("2026-09-12T17:40:32Z", hosts=["10.0.0.1"]),
        _report("2026-09-13T01:00:00Z", hosts=["10.0.0.2"], errors=[("10.0.0.2", "Host process failure")]),
    ])
    errors = merged.find(".//report/report/errors").findall("error")
    assert [e.findtext("host") for e in errors] == ["10.0.0.2"]


def test_errors_from_both_reports_are_kept():
    merged = _merge_reports([
        _report("2026-09-12T17:40:32Z", errors=[("10.0.0.1", "one")]),
        _report("2026-09-13T01:00:00Z", errors=[("10.0.0.2", "two")]),
    ])
    errors = merged.find(".//report/report/errors").findall("error")
    assert [e.findtext("host") for e in errors] == ["10.0.0.1", "10.0.0.2"]


def _page(*result_ids):
    results = "".join(f'<result id="{r}"/>' for r in result_ids)
    return ET.fromstring(
        '<get_reports_response><report id="x"><report id="x">'
        f"<scan_run_status>Done</scan_run_status><results>{results}</results>"
        "</report></report></get_reports_response>"
    )


def test_fetch_asks_for_every_qod(monkeypatch):
    # gvmd defaults to min_qod=70, which drops the whole low-confidence tail.
    # The cassette records the QoD instead and Soundwave applies the floor, so
    # the fetch has to ask for the lot.
    asked = []
    monkeypatch.setattr(openvas_client, "run_gmp", lambda params, xml: asked.append(xml) or _page("a"))
    _fetch_report(PARAMS, "r1")
    assert "min_qod=0" in asked[0]
    assert "levels=chml" in asked[0]


def test_fetch_stops_on_a_report_that_is_not_done(monkeypatch):
    running = ET.fromstring(
        '<get_reports_response><report id="x"><report id="x">'
        "<scan_run_status>Running</scan_run_status><results/></report></report></get_reports_response>"
    )
    monkeypatch.setattr(openvas_client, "run_gmp", lambda params, xml: running)
    assert _fetch_report(PARAMS, "r1") is None
