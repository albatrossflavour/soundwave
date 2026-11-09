"""Run from files/python with: python3 -m pytest tests -q"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib import findings as F  # noqa: E402


def _host(**over):
    return {**F.EMPTY_HOST, "status": "scanned", **over}


def _doc(name="openvas", hosts=None, checks=None, findings=None, dropped=None,
         unmapped=None, generated_at="2026-09-16T00:00:00Z", schema=F.SCHEMA):
    return {
        "schema": schema,
        "cassette": {"name": name, "scanner": "greenbone", "generated_at": generated_at},
        "hosts": hosts or {},
        "checks": checks or {},
        "findings": findings or [],
        "dropped": dropped or [],
        "unmapped": unmapped or [],
    }


def _check(**over):
    base = {
        "name": "A check", "summary": "It is bad.", "solution": "Fix it.",
        "fix_type": "vendor-fix", "severity": "high", "cvss_score": 7.5,
        "cvss_version": "3.0", "cvss_vector": "CVSS:3.1/AV:N", "cves": [],
        "references": [], "kev": False,
    }
    base.update(over)
    return base


def _finding(**over):
    base = {
        "certname": "node.lab", "check_id": "greenbone:1", "detected_at": "",
        "confidence": 100, "state": "", "port": None, "evidence": "",
        "packages": [], "kbs": [],
    }
    base.update(over)
    return base


# Document.check: the same check arriving from a second host must not clobber
# what the first one said.

def test_check_keeps_the_worst_score():
    document = F.Document("openvas", "greenbone")
    document.check("greenbone:1", **_check(cvss_score=5.0, severity="medium", cvss_version="2.0"))
    document.check("greenbone:1", **_check(cvss_score=7.5, severity="high", cvss_version="3.0"))
    stored = document.checks["greenbone:1"]
    assert (stored["cvss_score"], stored["severity"], stored["cvss_version"]) == (7.5, "high", "3.0")


def test_check_ignores_a_lower_score():
    document = F.Document("openvas", "greenbone")
    document.check("greenbone:1", **_check(cvss_score=7.5, severity="high"))
    document.check("greenbone:1", **_check(cvss_score=5.0, severity="medium"))
    assert document.checks["greenbone:1"]["severity"] == "high"


def test_check_unions_cves():
    document = F.Document("openvas", "greenbone")
    document.check("greenbone:1", **_check(cves=["CVE-2026-2"]))
    document.check("greenbone:1", **_check(cves=["CVE-2026-1", "CVE-2026-2"]))
    assert document.checks["greenbone:1"]["cves"] == ["CVE-2026-1", "CVE-2026-2"]


@pytest.mark.parametrize("first,second", [(False, True), (True, False)])
def test_check_kev_is_sticky(first, second):
    document = F.Document("openvas", "greenbone")
    document.check("greenbone:1", **_check(kev=first))
    document.check("greenbone:1", **_check(kev=second))
    assert document.checks["greenbone:1"]["kev"] is True


# Drops. A filter that quietly starts eating real findings is worse than the
# noise it was written to remove, so the counts have to be exact.

def test_drops_count_every_hit_but_cap_the_sample():
    drops = F.Drops()
    for n in range(12):
        drops.add("running-kernel", "another stream", f"node{n % 3}.lab", {"n": n})
    (entry,) = drops.to_list()
    assert entry["findings"] == 12
    assert entry["hosts"] == 3
    assert len(entry["sample"]) == F.SAMPLE_CAP
    assert entry["sample"][0] == {"n": 0}
    assert drops.total() == 12


def test_drops_are_listed_by_filter_name():
    drops = F.Drops()
    drops.add("unfixed", "no fix published", "node.lab", {})
    drops.add("different-stream", "older build", "node.lab", {})
    assert [e["filter"] for e in drops.to_list()] == ["different-stream", "unfixed"]
    assert drops.to_list()[0]["reason"] == "older build"


def test_write_is_atomic_and_readable(tmp_path):
    document = F.Document("openvas", "greenbone", scanner_version="22.4", run_id="r1")
    document.host("node.lab", status="scanned")
    document.check("greenbone:1", **_check())
    document.finding(**_finding())
    path = tmp_path / "openvas.json"
    document.write(str(path))

    written = json.loads(path.read_text())
    assert written["schema"] == "puppet-findings/1"
    assert written["cassette"]["name"] == "openvas"
    assert written["cassette"]["run_id"] == "r1"
    assert written["cassette"]["generated_at"]
    assert list(written["hosts"]) == ["node.lab"]
    # No half-written temporary left beside it for a reader to trip over.
    assert [p.name for p in tmp_path.iterdir()] == ["openvas.json"]
    assert oct(path.stat().st_mode & 0o777) == "0o640"


# The cassette says what its confidence numbers are out of, so
# a consumer's 70 cut is drawn on a scale it fits rather than assumed to fit.
def test_a_declared_confidence_scale_is_written_on_the_cassette(tmp_path):
    scale = {"min": 0, "max": 100, "kind": "qod"}
    document = F.Document("openvas", "greenbone", run_id="r1", confidence_scale=scale)
    assert document.to_dict()["cassette"]["confidence_scale"] == scale


# Absent rather than null, so a cassette that has not said stays exactly the
# shape it always was, which the findings API reads as the 0-100 it assumes.
def test_an_undeclared_confidence_scale_is_left_out(tmp_path):
    document = F.Document("openvas", "greenbone", run_id="r1")
    assert "confidence_scale" not in document.to_dict()["cassette"]


# A scanner that does not report a version or a feed is not a
# scanner whose version is blank. The findings API keeps a key sent as null apart from
# one sent empty, so the empty string and the empty object said the wrong one.
def test_an_unreported_version_and_feed_are_null_not_empty(tmp_path):
    cassette = F.Document("openvas", "greenbone", run_id="r1").to_dict()["cassette"]
    assert cassette["scanner_version"] is None
    assert cassette["feed"] is None


def test_a_reported_version_and_feed_are_kept(tmp_path):
    feed = {"name": "vuls-nightly-db", "version": "0"}
    cassette = F.Document("vuls", "vuls", scanner_version="0.40.1", feed=feed, run_id="r1").to_dict()["cassette"]
    assert cassette["scanner_version"] == "0.40.1"
    assert cassette["feed"] == feed


# read_cassettes: one broken cassette must not take the other's findings with it.

def test_read_cassettes_skips_what_it_cannot_use(tmp_path, caplog):
    (tmp_path / "good.json").write_text(json.dumps(_doc()))
    (tmp_path / "broken.json").write_text("{not json")
    (tmp_path / "old.json").write_text(json.dumps(_doc(schema="puppet-findings/0")))
    (tmp_path / "notes.txt").write_text("ignored")

    with caplog.at_level("ERROR", logger="transformer"):
        loaded = F.read_cassettes(str(tmp_path))

    assert [d["cassette"]["name"] for d in loaded] == ["openvas"]
    assert "broken.json" in caplog.text
    assert "puppet-findings/0" in caplog.text


def test_read_cassettes_on_a_missing_directory(tmp_path, caplog):
    with caplog.at_level("ERROR", logger="transformer"):
        assert F.read_cassettes(str(tmp_path / "nope")) == []
    assert "Cannot read cassette directory" in caplog.text


# merge

def test_merge_unions_hosts_and_concatenates_findings():
    a = _doc("openvas", hosts={"a.lab": _host()}, findings=[_finding(certname="a.lab")])
    b = _doc("vuls", hosts={"b.lab": _host()}, findings=[_finding(certname="b.lab")])
    hosts, _, findings = F.merge([a, b])
    assert sorted(hosts) == ["a.lab", "b.lab"]
    assert [f["certname"] for f in findings] == ["a.lab", "b.lab"]


def test_merge_prefers_the_later_scan_end():
    a = _doc("openvas", hosts={"a.lab": _host(scan_end="2026-09-15T00:00:00Z", ipaddress="10.0.0.1")})
    b = _doc("vuls", hosts={"a.lab": _host(scan_end="2026-09-16T00:00:00Z", ipaddress="10.0.0.2")})
    hosts, _, _ = F.merge([a, b])
    assert hosts["a.lab"]["scan_end"] == "2026-09-16T00:00:00Z"
    assert hosts["a.lab"]["ipaddress"] == "10.0.0.2"


@pytest.mark.parametrize("order", ["scanned first", "unreachable first"])
def test_merge_keeps_scanned_over_unreachable(order):
    # The vuls cassette writes an unreachable host with no scan end, so the cassette that
    # actually reached the node is the one that should decide its status.
    scanned = _doc("openvas", hosts={"a.lab": _host(scan_end="2026-09-15T00:00:00Z")})
    missed = _doc("vuls", hosts={"a.lab": _host(status="unreachable", scan_end="")})
    documents = [scanned, missed] if order == "scanned first" else [missed, scanned]
    hosts, _, _ = F.merge(documents)
    assert hosts["a.lab"]["status"] == "scanned"


def test_merge_keeps_the_first_of_two_identical_check_ids(caplog):
    a = _doc("openvas", checks={"greenbone:1": _check(name="first")})
    b = _doc("vuls", checks={"greenbone:1": _check(name="second")})
    with caplog.at_level("WARNING", logger="transformer"):
        _, checks, _ = F.merge([a, b])
    assert checks["greenbone:1"]["name"] == "first"
    assert "more than one cassette" in caplog.text


def test_merge_fills_in_missing_host_keys():
    # A cassette written against an older version of the format must not make
    # consumers test for the presence of every field.
    sparse = _doc("vuls", hosts={"a.lab": {"status": "scanned"}})
    hosts, _, _ = F.merge([sparse])
    assert hosts["a.lab"]["authenticated"] is False
    assert hosts["a.lab"]["warnings"] == []


# Document.finding: the format promises one finding per certname, check and
# port, and Greenbone returns a result row per piece of evidence.

def test_finding_folds_a_repeat_of_the_same_check_and_port():
    document = F.Document("openvas", "greenbone")
    document.finding(**_finding(port="22/tcp", evidence="group14"))
    document.finding(**_finding(port="22/tcp", evidence="group1"))
    (finding,) = document.findings
    assert finding["evidence"] == "group14\n\ngroup1"


def test_finding_keeps_a_different_port_apart():
    document = F.Document("openvas", "greenbone")
    document.finding(**_finding(port="22/tcp"))
    document.finding(**_finding(port="443/tcp"))
    assert len(document.findings) == 2


def test_finding_does_not_repeat_identical_evidence():
    document = F.Document("openvas", "greenbone")
    document.finding(**_finding(evidence="same"))
    document.finding(**_finding(evidence="same"))
    (finding,) = document.findings
    assert finding["evidence"] == "same"


def test_finding_folds_to_the_higher_confidence():
    document = F.Document("openvas", "greenbone")
    document.finding(**_finding(confidence=30))
    document.finding(**_finding(confidence=98))
    assert document.findings[0]["confidence"] == 98


def test_finding_folding_never_reads_an_unrated_row_as_zero():
    document = F.Document("openvas", "greenbone")
    document.finding(**_finding(confidence=None))
    document.finding(**_finding(confidence=70))
    assert document.findings[0]["confidence"] == 70


def test_finding_folding_keeps_null_when_neither_row_is_rated():
    document = F.Document("openvas", "greenbone")
    document.finding(**_finding(confidence=None))
    document.finding(**_finding(confidence=None))
    assert document.findings[0]["confidence"] is None


def test_finding_folding_unions_packages_and_takes_the_worst_state():
    document = F.Document("openvas", "greenbone")
    document.finding(**_finding(state="fixable", packages=[{"name": "curl"}]))
    document.finding(**_finding(state="pro-only", packages=[{"name": "curl"}, {"name": "libcurl3"}]))
    (finding,) = document.findings
    assert [p["name"] for p in finding["packages"]] == ["curl", "libcurl3"]
    assert finding["state"] == "pro-only"


# correlate: findings from any number of cassettes describing one weakness.

def _cdoc(name, checks, findings):
    return {"cassette": {"name": name}, "checks": checks, "findings": findings}


def _two_cassettes(check_a=None, check_b=None, find_a=None, find_b=None):
    a = _cdoc("openvas", {"greenbone:1": dict({"cves": ["CVE-1"], "fix_type": "vendor-fix"}, **(check_a or {}))},
              [_finding(check_id="greenbone:1", **(find_a or {}))])
    b = _cdoc("vuls", {"vuls:1": dict({"cves": ["CVE-1"], "fix_type": "vendor-fix"}, **(check_b or {}))},
              [_finding(check_id="vuls:1", **(find_b or {}))])
    return [a, b]


def test_correlate_joins_two_cassettes_on_one_cve():
    record = F.correlate(_two_cassettes())
    assert record.groups == 1
    assert record.cross_cassette == 1
    assert record.findings == 2


def test_correlate_ignores_a_check_with_no_cve():
    """Grouping on an absent CVE joined OpenSSH to OpenSSL on the lab."""
    docs = _two_cassettes(check_a={"cves": []}, check_b={"cves": []})
    assert F.correlate(docs).groups == 0


def test_correlate_ignores_an_identifier_that_is_not_a_cve():
    """The vuls cassette puts Microsoft advisory IDs in `cves`."""
    docs = _two_cassettes(check_a={"cves": ["ADV190023"]}, check_b={"cves": ["ADV190023"]})
    assert F.correlate(docs).groups == 0


def test_correlate_keeps_a_package_finding_apart_from_a_service_finding():
    docs = _two_cassettes(find_a={"packages": [{"name": "openssl"}]}, find_b={"port": "443/tcp"})
    assert F.correlate(docs).groups == 0


def test_correlate_keeps_a_patch_apart_from_a_mitigation():
    docs = _two_cassettes(check_b={"cves": ["CVE-1"], "fix_type": "mitigation"})
    assert F.correlate(docs).groups == 0


def test_correlate_never_spans_hosts():
    docs = _two_cassettes(find_b={"certname": "other.lab"})
    assert F.correlate(docs).groups == 0


def test_correlate_does_not_chain_through_a_shared_cve():
    """A carries CVE-1, B carries CVE-1 and CVE-2, C carries CVE-2.

    Under transitive closure all three become one blob. They must stay as two
    groups: one for each CVE.
    """
    docs = [_cdoc("openvas", {
        "greenbone:a": {"cves": ["CVE-1"], "fix_type": "vendor-fix"},
        "greenbone:b": {"cves": ["CVE-1", "CVE-2"], "fix_type": "vendor-fix"},
        "greenbone:c": {"cves": ["CVE-2"], "fix_type": "vendor-fix"},
    }, [_finding(check_id=f"greenbone:{x}") for x in "abc"])]
    record = F.correlate(docs)
    assert record.groups == 2
    assert all(len(s["joined"]) == 2 for s in record.to_dict()["sample"])


def test_correlate_leaves_an_excepted_pair_uncorrelated():
    docs = _two_cassettes()
    record = F.correlate(docs, exceptions=[("greenbone:1", "vuls:1")])
    assert record.groups == 0
    assert record.exceptions_applied == 1


def test_correlate_counts_a_within_cassette_join_but_not_as_cross_cassette():
    docs = [_cdoc("openvas", {
        "greenbone:a": {"cves": ["CVE-1"], "fix_type": "vendor-fix"},
        "greenbone:b": {"cves": ["CVE-1"], "fix_type": "vendor-fix"},
    }, [_finding(check_id="greenbone:a"), _finding(check_id="greenbone:b")])]
    record = F.correlate(docs)
    assert record.groups == 1
    assert record.cross_cassette == 0


def test_correlate_skips_a_finding_whose_check_is_missing():
    docs = [_cdoc("openvas", {}, [_finding(check_id="greenbone:gone")])]
    assert F.correlate(docs).groups == 0


def test_correlate_sample_is_bounded_and_the_counts_are_not():
    checks, findings = {}, []
    for n in range(F.SAMPLE_CAP + 5):
        for side in ("a", "b"):
            checks[f"greenbone:{n}{side}"] = {"cves": [f"CVE-{n}"], "fix_type": "vendor-fix"}
            findings.append(_finding(check_id=f"greenbone:{n}{side}"))
    record = F.correlate([_cdoc("openvas", checks, findings)])
    assert record.groups == F.SAMPLE_CAP + 5
    assert len(record.to_dict()["sample"]) == F.SAMPLE_CAP


def test_correlate_is_deterministic():
    docs = _two_cassettes()
    assert F.correlate(docs).to_dict() == F.correlate(list(reversed(docs))).to_dict()


# clock_skew: a scan that has not happened yet is a clock, not a scan.

NOW = 1789575581


def _hosts(*ends):
    return {f"h{i}.lab": dict(F.EMPTY_HOST, scan_end=e) for i, e in enumerate(ends)}


def test_clock_skew_is_zero_when_scans_are_in_the_past():
    assert F.clock_skew(_hosts("2026-09-16T16:19:41Z"), now=NOW + 3600) == 0


def test_clock_skew_reports_a_future_scan_end():
    assert F.clock_skew(_hosts("2026-09-16T16:19:41Z"), now=NOW - 7200) == 7200


def test_clock_skew_tolerates_ordinary_drift():
    """A scanner host a few seconds ahead is drift, not a timezone."""
    assert F.clock_skew(_hosts("2026-09-16T16:19:41Z"), now=NOW - 30) == 0


def test_clock_skew_catches_the_ten_hour_timezone_case():
    """Local time wearing a Z, which is the fault this exists to name."""
    assert F.clock_skew(_hosts("2026-09-17T02:19:41Z"), now=NOW) == 36000


def test_clock_skew_takes_the_worst_host():
    skew = F.clock_skew(_hosts("2026-09-16T16:19:41Z", "2026-09-17T02:19:41Z"), now=NOW)
    assert skew == 36000


def test_clock_skew_ignores_hosts_with_no_scan_end():
    assert F.clock_skew(_hosts("", "2026-09-17T02:19:41Z"), now=NOW) == 36000


@pytest.mark.parametrize("hosts", [{}, None])
def test_clock_skew_is_zero_when_nothing_was_scanned(hosts):
    assert F.clock_skew(hosts, now=NOW) == 0


def test_clock_skew_accepts_an_offset_as_readily_as_a_z():
    """The vuls cassette writes +10:00; the same instant must not read as skew."""
    assert F.clock_skew(_hosts("2026-09-17T02:19:41+10:00"), now=NOW) == 0


# to_vr

def test_to_vr_applies_the_confidence_floor(caplog):
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check()}
    findings = [_finding(confidence=30), _finding(confidence=70)]
    with caplog.at_level("INFO", logger="transformer"):
        data, _ = F.to_vr(hosts, checks, findings)
    (record,) = data
    assert len(record["vulnerabilities"]) == 1
    assert "below confidence 70" in caplog.text


@pytest.mark.parametrize("absent", [False, True])
def test_to_vr_keeps_a_finding_that_carries_no_confidence(absent, caplog):
    """A scanner with no QoD equivalent must not have its whole push filtered.

    Nessus offers only booleans and Qualys nothing per detection, so defaulting
    an absent confidence to 0 dropped every finding such a cassette produced,
    under a log line that read exactly like the floor working normally.
    """
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check()}
    finding = _finding()
    if absent:
        del finding["confidence"]
    else:
        finding["confidence"] = None
    with caplog.at_level("INFO", logger="transformer"):
        data, _ = F.to_vr(hosts, checks, [finding])
    assert len(data[0]["vulnerabilities"]) == 1
    assert "carry no confidence" in caplog.text


def test_to_vr_still_drops_a_scored_finding_below_the_floor():
    """The floor goes on working for a cassette that does report confidence."""
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check()}
    data, _ = F.to_vr(hosts, checks, [_finding(confidence=0)])
    assert data[0]["vulnerabilities"] == []


def test_to_vr_floor_can_be_lowered():
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check()}
    data, _ = F.to_vr(hosts, checks, [_finding(confidence=30)], min_confidence=0)
    assert len(data[0]["vulnerabilities"]) == 1


def test_to_vr_sends_a_clean_host_with_an_empty_list():
    # A node left out of a push keeps whatever VR already held, so a patched
    # node would show its old findings forever.
    data, _ = F.to_vr({"clean.lab": _host(ipaddress="10.0.0.9")}, {}, [])
    assert data == [{"hostname": "clean.lab", "ipaddress": "10.0.0.9", "vulnerabilities": []}]


def test_to_vr_leaves_out_a_host_that_was_never_reached():
    hosts = {"gone.lab": _host(status="unreachable"), "here.lab": _host()}
    data, _ = F.to_vr(hosts, {}, [])
    assert [r["hostname"] for r in data] == ["here.lab"]


def test_to_vr_keeps_a_partial_host():
    data, _ = F.to_vr({"half.lab": _host(status="partial")}, {}, [])
    assert [r["hostname"] for r in data] == ["half.lab"]


def test_to_vr_skips_a_finding_with_no_check(caplog):
    hosts = {"node.lab": _host()}
    with caplog.at_level("WARNING", logger="transformer"):
        data, _ = F.to_vr(hosts, {}, [_finding(check_id="greenbone:missing")])
    assert data[0]["vulnerabilities"] == []
    assert "unknown check" in caplog.text


def test_to_vr_warns_about_a_finding_with_no_host(caplog):
    with caplog.at_level("WARNING", logger="transformer"):
        data, _ = F.to_vr({}, {"greenbone:1": _check()}, [_finding()])
    assert data == []
    assert "no host block" in caplog.text


def test_to_vr_carries_package_names_and_cves():
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check(cves=["CVE-2026-1"])}
    findings = [_finding(packages=[{"name": "curl", "fixed": "7.81.0"}, {"name": ""}])]
    data, _ = F.to_vr(hosts, checks, findings)
    vulnerability = data[0]["vulnerabilities"][0]
    assert vulnerability["packages"] == ["curl"]
    assert vulnerability["cves"] == ["CVE-2026-1"]
    assert vulnerability["severity"] == "high"
    assert vulnerability["cvss_score"] == 7.5


def test_to_vr_says_a_fix_needs_a_subscription():
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check(solution="Please install the updated package(s).")}
    data, _ = F.to_vr(hosts, checks, [_finding(state="pro-only")])
    solution = data[0]["vulnerabilities"][0]["solution"]
    assert solution.startswith("Fixed only in a subscription archive")
    assert solution.endswith("\n\nPlease install the updated package(s).")


def test_to_vr_says_a_package_is_unfixed():
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check(solution="Please install the updated package(s).")}
    data, _ = F.to_vr(hosts, checks, [_finding(state="unfixed")])
    solution = data[0]["vulnerabilities"][0]["solution"]
    assert solution.startswith("No fix has been published")


def test_to_vr_leaves_an_ordinary_solution_alone():
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check(solution="Fix it.")}
    data, _ = F.to_vr(hosts, checks, [_finding(state="fixable")])
    assert data[0]["vulnerabilities"][0]["solution"] == "Fix it."


def test_to_vr_falls_back_when_a_check_has_no_text():
    hosts = {"node.lab": _host()}
    checks = {"greenbone:1": _check(summary="", solution="")}
    data, _ = F.to_vr(hosts, checks, [_finding()])
    vulnerability = data[0]["vulnerabilities"][0]
    assert vulnerability["summary"] == "No description available"
    assert vulnerability["solution"] == "No solution available"


def test_to_vr_scan_date_is_the_newest_scan_end():
    hosts = {
        "a.lab": _host(scan_end="2026-09-15T05:09:49Z"),
        "b.lab": _host(scan_end="2026-09-16T07:00:00Z"),
    }
    _, scan_date = F.to_vr(hosts, {}, [])
    assert scan_date == F.iso_to_epoch("2026-09-16T07:00:00Z")


def test_to_vr_scan_date_without_any_scan_end():
    # Better a push stamped now than one rejected for a missing date.
    _, scan_date = F.to_vr({"a.lab": _host()}, {}, [])
    assert scan_date > 0


@pytest.mark.parametrize("score,expected", [
    (10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "none"),
])
def test_severity_of(score, expected):
    assert F.severity_of(score) == expected


def test_iso_to_epoch_accepts_z_and_offsets():
    assert F.iso_to_epoch("2026-09-15T07:57:25Z") == 1789459045
    assert F.iso_to_epoch("2026-09-15T17:57:25+10:00") == 1789459045


@pytest.mark.parametrize("text", ["", None, "not a date", "0001-01-01"])
def test_iso_to_epoch_rejects_the_rest(text):
    assert F.iso_to_epoch(text) is None


def test_to_vr_skips_an_unscored_finding():
    """VR's schema rejects a finding with no cvss_version, and 0.0 is not a
    substitute: it is a real CVSS score meaning no impact. Microsoft's ADV
    advisories arrive this way, and PE answered the whole push with a 400
    schema-validation-exception until they were held back."""
    hosts = {"n1": dict(F.EMPTY_HOST, status="scanned")}
    checks = {
        "vuls:ADV190023": {"name": "adv", "cvss_score": 0.0, "cvss_version": "", "severity": "none"},
        "vuls:KB1": {"name": "kb", "cvss_score": 7.8, "cvss_version": "3.1", "severity": "high"},
    }
    findings = [
        {"certname": "n1", "check_id": "vuls:ADV190023", "confidence": 100},
        {"certname": "n1", "check_id": "vuls:KB1", "confidence": 100},
    ]
    data, _ = F.to_vr(hosts, checks, findings, min_confidence=70)
    names = [v["name"] for v in data[0]["vulnerabilities"]]
    assert names == ["kb"]


def test_to_vr_reports_an_unknown_check_rather_than_counting_it_unscored():
    """The unknown-check warning has to come first: a missing check has no
    cvss_version either, so guarding on the score would swallow it silently."""
    hosts = {"n1": dict(F.EMPTY_HOST, status="scanned")}
    findings = [{"certname": "n1", "check_id": "vuls:missing", "confidence": 100}]
    data, _ = F.to_vr(hosts, {}, findings, min_confidence=70)
    assert data[0]["vulnerabilities"] == []


def test_to_vr_says_a_mitigation_is_not_a_patch():
    """VR's only remediation is a patch job, so a mitigation finding offers a
    button that cannot close it. 45 of the 87 findings VR sees on the lab are
    mitigations and nothing on the board said so."""
    hosts = {"n1": dict(F.EMPTY_HOST, status="scanned")}
    checks = {"c": {"name": "dhe", "solution": "Disable DHE key exchange.", "fix_type": "mitigation",
                    "cvss_score": 7.5, "cvss_version": "3.1", "severity": "high"}}
    findings = [{"certname": "n1", "check_id": "c", "confidence": 100, "state": ""}]
    data, _ = F.to_vr(hosts, checks, findings, min_confidence=70)
    solution = data[0]["vulnerabilities"][0]["solution"]
    assert solution.startswith("Not closable by a patch job.")
    # Sentence case on purpose: the old wording shouted, and PE renders this in a
    # field titled Remediation where it is the first thing a reader sees.
    assert "NOT A PATCH" not in solution
    assert solution.endswith("Disable DHE key exchange.")


def test_to_vr_says_both_the_fix_type_and_the_host_state():
    """They are different facts: what kind of fix exists, and whether this host
    could take it. A Pro-only vendor fix is both a real patch and unreachable."""
    hosts = {"n1": dict(F.EMPTY_HOST, status="scanned")}
    checks = {"c": {"name": "x", "solution": "Update the package.", "fix_type": "none-available",
                    "cvss_score": 5.0, "cvss_version": "3.1", "severity": "medium"}}
    findings = [{"certname": "n1", "check_id": "c", "confidence": 100, "state": "pro-only"}]
    data, _ = F.to_vr(hosts, checks, findings, min_confidence=70)
    solution = data[0]["vulnerabilities"][0]["solution"]
    assert solution.index("Not closable by a patch job.") < solution.index("subscription archive")
    assert solution.endswith("Update the package.")


def test_to_vr_leaves_a_vendor_fix_unannotated():
    """A patch job does close these, so saying anything would be noise on the
    2,842 findings that are ordinary pending updates."""
    hosts = {"n1": dict(F.EMPTY_HOST, status="scanned")}
    checks = {"c": {"name": "x", "solution": "Update openssl.", "fix_type": "vendor-fix",
                    "cvss_score": 7.5, "cvss_version": "3.1", "severity": "high"}}
    findings = [{"certname": "n1", "check_id": "c", "confidence": 100, "state": "fixable"}]
    data, _ = F.to_vr(hosts, checks, findings, min_confidence=70)
    assert data[0]["vulnerabilities"][0]["solution"] == "Update openssl."


# Composition: sets of findings that share a
# correlation group become one record for VR, capped so a wide advisory cannot
# chain unrelated findings together, and composed within one cassette only for
# the findings API.

PIP = [{"name": "python3-pip"}]


def _pip_parts():
    """Greenbone's three-part pip advisory, as it sits on the lab: .1 and .2
    carry all three CVEs, .3 carries one, so .1 and .2 sit in three groups."""
    three = ["CVE-A", "CVE-B", "CVE-C"]
    checks = {
        "greenbone:p.1": _check(name="USN part 1", cves=three, cvss_score=7.5),
        "greenbone:p.2": _check(name="USN part 2", cves=three, cvss_score=7.5),
        "greenbone:p.3": _check(name="USN part 3", cves=["CVE-C"], cvss_score=7.5),
    }
    findings = [_finding(check_id=cid, packages=PIP, confidence=c)
                for cid, c in (("greenbone:p.1", 70), ("greenbone:p.2", 99), ("greenbone:p.3", 80))]
    return _doc("openvas", checks=checks, findings=findings)


def test_findings_sharing_groups_compose_into_one_set():
    sets, capped = F.composable_sets([_pip_parts()])
    assert capped == []
    assert [sorted(f["check_id"] for _, f, _ in members) for members in sets] == [
        ["greenbone:p.1", "greenbone:p.2", "greenbone:p.3"]]


def test_a_set_over_the_cap_is_left_alone_and_counted():
    cves = [f"CVE-{i}" for i in range(F.COMPOSE_MAX_CVES + 1)]
    checks = {"greenbone:wide": _check(cves=cves), "greenbone:narrow": _check(cves=["CVE-0"])}
    findings = [_finding(check_id="greenbone:wide"), _finding(check_id="greenbone:narrow")]
    sets, capped = F.composable_sets([_doc(checks=checks, findings=findings)])
    assert sets == []
    assert len(capped) == 1


def test_an_excepted_pair_does_not_compose():
    checks = {"greenbone:a": _check(cves=["CVE-1"]), "greenbone:b": _check(cves=["CVE-1"])}
    findings = [_finding(check_id="greenbone:a"), _finding(check_id="greenbone:b")]
    sets, _ = F.composable_sets([_doc(checks=checks, findings=findings)],
                                exceptions=[("greenbone:a", "greenbone:b")])
    assert sets == []


def _scipy():
    """The lab's scipy pair: Greenbone's advisory carries two CVEs at 9.8,
    Vuls reports only one of them, at 5.5."""
    return [
        _doc("openvas", checks={"greenbone:adv": _check(name="scipy advisory", cves=["CVE-25399", "CVE-29824"],
                                                           cvss_score=9.8)},
             findings=[_finding(check_id="greenbone:adv", packages=[{"name": "scipy"}],
                                detected_at="2026-09-24T00:01:00Z")]),
        _doc("vuls", checks={"vuls:25399": _check(name="scipy 25399", cves=["CVE-25399"], cvss_score=5.5)},
             findings=[_finding(check_id="vuls:25399", packages=[{"name": "scipy"}],
                                detected_at="2026-09-24T02:20:00Z")]),
    ]


# The fault found on the lab before this shipped: the set's narrowest member
# is Vuls at 5.5, and scoring the record from it would show CVE-29824, which
# only Greenbone reports and scores 9.8, as medium.
def test_the_record_takes_the_highest_per_cve_score_so_no_cve_is_understated():
    sets, _ = F.composable_sets(_scipy())
    check = F.compose_check(sets[0])
    assert check["cvss_score"] == 9.8
    assert check["severity"] == "critical"
    assert check["cves"] == ["CVE-25399", "CVE-29824"]


def test_the_composed_finding_keeps_every_contributor_and_its_own_age():
    sets, _ = F.composable_sets(_scipy())
    finding = F.compose_finding(sets[0])
    assert [(c["name"], c["check_id"], c["detected_at"]) for c in finding["contributors"]] == [
        ("openvas", "greenbone:adv", "2026-09-24T00:01:00Z"),
        ("vuls", "vuls:25399", "2026-09-24T02:20:00Z")]
    assert finding["detected_at"] == "2026-09-24T02:20:00Z"
    assert set(finding["contributors"][0]) == set(F.CONTRIBUTOR_FIELDS)


def test_confidence_is_the_highest_and_state_the_most_pessimistic():
    doc = _pip_parts()
    doc["findings"][0]["state"] = "fixable"
    doc["findings"][1]["state"] = "unfixed"
    sets, _ = F.composable_sets([doc])
    finding = F.compose_finding(sets[0])
    assert finding["confidence"] == 99
    assert finding["state"] == "unfixed"


def test_vr_gets_one_record_per_set_and_says_so_in_the_prose():
    docs = [_pip_parts()]
    hosts = {"node.lab": dict(F.EMPTY_HOST, status="scanned")}
    _, checks, findings = F.merge(docs)
    checks, findings, stats = F.compose_for_vr(docs, checks, findings)
    data, _ = F.to_vr(hosts, checks, findings)
    records = data[0]["vulnerabilities"]
    assert len(records) == 1
    assert stats == {"sets": 1, "findings": 3, "cross_cassette_sets": 0, "capped_sets": 0}
    assert "One weakness reported by 3 checks" in records[0]["solution"]


def test_findings_api_is_composed_within_a_cassette_and_never_across():
    within, stats = F.compose_document(_pip_parts())
    assert len(within["findings"]) == 1
    assert within["findings"][0]["check_id"] in _pip_parts()["checks"]
    assert stats["sets"] == 1
    for doc in _scipy():
        composed, stats = F.compose_document(doc)
        assert composed["findings"] == doc["findings"]
        assert stats["sets"] == 0


def test_composition_does_not_touch_its_inputs():
    doc = _pip_parts()
    before = json.dumps(doc, sort_keys=True)
    F.compose_document(doc)
    F.compose_for_vr([doc], *F.merge([doc])[1:])
    assert json.dumps(doc, sort_keys=True) == before
