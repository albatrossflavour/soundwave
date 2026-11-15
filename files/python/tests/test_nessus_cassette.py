"""Run from files/python with: python3 -m pytest tests -q

Fixtures follow the shape of public .nessus files (Nessus 10.1 and 10.8) rather
than a real export from this estate, which nobody has yet. When one exists it
belongs here.
"""

import os
import sys
from xml.sax.saxutils import escape

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cassettes.nessus import (  # noqa: E402
    cvss_of,
    packages_from,
    parse_exports,
    split_package,
)
from lib import findings as F  # noqa: E402

# 2026-11-13T02:15:31Z
END = "1794536131"
START = "1794535800"


def _item(plugin, severity, *, name="Check", port="0", protocol="tcp", output=None, children=""):
    out = f"<plugin_output>{escape(output)}</plugin_output>" if output is not None else ""
    return (f'<ReportItem port="{port}" svc_name="general" protocol="{protocol}" severity="{severity}" '
            f'pluginID="{plugin}" pluginName="{escape(name)}" pluginFamily="General">'
            f"{children}{out}</ReportItem>")


def _host(name, items=(), *, ip="192.0.2.5", fqdn="", credentialed="true",
          cpe="cpe:/o:canonical:ubuntu_linux:22.04 -> Canonical Ubuntu Linux", end=END):
    props = [("host-ip", ip), ("Credentialed_Scan", credentialed),
             ("HOST_START_TIMESTAMP", START), ("HOST_END_TIMESTAMP", end),
             ("HOST_END", "Fri Nov 13 13:15:31 2026")]
    if fqdn:
        props.append(("host-fqdn", fqdn))
    if cpe:
        props.append(("cpe-0", cpe))
    tags = "".join(f'<tag name="{k}">{escape(v)}</tag>' for k, v in props)
    return f'<ReportHost name="{name}"><HostProperties>{tags}</HostProperties>{"".join(items)}</ReportHost>'


def _file(tmp_path, hosts, name="scan.nessus", report="Weekly Linux"):
    path = tmp_path / name
    path.write_text('<?xml version="1.0" ?><NessusClientData_v2><Policy><policyName>x</policyName></Policy>'
                    f'<Report name="{report}">{"".join(hosts)}</Report></NessusClientData_v2>')
    return str(path)


SCAN_INFO = _item("19506", "0", name="Nessus Scan Information", output=(
    "Information about this scan : \n\nNessus version : 10.8.1\nPlugin feed version : 202611120000\n"
    "Credentialed checks : yes (on the localhost)\n"))

RPM_OUTPUT = ("\nRemote package installed : openssl-libs-1.1.1k-7.el8_6\n"
              "Should be                : openssl-libs-1.1.1k-9.el8_7\n")

OPENSSL = _item("166000", "3", name="RHEL 8 : openssl (RHSA-2026:1234)", output=RPM_OUTPUT, children=(
    "<cvss3_base_score>7.5</cvss3_base_score><cvss3_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</cvss3_vector>"
    "<cvss_base_score>5.0</cvss_base_score><cvss_vector>CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N</cvss_vector>"
    "<cve>CVE-2026-1234</cve><cve>CVE-2026-1235</cve><has_patch>true</has_patch>"
    "<see_also>https://access.redhat.com/errata/RHSA-2026:1234\nhttps://access.redhat.com/security/cve/CVE-2026-1234</see_also>"
    "<description>An update for openssl is now available.</description><solution>Update the affected packages.</solution>"))


def _doc(tmp_path, hosts, mapping=None):
    return parse_exports([_file(tmp_path, hosts)], mapping)


def test_host_block_comes_from_host_properties(tmp_path):
    document = _doc(tmp_path, [_host("web1", [SCAN_INFO], fqdn="web1.example.com")])
    host = document.hosts["web1.example.com"]
    assert host["ipaddress"] == "192.0.2.5"
    assert (host["os_family"], host["os_release"]) == ("ubuntu", "22.04")
    assert host["authenticated"] is True
    assert host["collection"] == "nessus"
    assert host["status"] == "scanned"


def test_scan_end_is_read_from_the_epoch_not_the_local_time(tmp_path):
    """HOST_END is local time with no zone; HOST_END_TIMESTAMP cannot lie about one."""
    document = _doc(tmp_path, [_host("web1", [], fqdn="web1.example.com")])
    host = document.hosts["web1.example.com"]
    assert F.iso_to_epoch(host["scan_end"]) == int(END)
    assert host["scan_end"].endswith("+00:00")


def test_a_host_with_no_findings_still_has_a_block(tmp_path):
    document = _doc(tmp_path, [_host("clean", [SCAN_INFO], fqdn="clean.example.com")])
    assert "clean.example.com" in document.hosts
    assert document.findings == []


def test_host_map_names_the_host_and_the_rest_are_unmapped(tmp_path):
    document = _doc(tmp_path, [_host("192.0.2.5", ip="192.0.2.5"), _host("192.0.2.6", ip="192.0.2.6", fqdn="db.lan")],
                    mapping={"192.0.2.5": "web1.example.com"})
    assert set(document.hosts) == {"web1.example.com", "db.lan"}
    assert document.unmapped == [{"identifier": "192.0.2.6", "collection": "nessus", "sent_as": "db.lan"}]


def test_scan_information_fills_scanner_version_and_feed(tmp_path):
    document = _doc(tmp_path, [_host("web1", [SCAN_INFO])])
    assert document.scanner_version == "10.8.1"
    assert document.feed == {"name": "nessus-plugins", "version": "202611120000", "fetched_at": None}
    assert document.run_id == "Weekly Linux"


def test_without_scan_information_version_and_feed_are_null(tmp_path):
    out = _doc(tmp_path, [_host("web1")]).to_dict()["cassette"]
    assert out["scanner_version"] is None and out["feed"] is None


def test_informational_items_are_not_findings(tmp_path):
    document = _doc(tmp_path, [_host("web1", [SCAN_INFO, _item("10287", "0", name="Traceroute")])])
    assert document.findings == []


def test_failed_patch_assessment_makes_the_host_partial(tmp_path):
    failed = _item("21745", "0", name="OS Security Patch Assessment Failed", output="sudo failed")
    document = _doc(tmp_path, [_host("web1", [failed], fqdn="web1.example.com")])
    host = document.hosts["web1.example.com"]
    assert host["status"] == "partial"
    assert "sudo failed" in host["errors"][0]


def test_package_finding(tmp_path):
    document = _doc(tmp_path, [_host("web1", [OPENSSL], fqdn="web1.example.com")])
    check = document.checks["nessus:166000"]
    assert check["name"] == "RHEL 8 : openssl (RHSA-2026:1234)"
    assert check["fix_type"] == "vendor-fix"
    assert (check["cvss_score"], check["cvss_version"]) == (7.5, "3.1")
    assert check["severity"] == "high"
    assert check["cves"] == ["CVE-2026-1234", "CVE-2026-1235"]
    assert len(check["references"]) == 2
    (finding,) = document.findings
    assert finding["confidence"] is None
    assert finding["state"] == "fixable"
    assert finding["port"] is None
    assert finding["packages"] == [{"name": "openssl-libs", "arch": "",
                                    "installed": "1.1.1k-7.el8_6", "fixed": "1.1.1k-9.el8_7"}]


def test_fix_type_is_null_when_nessus_does_not_say(tmp_path):
    """Nessus cannot tell a mitigation from a patch, so silence is null, not none-available."""
    ssh = _item("70658", "2", name="SSH Server CBC Mode Ciphers Enabled", port="22",
                children="<cvss_base_score>2.6</cvss_base_score>")
    document = _doc(tmp_path, [_host("web1", [ssh])])
    assert document.checks["nessus:70658"]["fix_type"] is None


def test_fix_type_flags_in_order(tmp_path):
    eol = _item("1", "4", children="<unsupported_by_vendor>true</unsupported_by_vendor><has_patch>true</has_patch>")
    unpatched = _item("2", "2", children="<vendor_unpatched>true</vendor_unpatched>")
    document = _doc(tmp_path, [_host("web1", [eol, unpatched])])
    assert document.checks["nessus:1"]["fix_type"] == "will-not-fix"
    assert document.checks["nessus:2"]["fix_type"] == "none-available"


def test_port_keeps_its_protocol(tmp_path):
    ssh = _item("70658", "2", port="22", children="<cvss_base_score>2.6</cvss_base_score>")
    (finding,) = _doc(tmp_path, [_host("web1", [ssh])]).findings
    assert finding["port"] == "22/tcp"
    assert finding["state"] == ""


def test_cvss_falls_back_to_v2_and_unscored_is_empty():
    import xml.etree.ElementTree as ET
    v2 = ET.fromstring("<i><cvss_base_score>5.0</cvss_base_score><cvss_vector>CVSS2#AV:N</cvss_vector></i>")
    assert cvss_of(v2) == (5.0, "2.0", "CVSS2#AV:N")
    v3 = ET.fromstring("<i><cvss3_base_score>9.8</cvss3_base_score></i>")
    assert cvss_of(v3) == (9.8, "3.0", "")
    assert cvss_of(ET.fromstring("<i/>")) == (0.0, "", "")


def test_unscored_check_is_held_back_from_vr(tmp_path):
    """No version means Soundwave leaves it in the cassette rather than send 0.0."""
    unscored = _item("3", "1", name="Unscored")
    document = _doc(tmp_path, [_host("web1", [unscored, OPENSSL], fqdn="web1.example.com")])
    data = document.to_dict()
    records, _ = F.to_vr(data["hosts"], data["checks"], data["findings"])
    names = [v["name"] for v in records[0]["vulnerabilities"]]
    assert names == ["RHEL 8 : openssl (RHSA-2026:1234)"]


def test_null_confidence_reaches_vr(tmp_path):
    """A cassette with no confidence must not be eaten by the floor."""
    data = _doc(tmp_path, [_host("web1", [OPENSSL], fqdn="web1.example.com")]).to_dict()
    records, _ = F.to_vr(data["hosts"], data["checks"], data["findings"], min_confidence=70)
    assert len(records[0]["vulnerabilities"]) == 1


def test_kbs_from_mskb_and_xref(tmp_path):
    item = _item("200000", "4", children=(
        "<cvss3_base_score>8.8</cvss3_base_score><mskb>5042322</mskb>"
        "<xref>MSKB:5042322</xref><xref>MSKB:5041578</xref><xref>IAVA:2026-A-0001</xref>"))
    (finding,) = _doc(tmp_path, [_host("win1", [item])]).findings
    assert finding["kbs"] == ["5042322", "5041578"]


def test_kev_is_read_when_present(tmp_path):
    item = _item("4", "4", children="<cvss3_base_score>9.8</cvss3_base_score>"
                                    "<cisa-known-exploited>2026/01/15</cisa-known-exploited>")
    assert _doc(tmp_path, [_host("web1", [item])]).checks["nessus:4"]["kev"] is True
    assert _doc(tmp_path, [_host("web1", [OPENSSL])]).checks["nessus:166000"]["kev"] is False


def test_split_package():
    assert split_package("openssl-libs-1.1.1k-7.el8_6") == ("openssl-libs", "1.1.1k-7.el8_6")
    assert split_package("bind9-host_1:9.9.5.dfsg-9+deb8u11") == ("bind9-host", "1:9.9.5.dfsg-9+deb8u11")
    assert split_package("libssl3_3.0.2-0ubuntu1.10") == ("libssl3", "3.0.2-0ubuntu1.10")
    assert split_package("bash_5.1-6") == ("bash", "5.1-6")
    assert split_package("python3-ruamel_yaml-0.16.6-7.el8") == ("python3-ruamel_yaml", "0.16.6-7.el8")
    assert split_package("weird") == ("weird", "")


def test_ubuntu_package_wording():
    output = ("\n  - Installed package : openjdk-11-jdk_11.0.13+8-0ubuntu1~18.04\n"
              "    Fixed package     : openjdk-11-jdk_11.0.18+10-0ubuntu1~18.04.1\n")
    assert packages_from(output) == [{"name": "openjdk-11-jdk", "arch": "",
                                      "installed": "11.0.13+8-0ubuntu1~18.04",
                                      "fixed": "11.0.18+10-0ubuntu1~18.04.1"}]


def test_several_packages_in_one_output():
    output = ("Remote package installed : nss-3.13.3-6.el6\nShould be : nss-3.13.6-2.el6_3\n\n"
              "Remote package installed : nspr-4.9-1.el6\nShould be : nspr-4.9.2-0.el6_3\n")
    assert [p["name"] for p in packages_from(output)] == ["nss", "nspr"]


def test_a_host_in_two_exports_keeps_the_newer_block_and_both_findings(tmp_path):
    older = _file(tmp_path, [_host("web1", [OPENSSL], fqdn="web1.example.com", end="1794449731",
                                   credentialed="false")], name="a.nessus")
    ssh = _item("70658", "2", port="22", children="<cvss_base_score>2.6</cvss_base_score>")
    newer = _file(tmp_path, [_host("web1", [ssh], fqdn="web1.example.com")], name="b.nessus", report="Weekly SSH")
    document = parse_exports([newer, older])
    assert document.hosts["web1.example.com"]["authenticated"] is True
    assert {f["check_id"] for f in document.findings} == {"nessus:166000", "nessus:70658"}
    assert document.run_id == "Weekly SSH, Weekly Linux"


def test_a_newer_run_of_the_same_scan_supersedes_the_older_findings(tmp_path):
    """Last week's export left in the drop folder must not keep a patched finding alive."""
    older = _file(tmp_path, [_host("web1", [OPENSSL], fqdn="web1.example.com", end="1794449731")],
                  name="a.nessus")
    ssh = _item("70658", "2", port="22", children="<cvss_base_score>2.6</cvss_base_score>")
    newer = _file(tmp_path, [_host("web1", [ssh], fqdn="web1.example.com")], name="b.nessus")
    document = parse_exports([older, newer])
    assert {f["check_id"] for f in document.findings} == {"nessus:70658"}


def test_cpe_2_3_os_tags_are_read(tmp_path):
    host = _host("web1", [], fqdn="web1.example.com", cpe="cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*")
    document = parse_exports([_file(tmp_path, [host])])
    assert document.hosts["web1.example.com"]["os_family"] == "ubuntu"


def test_an_unreadable_file_does_not_lose_the_others(tmp_path, caplog):
    bad = tmp_path / "bad.nessus"
    bad.write_text("<NessusClientData_v2><Report")
    good = _file(tmp_path, [_host("web1", [OPENSSL], fqdn="web1.example.com")])
    with caplog.at_level("ERROR", logger="transformer"):
        document = parse_exports([str(bad), good])
    assert "web1.example.com" in document.hosts
    assert "not a readable .nessus file" in caplog.text
