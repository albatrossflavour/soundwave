"""Run from files/python with: python3 -m pytest tests -q

Fixtures follow the shape of public XML Export 2.0 files rather than a real
export from this estate, which nobody has yet. When one exists it belongs here.
"""

import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cassettes.rapid7 import cvss_of, os_identity, parse_exports  # noqa: E402
from lib import findings as F  # noqa: E402

SCANS = ('<scans><scan id="7" name="Weekly" startTime="20261113T020000000" endTime="20261113T021531312" status="finished"/>'
         '<scan id="8" name="Adhoc" startTime="20261112T020000000" endTime="20261112T030000000" status="finished"/></scans>')

UBUNTU_OS = '<fingerprints><os certainty="0.90" vendor="Ubuntu" family="Linux" product="Linux" version="22.04"/></fingerprints>'


def _node(address, *, names=("web1.example.com",), status="alive", os=UBUNTU_OS, tests="", endpoints=""):
    name_xml = "".join(f"<name>{n}</name>" for n in names)
    return (f'<node address="{address}" status="{status}" device-id="12"><names>{name_xml}</names>{os}'
            f"<tests>{tests}</tests><endpoints>{endpoints}</endpoints></node>")


def _test(vuln, status="vulnerable-version", scan="7", text="Vulnerable software installed: OpenSSH 8.9"):
    return f'<test id="{vuln}" status="{status}" scan-id="{scan}"><Paragraph><Paragraph>{text}</Paragraph></Paragraph></test>'


def _endpoint(port, tests, protocol="tcp"):
    return (f'<endpoint protocol="{protocol}" port="{port}" status="open"><services><service name="SSH">'
            f"<tests>{tests}</tests></service></services></endpoint>")


SSH_DEF = ('<vulnerability id="ssh-cve-2023-48795" title="SSH Terrapin prefix truncation" severity="5" '
           'cvssScore="5.9" cvssVector="(AV:N/AC:H/Au:N/C:N/I:P/A:N)">'
           "<description><ContainerBlockElement><Paragraph>The SSH transport protocol allows a\n   prefix truncation."
           "</Paragraph></ContainerBlockElement></description>"
           '<references><reference source="CVE">CVE-2023-48795</reference>'
           '<reference source="URL">https://terrapin-attack.com</reference></references>'
           "<solution><ContainerBlockElement><UnorderedList><ListItem>Upgrade OpenSSH.</ListItem></UnorderedList>"
           "</ContainerBlockElement></solution></vulnerability>")

WIN_DEF = ('<vulnerability id="msft-cve-2026-0001" title="Windows kernel elevation" severity="8" cvssScore="7.2" '
           'cvssVector="(AV:L/AC:L/Au:N/C:C/I:C/A:C)"><references><reference source="CVE">CVE-2026-0001</reference>'
           '<reference source="MSKB">KB5042322</reference></references></vulnerability>')


def _file(tmp_path, nodes, definitions=(SSH_DEF,), name="export.xml"):
    path = tmp_path / name
    path.write_text(f'<?xml version="1.0"?><NexposeReport version="2.0">{SCANS}<nodes>{"".join(nodes)}</nodes>'
                    f'<VulnerabilityDefinitions>{"".join(definitions)}</VulnerabilityDefinitions></NexposeReport>')
    return str(path)


def _doc(tmp_path, nodes, definitions=(SSH_DEF,), mapping=None, timezone="UTC"):
    return parse_exports([_file(tmp_path, nodes, definitions)], mapping, {"timezone": timezone})


def test_host_block(tmp_path):
    document = _doc(tmp_path, [_node("192.0.2.5")])
    host = document.hosts["web1.example.com"]
    assert host["ipaddress"] == "192.0.2.5"
    assert (host["os_family"], host["os_release"]) == ("ubuntu", "22.04")
    assert host["collection"] == "rapid7"
    assert host["status"] == "scanned"
    assert host["authenticated"] is False


def test_scan_window_comes_from_the_scan_its_tests_name(tmp_path):
    ssh = _endpoint(22, _test("ssh-cve-2023-48795", scan="7"))
    host = _doc(tmp_path, [_node("192.0.2.5", endpoints=ssh)]).hosts["web1.example.com"]
    assert host["scan_end"] == "2026-11-13T02:15:31+00:00"
    assert host["scan_start"] == "2026-11-13T02:00:00+00:00"


def test_times_are_read_in_the_report_timezone(tmp_path):
    """The export carries no zone. Melbourne is +11:00 in November."""
    ssh = _endpoint(22, _test("ssh-cve-2023-48795"))
    host = _doc(tmp_path, [_node("192.0.2.5", endpoints=ssh)], timezone="Australia/Melbourne").hosts["web1.example.com"]
    assert host["scan_end"] == "2026-11-13T02:15:31+11:00"
    assert F.iso_to_epoch(host["scan_end"]) == F.iso_to_epoch("2026-11-12T15:15:31Z")


def test_an_unknown_timezone_writes_nothing(tmp_path, caplog):
    with caplog.at_level("ERROR", logger="transformer"):
        assert _doc(tmp_path, [_node("192.0.2.5")], timezone="Mars/Olympus") is None
    assert "unknown timezone" in caplog.text


def test_endpoint_finding(tmp_path):
    ssh = _endpoint(22, _test("ssh-cve-2023-48795"))
    document = _doc(tmp_path, [_node("192.0.2.5", endpoints=ssh)])
    check = document.checks["rapid7:ssh-cve-2023-48795"]
    assert check["name"] == "SSH Terrapin prefix truncation"
    assert check["summary"] == "The SSH transport protocol allows a prefix truncation."
    assert check["solution"] == "Upgrade OpenSSH."
    assert (check["cvss_score"], check["cvss_version"]) == (5.9, "2.0")
    assert check["cvss_vector"] == "AV:N/AC:H/Au:N/C:N/I:P/A:N"
    assert check["severity"] == "medium"
    assert check["cves"] == ["CVE-2023-48795"]
    assert check["references"] == ["https://terrapin-attack.com"]
    assert check["fix_type"] is None
    (finding,) = document.findings
    assert finding["port"] == "22/tcp"
    assert finding["confidence"] == 80
    assert finding["state"] == ""
    assert finding["evidence"] == "vulnerable-version: Vulnerable software installed: OpenSSH 8.9"


def test_node_level_finding_has_no_port(tmp_path):
    document = _doc(tmp_path, [_node("192.0.2.5", tests=_test("ssh-cve-2023-48795"))])
    assert document.findings[0]["port"] is None


def test_only_vulnerable_statuses_are_findings(tmp_path):
    tests = (_test("ssh-cve-2023-48795", status="not-vulnerable")
             + _test("ssh-cve-2023-48795", status="pass"))
    assert _doc(tmp_path, [_node("192.0.2.5", tests=tests)]).findings == []


def test_ids_join_whatever_their_case(tmp_path):
    tests = _test("SSH-CVE-2023-48795")
    document = _doc(tmp_path, [_node("192.0.2.5", tests=tests)])
    assert [f["check_id"] for f in document.findings] == ["rapid7:ssh-cve-2023-48795"]


def test_a_finding_with_no_definition_is_skipped_and_counted(tmp_path, caplog):
    with caplog.at_level("WARNING", logger="transformer"):
        document = _doc(tmp_path, [_node("192.0.2.5", tests=_test("nobody-knows"))])
    assert document.findings == []
    assert "1 finding(s) name a vulnerability the export does not define" in caplog.text


def test_kbs_are_bare_numbers(tmp_path):
    win_os = '<fingerprints><os certainty="1.00" vendor="Microsoft" family="Windows" product="Windows Server 2022"/></fingerprints>'
    node = _node("192.0.2.9", names=("win1.example.com",), os=win_os, tests=_test("msft-cve-2026-0001"))
    document = _doc(tmp_path, [node], definitions=(WIN_DEF,))
    assert document.findings[0]["kbs"] == ["5042322"]
    host = document.hosts["win1.example.com"]
    assert (host["os_family"], host["os_release"]) == ("windows", "Windows Server 2022")


def test_a_dead_node_is_unreachable(tmp_path):
    host = _doc(tmp_path, [_node("192.0.2.5", status="dead")]).hosts["web1.example.com"]
    assert host["status"] == "unreachable"


def test_host_map_and_unmapped(tmp_path):
    nodes = [_node("192.0.2.5", names=("web1.lan",)), _node("192.0.2.6", names=())]
    document = _doc(tmp_path, nodes, mapping={"192.0.2.5": "web1.example.com"})
    assert set(document.hosts) == {"web1.example.com", "192.0.2.6"}
    assert document.unmapped == [{"identifier": "192.0.2.6", "collection": "rapid7", "sent_as": "192.0.2.6"}]


def test_os_identity():
    def fp(**attrs):
        return ET.Element("os", {k: v for k, v in attrs.items()})
    assert os_identity(fp(vendor="Red Hat", product="Enterprise Linux", version="9.4")) == ("redhat", "9.4")
    assert os_identity(fp(vendor="Oracle", product="Linux", version="9.8")) == ("oracle", "9.8")
    assert os_identity(fp(vendor="Oracle", product="Solaris", version="11")) == ("", "")
    assert os_identity(fp(vendor="Ubuntu", product="Linux", version="24.04", cpe="cpe:/o:canonical:ubuntu_linux:24.04")) == ("ubuntu", "24.04")
    assert os_identity(None) == ("", "")


def test_highest_certainty_fingerprint_wins(tmp_path):
    os_xml = ('<fingerprints><os certainty="0.50" vendor="Debian" product="Linux" version="12"/>'
              '<os certainty="0.95" vendor="Ubuntu" product="Linux" version="24.04"/></fingerprints>')
    host = _doc(tmp_path, [_node("192.0.2.5", os=os_xml)]).hosts["web1.example.com"]
    assert host["os_family"] == "ubuntu"


def test_cvss_v3_is_preferred_when_present():
    vuln = ET.Element("vulnerability", {"cvssScore": "5.0", "cvssVector": "(AV:N)", "cvss3Score": "9.8",
                                        "cvss3Vector": "CVSS:3.1/AV:N/AC:L"})
    assert cvss_of(vuln) == (9.8, "3.1", "CVSS:3.1/AV:N/AC:L")
    assert cvss_of(ET.Element("vulnerability")) == (0.0, "", "")


def test_confidence_follows_the_detection_method(tmp_path):
    doc = _doc(tmp_path, [_node(f"192.0.2.{i}", names=(f"h{i}",), tests=_test("ssh-cve-2023-48795", status=s))
                          for i, s in enumerate(("vulnerable-exploited", "vulnerable-version",
                                                 "vulnerable-potential", "vulnerable-something-new"))])
    by_host = {f["certname"]: f["confidence"] for f in doc.findings}
    assert by_host == {"h0": 100, "h1": 80, "h2": 30, "h3": None}
    assert doc.to_dict()["cassette"]["confidence_scale"]["kind"] == "qod-equivalent"


def test_potential_findings_stay_out_of_vr(tmp_path):
    """Below the floor, as Greenbone's QoD 30 tail is. They stay in the file."""
    nodes = [_node("192.0.2.5", names=("sure",), tests=_test("ssh-cve-2023-48795", status="vulnerable-version")),
             _node("192.0.2.6", names=("maybe",), tests=_test("ssh-cve-2023-48795", status="vulnerable-potential"))]
    data = _doc(tmp_path, nodes).to_dict()
    records, _ = F.to_vr(data["hosts"], data["checks"], data["findings"])
    vulns = {r["hostname"]: [v["name"] for v in r["vulnerabilities"]] for r in records}
    assert vulns["sure"] == ["SSH Terrapin prefix truncation"]
    assert vulns["maybe"] == []
    assert len(data["findings"]) == 2


def test_windows_release_drops_the_edition():
    """Rendered as vuls and openvas render it, or one host is described two ways."""
    def fp(product):
        return ET.Element("os", {"vendor": "Microsoft", "product": product})
    assert os_identity(fp("Windows Server 2019 Standard Edition")) == ("windows", "Windows Server 2019")
    assert os_identity(fp("Windows Server 2008 R2, Enterprise Edition")) == ("windows", "Windows Server 2008 R2")


def test_a_newer_export_of_a_host_supersedes_the_older_findings(tmp_path):
    """Last week's export left in the drop folder must not keep a patched finding alive."""
    older = _file(tmp_path, [_node("192.0.2.5", tests=_test("ssh-cve-2023-48795"))], name="old.xml")
    newer = tmp_path / "new.xml"
    newer.write_text((tmp_path / "old.xml").read_text().replace("20261113", "20261120").replace(
        '<test id="ssh-cve-2023-48795" status="vulnerable-version"',
        '<test id="ssh-cve-2023-48795" status="not-vulnerable"'))
    document = parse_exports([older, str(newer)], None, {"timezone": "UTC"})
    assert document.hosts["web1.example.com"]["scan_end"].startswith("2026-11-20")
    assert document.findings == []
