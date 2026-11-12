"""Run from files/python with: python3 -m pytest tests -q"""

import os
import sys
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cassettes.openvas import (  # noqa: E402
    CASSETTE,
    _advisory_title,
    _os_identity,
    _package_fixes,
    _parse_tags,
    _unwrap,
    parse_report,
)

OID = "1.3.6.1.4.1.25623.1.0.117839"
SCAN_END = "2026-09-15T05:09:49Z"


def _xml_result(rid, ip, oid, severity, *, name="Check", hostname="", port=None,
                qod=None, description="", tags="", solution=None, solution_type=None,
                cvss_base=None, cves=(), urls=(), legacy_cves=()):
    host = f"<host>{ip}" + (f"<hostname>{escape(hostname)}</hostname>" if hostname else "") + "</host>"
    parts = [
        f"<name>{escape(name)}</name>",
        host,
        f"<severity>{severity}</severity>",
        f"<description>{escape(description)}</description>",
    ]
    if port is not None:
        parts.append(f"<port>{escape(port)}</port>")
    if qod is not None:
        parts.append(f"<qod><value>{qod}</value><type>remote_banner</type></qod>")

    nvt = [f"<name>{escape(name)}</name>"]
    if cvss_base is not None:
        nvt.append(f"<cvss_base>{cvss_base}</cvss_base>")
    nvt.append(f"<tags>{escape(tags)}</tags>")
    if solution is not None:
        attr = f" type={quoteattr(solution_type)}" if solution_type else ""
        nvt.append(f"<solution{attr}>{escape(solution)}</solution>")
    if cves or urls:
        refs = "".join(f'<ref type="cve" id={quoteattr(c)}/>' for c in cves)
        refs += "".join(f'<ref type="url" id={quoteattr(u)}/>' for u in urls)
        nvt.append(f"<refs>{refs}</refs>")
    nvt += [f"<cve>{escape(c)}</cve>" for c in legacy_cves]

    return f'<result id="{rid}">' + "".join(parts) + f'<nvt oid="{oid}">' + "".join(nvt) + "</nvt></result>"


def _xml_host(ip, *, start="", end="", hostname="", auth=None, os_cpe=None):
    details = ""
    if auth:
        details += f"<detail><name>{auth}</name><value>1</value></detail>"
    if hostname:
        details += f"<detail><name>hostname</name><value>{escape(hostname)}</value></detail>"
    if os_cpe:
        details += f"<detail><name>best_os_cpe</name><value>{escape(os_cpe)}</value></detail>"
    return f"<host><ip>{ip}</ip><start>{start}</start><end>{end}</end>{details}</host>"


def _xml_errors(*pairs):
    if not pairs:
        return ""
    body = "".join(
        f"<error><host>{ip}</host><description>{escape(text)}</description></error>" for ip, text in pairs
    )
    return f"<errors><count>{len(pairs)}</count>{body}</errors>"


def _report_file(tmp_path, *, hosts="", results="", errors="", scan_end=SCAN_END):
    xml = (
        '<get_reports_response status="200"><report id="r"><report id="r">'
        f"<scan_end>{scan_end}</scan_end>{hosts}{errors}"
        f"<results>{results}</results></report></report></get_reports_response>"
    )
    path = tmp_path / "report.xml"
    path.write_text(xml, encoding="utf-8")
    return str(path)


def _one(tmp_path, result_kwargs=None, *, host_kwargs=None, mapping=None, errors=""):
    """A report with one host block and one result on it."""
    host_kwargs = {"start": "2026-09-15T05:00:00Z", "end": "2026-09-15T05:09:49Z", **(host_kwargs or {})}
    result_kwargs = {"severity": 7.5, **(result_kwargs or {})}
    ip = host_kwargs.pop("ip", "192.0.2.13")
    path = _report_file(
        tmp_path,
        hosts=_xml_host(ip, **host_kwargs),
        results=_xml_result("1", ip, OID, **result_kwargs),
        errors=errors,
    )
    return parse_report(path, mapping)


MAPPED = {"192.0.2.13": "dashboard.example.com"}


# The fields the direct-to-VR parser threw away, which are the whole reason the
# findings file exists.

def test_check_id_is_the_nvt_oid(tmp_path):
    document = _one(tmp_path, mapping=MAPPED)
    assert list(document.checks) == [f"greenbone:{OID}"]
    assert document.findings[0]["check_id"] == f"greenbone:{OID}"


def test_result_without_an_oid_is_skipped(tmp_path):
    path = _report_file(
        tmp_path,
        hosts=_xml_host("192.0.2.13"),
        results=_xml_result("1", "192.0.2.13", "", 7.5),
    )
    document = parse_report(path, MAPPED)
    assert document.checks == {}
    assert document.findings == []


@pytest.mark.parametrize("spelling,expected", [
    ("VendorFix", "vendor-fix"),
    ("Mitigation", "mitigation"),
    ("Workaround", "workaround"),
    ("NoneAvailable", "none-available"),
    ("None available", "none-available"),
    ("WillNotFix", "will-not-fix"),
    ("Debug", ""),
])
def test_solution_type_becomes_fix_type(tmp_path, spelling, expected):
    document = _one(tmp_path, {"solution": "Do the thing.", "solution_type": spelling}, mapping=MAPPED)
    assert document.checks[f"greenbone:{OID}"]["fix_type"] == expected


def test_solution_type_falls_back_to_the_tag(tmp_path):
    # Older feed entries carry the type only in the pipe-delimited tags string.
    document = _one(
        tmp_path,
        {"solution": "Do the thing.", "tags": "solution_type=Mitigation"},
        mapping=MAPPED,
    )
    assert document.checks[f"greenbone:{OID}"]["fix_type"] == "mitigation"


# Greenbone's QoD runs 0-100, and openvas says so.
def test_the_cassette_declares_qod_on_zero_to_a_hundred(tmp_path):
    document = _one(tmp_path, mapping=MAPPED)
    assert document.to_dict()["cassette"]["confidence_scale"] == {"min": 0, "max": 100, "kind": "qod"}


def test_qod_becomes_confidence(tmp_path):
    document = _one(tmp_path, {"qod": 30}, mapping=MAPPED)
    assert document.findings[0]["confidence"] == 30


def test_missing_qod_is_null_not_zero(tmp_path):
    """A missing QoD is the scanner not saying, which is not a QoD of nothing.

    Scored zero it reads as a finding the scanner is certain is not there, and
    Soundwave's confidence floor drops it as low quality rather than saying the
    row was malformed.
    """
    document = _one(tmp_path, mapping=MAPPED)
    assert document.findings[0]["confidence"] is None


def test_port_and_evidence_are_carried(tmp_path):
    evidence = "The remote SSH server supports the following DHE KEX algorithm(s):\n\ndiffie-hellman-group14-sha256"
    document = _one(tmp_path, {"port": "22/tcp", "description": evidence}, mapping=MAPPED)
    finding = document.findings[0]
    assert finding["port"] == "22/tcp"
    assert finding["evidence"] == evidence


def test_absent_port_is_null(tmp_path):
    document = _one(tmp_path, mapping=MAPPED)
    assert document.findings[0]["port"] is None


# Host blocks. Without them a clean host and an unreachable one read the same.

def test_host_block_per_address_with_ssh_auth(tmp_path):
    document = _one(tmp_path, host_kwargs={"auth": "Auth-SSH-Success"}, mapping=MAPPED)
    host = document.hosts["dashboard.example.com"]
    assert host["authenticated"] is True
    assert host["ipaddress"] == "192.0.2.13"
    assert host["collection"] == "gmp"
    assert host["status"] == "scanned"


def test_smb_auth_also_counts(tmp_path):
    document = _one(tmp_path, host_kwargs={"auth": "Auth-SMB-Success"}, mapping=MAPPED)
    assert document.hosts["dashboard.example.com"]["authenticated"] is True


def test_unauthenticated_scan_still_completes(tmp_path):
    document = _one(tmp_path, mapping=MAPPED)
    assert document.hosts["dashboard.example.com"]["authenticated"] is False


def test_scan_window_comes_from_the_host_block(tmp_path):
    document = _one(tmp_path, mapping=MAPPED)
    host = document.hosts["dashboard.example.com"]
    assert host["scan_start"] == "2026-09-15T05:00:00Z"
    assert host["scan_end"] == "2026-09-15T05:09:49Z"
    assert document.findings[0]["detected_at"] == "2026-09-15T05:09:49Z"


def test_host_with_no_findings_still_gets_a_block(tmp_path):
    path = _report_file(
        tmp_path,
        hosts=_xml_host("192.0.2.13", end=SCAN_END) + _xml_host("192.0.2.99", end=SCAN_END),
        results=_xml_result("1", "192.0.2.13", OID, 7.5),
    )
    document = parse_report(path, {"192.0.2.13": "dashboard.lab", "192.0.2.99": "clean.lab"})
    assert sorted(document.hosts) == ["clean.lab", "dashboard.lab"]
    assert [f["certname"] for f in document.findings] == ["dashboard.lab"]
    assert document.hosts["clean.lab"]["status"] == "scanned"


def test_host_with_a_scan_error_is_partial(tmp_path):
    document = _one(
        tmp_path,
        mapping=MAPPED,
        errors=_xml_errors(("192.0.2.13", "Host process failure")),
    )
    host = document.hosts["dashboard.example.com"]
    assert host["status"] == "partial"
    assert host["errors"] == ["Host process failure"]


def test_unmapped_address_keeps_its_reverse_dns_name_and_is_recorded(tmp_path):
    document = _one(tmp_path, host_kwargs={"hostname": "old-dns-name.example.com"}, mapping={})
    assert "old-dns-name.example.com" in document.hosts
    assert document.unmapped == [
        {"identifier": "192.0.2.13", "collection": "gmp", "sent_as": "old-dns-name.example.com"}
    ]


def test_unmapped_address_without_reverse_dns_falls_back_to_the_address(tmp_path):
    document = _one(tmp_path, mapping={})
    assert "192.0.2.13" in document.hosts
    assert document.unmapped[0]["sent_as"] == "192.0.2.13"


def test_mapped_address_is_not_unmapped(tmp_path):
    document = _one(tmp_path, host_kwargs={"hostname": "old-dns-name.example.com"}, mapping=MAPPED)
    assert list(document.hosts) == ["dashboard.example.com"]
    assert document.unmapped == []


def test_result_for_an_address_with_no_host_block_still_lands(tmp_path):
    # gvmd has produced results for a host it left out of the host list; the
    # finding is real and must not be dropped for want of a block to hang it on.
    path = _report_file(tmp_path, results=_xml_result("1", "192.0.2.13", OID, 7.5, hostname="dashboard.lab"))
    document = parse_report(path, None, scan_end_fallback=SCAN_END)
    assert document.hosts["dashboard.lab"]["scan_end"] == SCAN_END
    assert document.findings[0]["certname"] == "dashboard.lab"


# Severity, scores and references.

@pytest.mark.parametrize("score,expected", [
    (9.8, "critical"), (9.0, "critical"), (7.5, "high"), (7.0, "high"),
    (4.3, "medium"), (4.0, "medium"), (2.6, "low"), (0.1, "low"),
])
def test_severity_buckets(tmp_path, score, expected):
    document = _one(tmp_path, {"severity": score}, mapping=MAPPED)
    assert document.checks[f"greenbone:{OID}"]["severity"] == expected


def test_log_rows_are_skipped(tmp_path):
    document = _one(tmp_path, {"severity": 0.0}, mapping=MAPPED)
    assert document.findings == []
    # The host block survives: the scan reached it, it simply found nothing.
    assert "dashboard.example.com" in document.hosts


def test_cvss_base_wins_over_the_result_severity(tmp_path):
    # apply_overrides can move a result's severity; the check keeps the NVT's
    # own base score so the number means the same thing on every host.
    document = _one(tmp_path, {"severity": 5.0, "cvss_base": 7.5}, mapping=MAPPED)
    assert document.checks[f"greenbone:{OID}"]["cvss_score"] == 7.5


def test_cves_and_urls_come_from_refs(tmp_path):
    document = _one(
        tmp_path,
        {"cves": ["CVE-2026-2", "CVE-2026-1", "CVE-2026-1"], "urls": ["https://b", "https://a"]},
        mapping=MAPPED,
    )
    check = document.checks[f"greenbone:{OID}"]
    assert check["cves"] == ["CVE-2026-1", "CVE-2026-2"]
    assert check["references"] == ["https://a", "https://b"]


def test_legacy_cve_children_are_read(tmp_path):
    document = _one(tmp_path, {"legacy_cves": ["CVE-2026-9", "NOCVE"]}, mapping=MAPPED)
    assert document.checks[f"greenbone:{OID}"]["cves"] == ["CVE-2026-9"]


def test_cvss_version_from_the_vector(tmp_path):
    v3 = _one(tmp_path, {"tags": "cvss_base_vector=CVSS:3.1/AV:N/AC:L"}, mapping=MAPPED)
    assert v3.checks[f"greenbone:{OID}"]["cvss_version"] == "3.0"
    v2 = _one(tmp_path, {"tags": "cvss_base_vector=AV:L/AC:L/Au:N"}, mapping=MAPPED)
    assert v2.checks[f"greenbone:{OID}"]["cvss_version"] == "2.0"


def test_malformed_result_does_not_lose_the_report(tmp_path):
    # A severity that will not parse used to take the whole report with it.
    broken = f'<result id="1"><host>192.0.2.13</host><severity>NaN-ish</severity><nvt oid="{OID}"/></result>'
    path = _report_file(
        tmp_path,
        hosts=_xml_host("192.0.2.13", end=SCAN_END),
        results=broken + _xml_result("2", "192.0.2.13", "1.2.3", 7.5),
    )
    document = parse_report(path, MAPPED)
    assert list(document.checks) == ["greenbone:1.2.3"]


def test_no_report_element(tmp_path):
    path = tmp_path / "empty.xml"
    path.write_text("<get_reports_response status='400'/>", encoding="utf-8")
    assert parse_report(str(path), None) is None


# Package parsing, ported from the direct-to-VR parser. The Windows
# descriptions are copied from the lab's 2026-09-15 scan; the package ones are
# built from openvasd's message strings with fixed versions from the notus feed.

FONTTOOLS_ESM = (
    "\nVulnerable package:   python3-fonttools\n"
    "Installed version:    python3-fonttools-4.46.0-1build2\n"
    "Fixed version:      >=python3-fonttools-4.46.0-1ubuntu0.1~esm1\n"
)
IEXPRESS_WORKAROUND = (
    "Fixed version:     Workaround\n"
    "File checked:      C:\\Windows\\system32\\IEXPRESS.EXE\n"
    "File version:      11.0.20348.1\n"
)
SNIPPING_TOOL = (
    "Installed version: 10.0.20348.2849\n"
    "Fixed version:     11.2302.20.0\n"
    "Installation\n"
    "path / port:       C:\\Windows\\System32\n"
)
JQUERY = "Installed version: 1.8.3\nFixed version:     1.9.0\nInstallation\npath / port:       /usr/share/javascript/jquery/\n"


def _result_element(description):
    result = ET.Element("result")
    ET.SubElement(result, "description").text = description
    return result


def _names(description):
    return [fix.name for fix in _package_fixes(_result_element(description))]


def test_package_name_comes_from_the_vulnerable_package_line():
    assert _names(FONTTOOLS_ESM) == ["python3-fonttools"]


@pytest.mark.parametrize("description", [IEXPRESS_WORKAROUND, SNIPPING_TOOL, JQUERY])
def test_version_checks_are_not_packages(description):
    # Reading names out of Fixed version sent PE packages called "Workaround",
    # "1.9.0" and "11.2302.20.0".
    assert _names(description) == []


def test_several_packages_keep_order_and_hyphens():
    description = (
        "Vulnerable package:   libcurl3-gnutls\nInstalled version:    libcurl3-gnutls-7.81.0-1ubuntu1.15\n"
        "Fixed version:      >=libcurl3-gnutls-7.81.0-1ubuntu1.16\n\n"
        "Vulnerable package:   curl\nInstalled version:    curl-7.81.0-1ubuntu1.15\n"
        "Fixed version:      >=curl-7.81.0-1ubuntu1.16\n"
    )
    assert _names(description) == ["libcurl3-gnutls", "curl"]


def test_repeated_package_is_listed_once():
    assert _names(FONTTOOLS_ESM + FONTTOOLS_ESM) == ["python3-fonttools"]


def test_range_keeps_both_fixed_versions_and_upgrades_to_the_upper_bound():
    description = (
        "Vulnerable package:   openssl\nInstalled version:    openssl-3.0.2-0ubuntu1.10\n"
        "Fixed version:      < openssl-3.0.2-0ubuntu1.9\nFixed version:      >=openssl-3.0.2-0ubuntu1.18\n"
    )
    (fix,) = _package_fixes(_result_element(description))
    assert fix.fixed_versions == ["< openssl-3.0.2-0ubuntu1.9", ">=openssl-3.0.2-0ubuntu1.18"]
    assert fix.best_fixed() == "openssl-3.0.2-0ubuntu1.18"
    assert fix.installed == "openssl-3.0.2-0ubuntu1.10"


def test_no_description():
    assert _package_fixes(ET.Element("result")) == []
    assert _package_fixes(None) == []


def _fix(name, fixed):
    description = f"Vulnerable package:   {name}\nInstalled version:    {name}-0\nFixed version:      >={fixed}\n"
    (fix,) = _package_fixes(_result_element(description))
    return fix


@pytest.mark.parametrize("fixed", [
    "4.46.0-1ubuntu0.1~esm1",
    "1.8.9p5-1ubuntu1.5+esm1",
    "7:6.1.1-3ubuntu5+esm10",
    "2.0.1ubuntu0.20.04.2esm2",
    "1.9.14-1ubuntu1+esm1~22.04.1",
])
def test_esm_spellings_from_the_feed(fixed):
    assert _fix("pkg", fixed).pro_channel() == "ESM"


def test_esm_with_name_prefix():
    assert _fix("python3-fonttools", "python3-fonttools-4.46.0-1ubuntu0.1~esm1").pro_channel() == "ESM"


def test_fips():
    assert _fix("linux-image-5.4.0-1145-gcp-fips", "5.4.0-1145.154+fips1").pro_channel() == "FIPS"


@pytest.mark.parametrize("name,fixed", [
    ("curl", "curl-7.81.0-1ubuntu1.16"),
    ("openssl", "3.0.17-1~deb12u2"),
    # "fips" in the name, not the version.
    ("linux-image-5.4.0-1145-gcp-fips", "linux-image-5.4.0-1145-gcp-fips-5.4.0-1145.154"),
    ("openssl-fips1", "openssl-fips1-3.0.2-0ubuntu1.18"),
])
def test_standard_archive(name, fixed):
    assert _fix(name, fixed).pro_channel() is None


# state, which replaces the sentence the old parser glued onto the solution.

def test_state_is_pro_only_for_an_esm_fix(tmp_path):
    document = _one(tmp_path, {"description": FONTTOOLS_ESM}, mapping=MAPPED)
    finding = document.findings[0]
    assert finding["state"] == "pro-only"
    assert finding["packages"] == [{
        "name": "python3-fonttools",
        "arch": "",
        "installed": "python3-fonttools-4.46.0-1build2",
        "fixed": "python3-fonttools-4.46.0-1ubuntu0.1~esm1",
    }]


def test_state_is_fixable_for_a_standard_archive_fix(tmp_path):
    description = (
        "Vulnerable package:   curl\nInstalled version:    curl-7.81.0-1ubuntu1.15\n"
        "Fixed version:      >=curl-7.81.0-1ubuntu1.16\n"
    )
    document = _one(tmp_path, {"description": description}, mapping=MAPPED)
    assert document.findings[0]["state"] == "fixable"


def test_state_is_unfixed_when_no_fixed_version_is_given(tmp_path):
    description = "Vulnerable package:   curl\nInstalled version:    curl-7.81.0-1ubuntu1.15\n"
    document = _one(tmp_path, {"description": description}, mapping=MAPPED)
    assert document.findings[0]["state"] == "unfixed"


def test_state_is_empty_for_a_finding_that_is_not_about_a_package(tmp_path):
    document = _one(tmp_path, {"description": "The remote host responded to an ICMP timestamp request."}, mapping=MAPPED)
    assert document.findings[0]["state"] == ""
    assert document.findings[0]["packages"] == []


# Advisory naming and tag parsing, ported unchanged.

def test_advisory_title_single_package():
    tags = {"affected": "'fonttools' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10."}
    assert _advisory_title("Ubuntu: Security Advisory (USN-7917-1)", tags) == "fonttools: Ubuntu USN-7917-1"


def test_advisory_title_debian():
    tags = {"affected": "'xorg-server' package(s) on Debian 13."}
    assert _advisory_title("Debian: Security Advisory (DSA-6497-1)", tags) == "xorg-server: Debian DSA-6497-1"


def test_advisory_title_several_packages():
    tags = {"affected": "'dotnet8, dotnet10' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 26.04."}
    assert _advisory_title("Ubuntu: Security Advisory (USN-8740-1)", tags) == "dotnet8, dotnet10: Ubuntu USN-8740-1"


def test_advisory_title_long_package_list_is_cut():
    tags = {"affected": "'linux, linux-aws, linux-aws-7.0, linux-gcp, linux-gke, linux-hwe-7.0, linux-realtime' package(s) on Ubuntu 24.04."}
    assert _advisory_title("Ubuntu: Security Advisory (USN-8726-1)", tags) == \
        "linux, linux-aws, linux-aws-7.0 +4 more: Ubuntu USN-8726-1"


def test_advisory_title_other_distro_spellings():
    tags = {"affected": "'kernel' package(s) on Huawei EulerOS V2.0SP10."}
    assert _advisory_title("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1234)", tags) == \
        "kernel: Huawei EulerOS EulerOS-SA-2025-1234"
    tags = {"affected": "'curl' package(s) on openSUSE Leap 15.6."}
    assert _advisory_title("openSUSE Security Advisory (SUSE-SU-2026:1234-1)", tags) == \
        "curl: openSUSE SUSE-SU-2026:1234-1"


@pytest.mark.parametrize("name,tags", [
    ("Windows IExpress Untrusted Search Path Vulnerability", {}),
    ("TCP Timestamps Information Disclosure", {"affected": "All systems"}),
    # An advisory without the tag cannot be renamed consistently across hosts.
    ("Ubuntu: Security Advisory (USN-7917-1)", {}),
])
def test_everything_else_keeps_its_name(name, tags):
    assert _advisory_title(name, tags) == name


def test_pipe_inside_a_tag_value():
    nvt = ET.fromstring("<nvt><tags>summary=s|insight=use a | b to pipe|solution_type=VendorFix</tags></nvt>")
    assert _parse_tags(nvt) == {"summary": "s", "insight": "use a | b to pipe", "solution_type": "VendorFix"}


def test_unwrap_keeps_paragraphs():
    text = "It was discovered that pip incorrectly handled TLS\ncertificate verification.\n\nIt was discovered that\nurllib3 did not limit."
    assert _unwrap(text) == (
        "It was discovered that pip incorrectly handled TLS certificate verification.\n\n"
        "It was discovered that urllib3 did not limit."
    )


def test_advisory_summary_comes_from_insight(tmp_path):
    # The advisory's own summary only restates its name, so the check would
    # otherwise say nothing a reader could act on.
    tags = (
        "summary=The remote host is missing an update for the 'fonttools' package(s) announced via the USN-7917-1 advisory."
        "|insight=It was discovered that fontTools was vulnerable to\npath traversal attacks. (CVE-2025-66034)"
        "|affected='fonttools' package(s) on Ubuntu 22.04, Ubuntu 24.04."
        "|solution_type=VendorFix"
    )
    document = _one(
        tmp_path,
        {"name": "Ubuntu: Security Advisory (USN-7917-1)", "severity": 9.8,
         "description": FONTTOOLS_ESM, "tags": tags, "solution": "Please install the updated package(s)."},
        mapping=MAPPED,
    )
    check = document.checks[f"greenbone:{OID}"]
    assert check["name"] == "fonttools: Ubuntu USN-7917-1"
    assert check["summary"] == "It was discovered that fontTools was vulnerable to path traversal attacks. (CVE-2025-66034)"
    assert check["fix_type"] == "vendor-fix"
    assert check["solution"] == "Please install the updated package(s)."

# os_family and os_release, from Greenbone's best_os_cpe. Every CPE below was
# taken from a real report on the lab, 2026-09-17.

@pytest.mark.parametrize("cpe,expected", [
    ("cpe:/o:canonical:ubuntu_linux:24.04:-:lts", ("ubuntu", "24.04")),
    ("cpe:/o:canonical:ubuntu_linux:22.04:-:lts", ("ubuntu", "22.04")),
    ("cpe:/o:debian:debian_linux:12.15", ("debian", "12.15")),
    ("cpe:/o:oracle:linux:9.8", ("oracle", "9.8")),
    ("cpe:/o:almalinux:almalinux:8.10", ("alma", "8.10")),
    ("cpe:/o:rocky:rocky:9.8", ("rocky", "9.8")),
])
def test_os_identity_reads_a_real_cpe(cpe, expected):
    assert _os_identity(cpe) == expected


def test_os_identity_takes_windows_release_from_the_product():
    """Windows carries the release in the product, not the version field.

    The vuls cassette writes "Windows Server 2022" from Vuls, so this has to render the
    same or the two cassettes describe one host two ways.
    """
    assert _os_identity("cpe:/o:microsoft:windows_server_2022:standard_x64") == (
        "windows", "Windows Server 2022")


@pytest.mark.parametrize("cpe", ["", "not-a-cpe", "cpe:/a:openssl:openssl:3.0.21"])
def test_os_identity_is_empty_rather_than_wrong(cpe):
    """An application CPE and a malformed one are both "no answer", not a guess."""
    assert _os_identity(cpe) == ("", "")


def test_os_identity_warns_once_about_an_unmapped_vendor(caplog):
    import cassettes.openvas as LB
    LB._unmapped_os_vendors.discard("nobody")
    with caplog.at_level("WARNING", logger="transformer"):
        assert LB._os_identity("cpe:/o:nobody:mystery_os:1.0") == ("", "")
        LB._os_identity("cpe:/o:nobody:mystery_os:2.0")
    assert caplog.text.count("No os_family mapping") == 1


def test_host_block_carries_the_os(tmp_path):
    document = _one(tmp_path, host_kwargs={"os_cpe": "cpe:/o:rocky:rocky:9.8"}, mapping=MAPPED)
    host = document.hosts["dashboard.example.com"]
    assert (host["os_family"], host["os_release"]) == ("rocky", "9.8")


def test_host_block_os_is_empty_when_greenbone_did_not_fingerprint_it(tmp_path):
    document = _one(tmp_path, mapping=MAPPED)
    host = document.hosts["dashboard.example.com"]
    assert (host["os_family"], host["os_release"]) == ("", "")


def test_the_cassette_is_named_for_its_scanner():
    assert CASSETTE == "openvas"
