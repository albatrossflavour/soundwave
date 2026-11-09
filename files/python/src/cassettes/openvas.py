"""
openvas cassette: turn a Greenbone GMP report into the scanner-neutral findings file.

Greenbone finds network exposure, TLS and configuration problems, and Ubuntu
and Debian package advisories. What another cassette finds is not this one's
business: report everything the scanner said, and let Soundwave work out what
turns out to be the same thing twice.

GMP reports are result-centric: a flat list of <result> rows, each carrying its
own host. The findings file is check-centric with a host block per host, so
this groups as it goes, and it keeps the things the old direct-to-VR parser
threw away on the floor: the NVT OID, the solution type, the QoD, the port, and
the per-host result description. Those four are the whole of what makes a
finding actionable by Puppet rather than merely countable.

The format is docs/findings-file.md.
"""

import logging
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import findings as F  # noqa: E402
from lib.config_helper import load_transformer_parameters  # noqa: E402
from lib.host_map import load_host_map  # noqa: E402
from lib.openvas_client import get_latest_report  # noqa: E402

logger = logging.getLogger("transformer")

CASSETTE = "openvas"

# Package checks (Notus, in openvasd) print one block per vulnerable package in
# the result <description>:
#     Vulnerable package:   curl
#     Installed version:    curl-7.68.0-1ubuntu2.25
#     Fixed version:      >=curl-7.68.0-1ubuntu2.25+esm3
# A vulnerable range prints two Fixed version lines (< and >=). The package name
# comes from the Vulnerable package line and nowhere else. Version checks
# (Windows files, web apps) print Installed and Fixed version with no package
# line, and their "fixed version" is a number or the word Workaround; reading
# names out of Fixed version sent PE packages called "Workaround", "1.9.0" and
# "11.2302.20.0".
_PACKAGE_LINE_RE = re.compile(
    r"^\s*(Vulnerable package|Installed version|Fixed version):[ \t]*(.*?)\s*$", re.MULTILINE
)

# Ubuntu publishes some fixes only to Ubuntu Pro archives, and says so in the
# version: 1.2-1ubuntu0.1~esm1, 1.8.9p5-1ubuntu1.5+esm1, 2.0.1ubuntu0.20.04.2esm2
# (ESM) and 5.4.0-1145.154+fips1 (FIPS). Spellings taken from the notus feed,
# 2026-09-15. Only the version is tested: package names carry "fips" too.
_PRO_CHANNELS = (
    ("ESM", re.compile(r"(?<![A-Za-z])esm\d+")),
    ("FIPS", re.compile(r"(?<![A-Za-z])fips\d+")),
)

# Distro advisory checks, as the feed names them: "Ubuntu: Security Advisory
# (USN-7917-1)", "openSUSE Security Advisory (SUSE-SU-...)", "Huawei EulerOS:
# Security Advisory for kernel (EulerOS-SA-...)". Their affected tag starts with
# the advisory's source packages: "'fonttools' package(s) on Ubuntu 22.04, ...".
_ADVISORY_NAME_RE = re.compile(r"^(?P<distro>.+?):?\s+Security Advisory(?:\s+for\s+.+?)?\s+\((?P<id>[^()]+)\)$")
_AFFECTED_RE = re.compile(r"^'(?P<packages>[^']+)' package\(s\)")
_TITLE_PACKAGES = 3
_TAG_SPLIT_RE = re.compile(r"\|(?=[A-Za-z_][A-Za-z0-9_]*=)")

# This cassette's mapping onto the findings file's fix_type vocabulary, which is
# defined by the format rather than by Greenbone. The shape came from
# solution_type and the values happen to line up one for one, so the mapping is
# only a spelling change here. Other scanners are not so lucky: Nessus and
# Qualys have no mitigation equivalent and their cassettes write null.
_FIX_TYPE = {
    "vendorfix": "vendor-fix",
    "mitigation": "mitigation",
    "workaround": "workaround",
    "noneavailable": "none-available",
    "willnotfix": "will-not-fix",
}

# Greenbone reports the OS it settled on as a CPE, `best_os_cpe`, on every host
# it fingerprinted: cpe:/o:canonical:ubuntu_linux:24.04:-:lts. The family names
# on the right are Vuls's, deliberately, because the vuls cassette already writes them and
# two cassettes describing one host in two vocabularies is the fault this field
# was empty instead of. Keyed on the CPE vendor, with the product only where a
# vendor ships more than one OS line.
_OS_FAMILY_BY_CPE_VENDOR = {
    "canonical": "ubuntu",
    "debian": "debian",
    "oracle": "oracle",
    "almalinux": "alma",
    "rocky": "rocky",
    "redhat": "redhat",
    "centos": "centos",
    "fedoraproject": "fedora",
    "amazon": "amazon",
    "suse": "suse",
    "opensuse": "opensuse",
    "microsoft": "windows",
}

_CPE_OS_RE = re.compile(r"^cpe:/o:(?P<vendor>[^:]+):(?P<product>[^:]+)(?::(?P<version>[^:]+))?")

# Families already seen and reported as unmapped, so one unknown distro logs
# once per run rather than once per host.
_unmapped_os_vendors = set()


def _os_identity(cpe):
    """(os_family, os_release) from Greenbone's best_os_cpe, or ("", "").

    An unrecognised vendor returns empty and says so. Guessing a family from a
    string nobody has checked is how a consumer ends up grouping two distros
    together, and an empty field at least reads as absent.
    """
    match = _CPE_OS_RE.match((cpe or "").strip())
    if not match:
        return "", ""
    vendor = match.group("vendor").lower()
    family = _OS_FAMILY_BY_CPE_VENDOR.get(vendor, "")
    if not family:
        if vendor not in _unmapped_os_vendors:
            _unmapped_os_vendors.add(vendor)
            logger.warning(f"No os_family mapping for CPE vendor {vendor!r} ({cpe}); left empty")
        return "", ""
    version = (match.group("version") or "").strip()
    if family == "windows":
        # Windows carries the release in the product, not the version:
        # cpe:/o:microsoft:windows_server_2022:standard_x64. The vuls cassette writes
        # "Windows Server 2022" from Vuls, so this has to render the same.
        return family, match.group("product").replace("_", " ").strip().title()
    return family, version


# Host details that say the scan logged in. Without one the findings are real
# but the package list is absent, which is a different kind of blind.
_AUTH_DETAILS = ("Auth-SSH-Success", "Auth-SMB-Success", "Auth-ESXi-Success", "Auth-SNMP-Success")

_REFERENCE_CAP = 10


def _parse_tags(nvt):
    """GMP packs metadata into a pipe-delimited <tags> string: k=v|k=v|...

    Values are free text (insight is a vendor's whole write-up), so only a pipe
    that starts the next key splits.
    """
    tags = {}
    tag_el = nvt.find("tags") if nvt is not None else None
    if tag_el is not None and tag_el.text:
        for part in _TAG_SPLIT_RE.split(tag_el.text):
            if "=" in part:
                key, _, value = part.partition("=")
                tags[key.strip()] = value.strip()
    return tags


def _unwrap(text):
    """Join hard-wrapped lines, keeping blank-line paragraph breaks."""
    paragraphs = re.split(r"\n\s*\n", text.strip())
    return "\n\n".join(" ".join(line.strip() for line in p.splitlines()) for p in paragraphs)


def _advisory_title(name, tags):
    """Name a distro advisory by what it affects, for the list PE shows.

    Greenbone names every one "<Distro>: Security Advisory (<ID>)", which says
    nothing until it's looked up. PE groups findings by name, so the new name
    has to be the same on every host: it comes from the advisory's source
    package list in the affected tag, not the packages vulnerable on this host.
    The ID stays, since several advisories share a package (USN-8344-1, -2 and
    -3 are all python-pip). Anything else keeps its name.
    """
    match = _ADVISORY_NAME_RE.match(name)
    affected = _AFFECTED_RE.match(tags.get("affected", "")) if match else None
    if not affected:
        return name
    packages = [p.strip() for p in affected.group("packages").split(",") if p.strip()]
    shown = ", ".join(packages[:_TITLE_PACKAGES])
    if len(packages) > _TITLE_PACKAGES:
        shown += f" +{len(packages) - _TITLE_PACKAGES} more"
    return f"{shown}: {match.group('distro')} {match.group('id')}"


def _cvss_version(tags, score):
    vector = tags.get("cvss_base_vector", "")
    if "CVSS:3" in vector:
        return "3.0"
    if vector:
        return "2.0"
    return "2.0" if score > 0.0 else ""


def _refs(nvt):
    """(cves, urls) from an NVT's references."""
    cves, urls = [], []
    if nvt is None:
        return cves, urls
    refs = nvt.find("refs")
    if refs is not None:
        for ref in refs.findall("ref"):
            kind = ref.get("type", "").lower()
            value = ref.get("id", "")
            if not value:
                continue
            if kind == "cve":
                cves.append(value)
            elif kind == "url":
                urls.append(value)
    # Older feeds expose CVEs as direct <cve> children instead of refs.
    for cve in nvt.findall("cve"):
        if cve.text and cve.text not in ("NOCVE", ""):
            cves.append(cve.text)
    return sorted(set(cves)), sorted(set(urls))[:_REFERENCE_CAP]


class PackageFix:
    def __init__(self, name):
        self.name = name
        self.installed = ""
        self.fixed_versions = []

    def pro_channel(self):
        """The Ubuntu Pro service the fix ships in (ESM, FIPS), or None."""
        for fixed in self.fixed_versions:
            version = fixed.lstrip("<>= \t")
            if version.startswith(f"{self.name}-"):
                version = version[len(self.name) + 1:]
            for channel, pattern in _PRO_CHANNELS:
                if pattern.search(version):
                    return channel
        return None

    def best_fixed(self):
        """The version to upgrade to: the >= bound, or the only one given."""
        for fixed in self.fixed_versions:
            if fixed.startswith(">="):
                return fixed[2:].strip()
        return self.fixed_versions[0].lstrip("<>= \t") if self.fixed_versions else ""


def _package_fixes(result):
    """The vulnerable packages a package check reported, in order, one per name.

    Anything that isn't a package check has no Vulnerable package line and
    yields an empty list.
    """
    description = result.findtext("description") if result is not None else None
    fixes = {}
    current = None
    for label, value in _PACKAGE_LINE_RE.findall(description or ""):
        if label == "Vulnerable package":
            current = fixes.setdefault(value, PackageFix(value)) if value else None
        elif label == "Installed version" and current is not None and value:
            current.installed = value
        elif label == "Fixed version" and current is not None and value:
            current.fixed_versions.append(value)
    return list(fixes.values())


def _host_identity(result):
    """(ipaddress, reverse DNS hostname) for a result's <host>IP<hostname>..</host>."""
    host_el = result.find("host")
    if host_el is None:
        return "", ""
    ipaddress = (host_el.text or "").strip()
    hostname_el = host_el.find("hostname")
    hostname = hostname_el.text.strip() if hostname_el is not None and hostname_el.text else ""
    return ipaddress, hostname


def _host_blocks(report):
    """Per-address scan window, reverse DNS name and whether the scan logged in.

    Every address the scan touched gets one, findings or not. A host with no
    findings and a host never reached look identical from the findings alone,
    and telling them apart is most of what a blind spot report is.
    """
    blocks = {}
    for host in report.findall("host"):
        ipaddress = (host.findtext("ip") or "").strip()
        if not ipaddress:
            continue
        details = {}
        authenticated = False
        for detail in host.findall("detail"):
            name = detail.findtext("name", "")
            if name in _AUTH_DETAILS:
                authenticated = True
            elif name in ("hostname", "best_os_cpe"):
                details[name] = (detail.findtext("value") or "").strip()
        os_family, os_release = _os_identity(details.get("best_os_cpe", ""))
        blocks[ipaddress] = {
            "hostname": details.get("hostname", ""),
            "os_family": os_family,
            "os_release": os_release,
            "scan_start": host.findtext("start", "") or "",
            "scan_end": host.findtext("end", "") or "",
            "authenticated": authenticated,
        }
    return blocks


def _host_errors(report):
    """Per-address scan errors, so a host that half-failed does not read as clean."""
    errors = {}
    container = report.find("errors")
    if container is None:
        return errors
    for error in container.findall("error"):
        host_el = error.find("host")
        ipaddress = (host_el.text or "").strip() if host_el is not None else ""
        if not ipaddress:
            continue
        message = (error.findtext("description") or "").strip()
        if message:
            errors.setdefault(ipaddress, []).append(message)
    return errors


def parse_report(xml_path, mapping, scan_end_fallback=""):
    """Build the openvas findings document from a merged GMP report."""
    root = ET.parse(xml_path).getroot()
    # An Element with no children is falsy, so `a or b` would silently pick the
    # outer report whenever the inner one came back empty.
    report = root.find(".//report/report")
    if report is None:
        report = root.find(".//report")
    if report is None:
        logger.error("No <report> element found in GMP response")
        return None

    # QoD is Greenbone's quality of detection, 0-100, and it is what goes in
    # each finding's confidence below. Said on the cassette so the findings API knows
    # which scale its 70 cut is being drawn on.
    document = F.Document(CASSETTE, "greenbone", run_id=report.get("id", ""),
                          confidence_scale={"min": 0, "max": 100, "kind": "qod"})
    blocks = _host_blocks(report)
    errors = _host_errors(report)

    # Address to the name the finding is filed under. The map is what PuppetDB
    # knows; anything else keeps the name gvmd had and is recorded, because a
    # host PE will not match is worth seeing here rather than nowhere.
    names = {}
    for ipaddress, block in blocks.items():
        certname = (mapping or {}).get(ipaddress)
        name = certname or block["hostname"] or ipaddress
        names[ipaddress] = name
        document.host(
            name,
            ipaddress=ipaddress,
            os_family=block["os_family"],
            os_release=block["os_release"],
            collection="gmp",
            status="partial" if errors.get(ipaddress) else "scanned",
            authenticated=block["authenticated"],
            scan_start=block["scan_start"],
            scan_end=block["scan_end"] or scan_end_fallback,
            errors=errors.get(ipaddress, []),
        )
        if not certname:
            document.unmapped.append({
                "identifier": ipaddress, "collection": "gmp", "sent_as": name,
            })

    results = report.find("results")
    for result in (results.findall("result") if results is not None else []):
        try:
            _add_result(document, result, names, mapping, scan_end_fallback)
        except Exception as err:  # one malformed row must not lose the report
            logger.error(f"Error parsing result {result.get('id')}: {err}")
    return document


def _add_result(document, result, names, mapping, scan_end_fallback):
    severity_el = result.find("severity")
    score = float(severity_el.text) if severity_el is not None and severity_el.text else 0.0
    # Log and None rows carry no finding, only the scanner's working out.
    if score <= 0.0:
        return

    nvt = result.find("nvt")
    oid = nvt.get("oid", "") if nvt is not None else ""
    if not oid:
        return
    check_id = f"greenbone:{oid}"
    tags = _parse_tags(nvt)

    ipaddress, hostname = _host_identity(result)
    certname = names.get(ipaddress)
    if certname is None:
        # A result for an address with no host block. Keep it, under the best
        # name available, and give it a host block so the push can carry it.
        certname = (mapping or {}).get(ipaddress) or hostname or ipaddress
        names[ipaddress] = certname
        document.host(certname, ipaddress=ipaddress, collection="gmp",
                      status="scanned", scan_end=scan_end_fallback)

    cvss_base = nvt.findtext("cvss_base", "") if nvt is not None else ""
    try:
        cvss_score = float(cvss_base) if cvss_base else score
    except ValueError:
        cvss_score = score

    name = result.findtext("name", "") or (nvt.findtext("name", "") if nvt is not None else "")

    solution_el = nvt.find("solution") if nvt is not None else None
    solution = ""
    if solution_el is not None and solution_el.text:
        solution = solution_el.text.strip()
    elif tags.get("solution"):
        solution = tags["solution"]
    solution_type = ""
    if solution_el is not None:
        solution_type = solution_el.get("type", "")
    solution_type = solution_type or tags.get("solution_type", "")
    fix_type = _FIX_TYPE.get(solution_type.replace(" ", "").lower(), "")

    summary = tags.get("summary") or ""
    title = _advisory_title(name, tags)
    if title != name:
        name = title
        if tags.get("insight"):
            summary = _unwrap(tags["insight"])

    cves, urls = _refs(nvt)

    document.check(
        check_id,
        name=name,
        summary=summary,
        solution=solution or "No solution available",
        fix_type=fix_type,
        severity=F.severity_of(score),
        vendor_severity="",
        cvss_score=cvss_score,
        cvss_version=_cvss_version(tags, cvss_score),
        cvss_vector=tags.get("cvss_base_vector", ""),
        cves=cves,
        references=urls,
        kev=False,
    )

    fixes = _package_fixes(result)
    pro = next((f.pro_channel() for f in fixes if f.pro_channel()), None)
    if not fixes:
        state = ""
    elif pro:
        state = "pro-only"
    elif any(f.fixed_versions for f in fixes):
        state = "fixable"
    else:
        state = "unfixed"

    qod = result.findtext("qod/value", "")
    document.finding(
        certname=certname,
        check_id=check_id,
        detected_at=document.hosts.get(certname, {}).get("scan_end", "") or scan_end_fallback,
        # No QoD is not a QoD of nothing. Greenbone always sends one, so this
        # is only reached on a malformed row, and scoring it zero would have
        # Soundwave's floor drop it as low confidence rather than say so.
        confidence=int(qod) if qod.isdigit() else None,
        state=state,
        port=result.findtext("port", "") or None,
        evidence=(result.findtext("description", "") or "").strip(),
        packages=[
            {
                "name": fix.name,
                "arch": "",
                "installed": fix.installed,
                "fixed": fix.best_fixed(),
            }
            for fix in fixes
        ],
        kbs=[],
    )


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
    params = load_transformer_parameters(section="GREENBONE")
    cassette_dir = load_transformer_parameters(section="DEFAULT")["cassette_dir"]

    report_path = get_latest_report(params)
    if report_path is None:
        logger.error("No scan report retrieved from Greenbone")
        return 1
    try:
        mapping = load_host_map(params.get("host_map_file", ""))
        document = parse_report(report_path, mapping)
    finally:
        try:
            os.remove(report_path)
        except OSError as err:
            logger.error(f"Could not remove {report_path}: {err}")

    if document is None:
        return 1
    document.write(os.path.join(cassette_dir, f"{CASSETTE}.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
