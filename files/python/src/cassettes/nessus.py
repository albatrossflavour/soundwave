#!/usr/bin/env python3
"""
nessus cassette: turn .nessus exports into the scanner-neutral findings file.

Experimental. Built against Tenable's documented format and public sample
files, and not yet run against a real scanner.

Nessus, Tenable Vulnerability Management and Tenable.sc all export the same
NessusClientData_v2 XML, so one cassette reads all three. It either exports
named scans over the Nessus / Tenable VM API (lib/tenable_client.py) or reads
every .nessus file dropped in its export directory.

What it will not invent, because the format forbids it:

  confidence  Nessus has no per-finding confidence. Every finding is written
              with null, which Soundwave counts and does not filter, rather
              than a number picked to get past the floor.
  fix_type    Nessus has no solution type. `unsupported_by_vendor`,
              `vendor_unpatched` and `has_patch` map onto will-not-fix,
              none-available and vendor-fix. Nothing in it tells a mitigation
              from a patch, so with none of the three set it is null.

The format is docs/findings-file.md.
"""

import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import export_cassette as X  # noqa: E402
from lib import findings as F  # noqa: E402
from lib.os_identity import os_from_cpe  # noqa: E402

logger = logging.getLogger("transformer")

CASSETTE = "nessus"
SUFFIXES = (".nessus",)

# Info-level plugins carry no finding, but these two say something about the
# scan itself. 19506 is the scan's own summary; 21745 is Nessus saying its
# local checks did not run, which makes a clean host a host it could not see.
SCAN_INFO_PLUGIN = "19506"
PATCH_ASSESSMENT_FAILED_PLUGIN = "21745"

DESCRIPTION_CAP = 2000
REFERENCE_CAP = 10

# The three booleans Tenable documents as plugin attributes, in the order they
# are tested: a vendor that has dropped the product says more than one that
# has not shipped a fix yet, and either says more than "a patch exists".
_FIX_TYPE_FLAGS = (
    ("unsupported_by_vendor", "will-not-fix"),
    ("vendor_unpatched", "none-available"),
    ("has_patch", "vendor-fix"),
)

# Local package checks, in the two wordings Tenable uses. RPM and Debian:
#     Remote package installed : openssl-1.1.1k-7.el8_6
#     Should be                : openssl-1.1.1k-9.el8_7
# Ubuntu:
#     - Installed package : openjdk-11-jdk_11.0.13+8-0ubuntu1~18.04
#       Fixed package     : openjdk-11-jdk_11.0.18+10-0ubuntu1~18.04.1
_PACKAGE_RES = (
    re.compile(r"Remote package installed\s*:\s*(?P<installed>\S+)\s*\n\s*Should be\s*:\s*(?P<fixed>\S+)"),
    re.compile(r"Installed package\s*:\s*(?P<installed>\S+)\s*\n\s*Fixed package\s*:\s*(?P<fixed>\S+)"),
)

_INFO_LINE_RE = re.compile(r"^[ \t]*(?P<key>[A-Za-z][A-Za-z ]*?)[ \t]*:[ \t]*(?P<value>[^\n]*?)[ \t]*$", re.M)
_KB_RE = re.compile(r"^(?:KB)?(\d{6,8})$", re.I)


def _rpm_shaped(text):
    """name-version-release, with version and release both starting in a digit."""
    parts = text.rsplit("-", 2)
    return len(parts) == 3 and parts[1][:1].isdigit() and parts[2][:1].isdigit()


def split_package(spec):
    """(name, version) from `name-version-release` or `name_version`.

    Debian and Ubuntu join name and version with an underscore, and neither
    their names nor their versions can contain one, so a Debian spec has one
    underscore with a version (starting in a digit) after it. RPM joins with
    dashes, and both its names (`python3-ruamel_yaml`) and its releases
    (`7.el8_6`) can carry an underscore, so an underscore alone proves nothing.
    """
    head, sep, tail = spec.partition("_")
    if sep and tail[:1].isdigit() and not _rpm_shaped(head):
        return head, tail
    parts = spec.rsplit("-", 2)
    if len(parts) == 3:
        return parts[0], f"{parts[1]}-{parts[2]}"
    return spec, ""


def packages_from(output):
    packages = []
    for pattern in _PACKAGE_RES:
        for match in pattern.finditer(output or ""):
            name, installed = split_package(match.group("installed"))
            _, fixed = split_package(match.group("fixed"))
            packages.append({"name": name, "arch": "", "installed": installed, "fixed": fixed})
    return packages


def _epoch_iso(text):
    """An epoch-seconds string as UTC ISO-8601, or "".

    HOST_END is the scanner's local time with no zone. HOST_END_TIMESTAMP is
    epoch seconds and so cannot carry a timezone mistake, which is why it is
    the one read.
    """
    try:
        epoch = int((text or "").strip())
    except ValueError:
        return ""
    if epoch <= 0:
        return ""
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _flag(item, name):
    return (item.findtext(name) or "").strip().lower() == "true"


def fix_type_of(item):
    for name, value in _FIX_TYPE_FLAGS:
        if _flag(item, name):
            return value
    return None


def cvss_of(item):
    """(score, version, vector). v3 first, then v2. ("", "", "") is unscored.

    v4 is not read: nothing yet says VR's schema accepts it, and a version it
    refuses rejects the whole push rather than the one record.
    """
    for score_key, vector_key, default in (("cvss3_base_score", "cvss3_vector", "3.0"),
                                          ("cvss_base_score", "cvss_vector", "2.0")):
        text = (item.findtext(score_key) or "").strip()
        if not text:
            continue
        try:
            score = float(text)
        except ValueError:
            continue
        vector = (item.findtext(vector_key) or "").strip()
        version = default
        match = re.match(r"CVSS:(\d\.\d)/", vector)
        if match:
            version = match.group(1)
        return score, version, vector
    return 0.0, "", ""


def kbs_of(item):
    """Microsoft KB numbers, bare, as the vuls cassette writes them."""
    found = []
    for text in [x.text for x in item.findall("mskb")] + [
            x.text.split(":", 1)[1] for x in item.findall("xref")
            if x.text and x.text.upper().startswith("MSKB:")]:
        match = _KB_RE.match((text or "").strip())
        if match and match.group(1) not in found:
            found.append(match.group(1))
    return found


def _scan_info(output):
    return {m.group("key").strip().lower(): m.group("value") for m in _INFO_LINE_RE.finditer(output or "")}


class _Parse:
    """One document built from one or more .nessus files."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.document = F.Document(CASSETTE, "nessus")
        self.scanner_version = None
        self.feed_version = None
        self.run_ids = []
        self.unmapped = set()
        # (certname, scan name) -> (scan_end, [ReportItem]) from the newest
        # run of that scan. A newer run of the same scan replaces an older
        # export's findings, or a vulnerability patched since would never
        # clear. A different scan of the same host is another look, and keeps
        # its own.
        self.latest = {}
        self.report = ""

    def file(self, path):
        for event, elem in ET.iterparse(path, events=("start", "end")):
            if event == "start" and elem.tag == "Report":
                self.report = elem.get("name", "")
                if elem.get("name"):
                    self.run_ids.append(elem.get("name"))
            elif event == "end" and elem.tag == "ReportHost":
                try:
                    self.host(elem)
                except Exception as err:  # one malformed host must not lose the export
                    logger.error(f"Error parsing host {elem.get('name')!r} in {path}: {err}")
                elem.clear()
            elif event == "end" and elem.tag == "Policy":
                elem.clear()

    def host(self, report_host):
        props = {}
        cpes = []
        for tag in report_host.findall("HostProperties/tag"):
            name, value = tag.get("name", ""), (tag.text or "").strip()
            props[name] = value
            if name.startswith("cpe"):
                cpes.append(value)  # os_from_cpe skips anything that is not an OS

        address = props.get("host-ip", "") or report_host.get("name", "")
        certname, mapped = X.certname_for(self.mapping, address, props.get("host-fqdn"),
                                          props.get("host-rdns"), report_host.get("name"))
        os_family, os_release = "", ""
        for cpe in cpes:
            os_family, os_release = os_from_cpe(cpe)
            if os_family:
                break

        errors = []
        items = report_host.findall("ReportItem")
        for item in items:
            plugin = item.get("pluginID", "")
            output = (item.findtext("plugin_output") or "").strip()
            if plugin == SCAN_INFO_PLUGIN:
                info = _scan_info(output)
                self.scanner_version = self.scanner_version or info.get("nessus version")
                self.feed_version = self.feed_version or info.get("plugin feed version")
            elif plugin == PATCH_ASSESSMENT_FAILED_PLUGIN:
                errors.append(f"OS Security Patch Assessment Failed: {output}"[:DESCRIPTION_CAP])

        scan_end = _epoch_iso(props.get("HOST_END_TIMESTAMP"))
        X.record_host(
            self.document, certname,
            ipaddress=address,
            os_family=os_family,
            os_release=os_release,
            collection="nessus",
            status="partial" if errors else "scanned",
            authenticated=props.get("Credentialed_Scan", "").lower() == "true",
            scan_start=_epoch_iso(props.get("HOST_START_TIMESTAMP")),
            scan_end=scan_end,
            errors=errors,
        )
        if not mapped and address not in self.unmapped:
            self.unmapped.add(address)
            self.document.unmapped.append({"identifier": address, "collection": "nessus", "sent_as": certname})

        found = [item for item in items if item.get("severity", "0") != "0"]
        key = (certname, self.report)
        current = self.latest.get(key)
        if current is None or X.newer_scan(scan_end, current[0]):
            self.latest[key] = (scan_end, found)
        elif not X.newer_scan(current[0], scan_end):
            current[1].extend(found)  # the same scan seen twice; findings fold

    def finding(self, certname, item, detected_at):
        plugin = item.get("pluginID", "")
        check_id = f"{CASSETTE}:{plugin}"
        score, version, vector = cvss_of(item)
        references = [line.strip() for line in (item.findtext("see_also") or "").splitlines() if line.strip()]
        description = (item.findtext("description") or "").strip()
        self.document.check(
            check_id,
            name=item.get("pluginName", "") or check_id,
            summary=(description or (item.findtext("synopsis") or "").strip())[:DESCRIPTION_CAP],
            solution=(item.findtext("solution") or "").strip() or "No solution available",
            fix_type=fix_type_of(item),
            severity=F.severity_of(score),
            vendor_severity="",
            cvss_score=score,
            cvss_version=version,
            cvss_vector=vector,
            cves=sorted({(c.text or "").strip() for c in item.findall("cve") if (c.text or "").strip()}),
            references=references[:REFERENCE_CAP],
            kev=bool((item.findtext("cisa-known-exploited") or "").strip()),
        )

        output = (item.findtext("plugin_output") or "").strip()
        packages = packages_from(output)
        port = item.get("port", "0")
        self.document.finding(
            certname=certname,
            check_id=check_id,
            detected_at=detected_at,
            confidence=None,
            state="fixable" if any(p["fixed"] for p in packages) else "",
            port=f"{port}/{item.get('protocol', 'tcp')}" if port not in ("", "0") else None,
            evidence=output,
            packages=packages,
            kbs=kbs_of(item),
        )

    def result(self):
        document = self.document
        for (certname, _), (scan_end, items) in self.latest.items():
            detected_at = scan_end or document.hosts[certname].get("scan_end", "")
            for item in items:
                try:
                    self.finding(certname, item, detected_at)
                except Exception as err:  # one malformed item must not lose the host
                    logger.error(f"Error parsing plugin {item.get('pluginID')} on {certname}: {err}")
        document.scanner_version = self.scanner_version or None
        # The plugin feed's version is a timestamp of when it was built, not of
        # when this scanner fetched it, so fetched_at stays unknown.
        if self.feed_version:
            document.feed = {"name": "nessus-plugins", "version": self.feed_version, "fetched_at": None}
        document.run_id = ", ".join(self.run_ids)
        return document


def parse_exports(paths, mapping=None, params=None):
    """Build the nessus document from every .nessus file in paths."""
    parse = _Parse(mapping)
    for path in paths:
        try:
            parse.file(path)
        except ET.ParseError as err:
            logger.error(f"{path} is not a readable .nessus file: {err}")
    return parse.result()


def fetch(params, workdir):
    from lib.tenable_client import export_scans
    scans = [s for s in params.get("scans", "").split("|") if s]
    return export_scans(params["url"], params.get("access_key", ""), params.get("secret_key", ""),
                        scans, workdir, ca_cert=params.get("ca_cert") or None,
                        timeout=int(params.get("timeout") or 1800))


def main():
    return X.run(CASSETTE, "NESSUS", SUFFIXES, fetch, parse_exports)


if __name__ == "__main__":
    sys.exit(main())
