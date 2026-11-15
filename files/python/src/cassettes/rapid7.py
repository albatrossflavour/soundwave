#!/usr/bin/env python3
"""
rapid7 cassette: turn InsightVM or Nexpose XML Export 2.0 into the findings file.

Experimental. Built against Rapid7's documented format, the console's v3 API
specification and public sample exports, and not yet run against a real
console.

It either generates a named XML Export 2.0 report on the console
(lib/rapid7_client.py) or reads every .xml file dropped in its export
directory. The export lists nodes first, each with the tests that found
something, and the vulnerability definitions after them all, so findings are
reduced as nodes go by and named once the definitions arrive.

What it will not invent, because the format forbids it:

  confidence     Rapid7 says how it found a vulnerability (exploited, by
                 version, potential), which is a method rather than a number.
                 Each method takes the QoD Greenbone publishes for the same
                 kind of detection (CONFIDENCE_BY_STATUS), because Soundwave's
                 floor is drawn on that scale. A status not in the table is
                 null rather than guessed. The method still opens the evidence.
  fix_type       Rapid7 has no solution type. Null.
  authenticated  The export does not say whether a node was scanned with
                 credentials. Left false, which reads as "not known to be".
  timestamps     The export's times carry no zone. They are in the zone the
                 console's report was set to, which this cassette is told
                 (`timezone`, UTC by default) rather than guesses.

The format is docs/findings-file.md.
"""

import logging
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # Python before 3.9 is not supported, but say why
    ZoneInfo = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import export_cassette as X  # noqa: E402
from lib import findings as F  # noqa: E402
from lib.os_identity import os_from_cpe, os_from_vendor  # noqa: E402

logger = logging.getLogger("transformer")

CASSETTE = "rapid7"
SUFFIXES = (".xml",)
DESCRIPTION_CAP = 2000
REFERENCE_CAP = 10

# Every status that means the test found the vulnerability. The rest (pass,
# fail, not-vulnerable, error, skipped...) carry no finding.
VULNERABLE_PREFIX = "vulnerable"

# Rapid7's detection method as the QoD Greenbone gives the same kind of
# detection, so Soundwave's floor (gvmd's default minimum QoD, 70) means the
# same thing for both scanners. `vulnerable-version` takes the banner figure
# rather than `package` (97): the export does not say whether the node was
# scanned with credentials, and either clears the floor.
CONFIDENCE_BY_STATUS = {
    "vulnerable-exploited": 100,  # exploit
    "vulnerable-version": 80,     # remote_banner, executable_version
    "vulnerable-potential": 30,   # remote_banner_unreliable
}
CONFIDENCE_SCALE = {"min": 0, "max": 100, "kind": "qod-equivalent"}

def _text(elem):
    """An element's prose with the markup and its whitespace flattened."""
    if elem is None:
        return ""
    return " ".join(" ".join(elem.itertext()).split())


def os_identity(fingerprint):
    """(os_family, os_release) from a node's best <os> fingerprint, or ("", "")."""
    if fingerprint is None:
        return "", ""
    if fingerprint.get("cpe"):
        family, release = os_from_cpe(fingerprint.get("cpe"))
        if family:
            return family, release
    return os_from_vendor(fingerprint.get("vendor"), fingerprint.get("product"), fingerprint.get("version"))


def _best_os(node):
    def certainty(fp):
        try:
            return float(fp.get("certainty") or 0)
        except ValueError:
            return 0.0
    fingerprints = node.findall("fingerprints/os")
    return max(fingerprints, key=certainty) if fingerprints else None


class _Clock:
    """Rapid7's zone-less `20261113T021500123` as ISO-8601 in a named zone."""

    def __init__(self, zone_name):
        if ZoneInfo is None:
            raise ValueError("zoneinfo needs Python 3.9 or later")
        try:
            self.zone = ZoneInfo(zone_name or "UTC")
        except (ZoneInfoNotFoundError, ValueError) as err:
            raise ValueError(f"unknown timezone {zone_name!r}: {err}") from err

    def iso(self, text):
        text = (text or "").strip()
        try:
            parsed = datetime.strptime(text[:15], "%Y%m%dT%H%M%S")
        except ValueError:
            return ""
        return parsed.replace(tzinfo=self.zone).isoformat()


def cvss_of(vuln):
    """(score, version, vector). v3 first if the export carries it, then v2.

    No sample export carries a v3 attribute, so the v3 names below are a guess
    that costs nothing when it is wrong. v2's vector arrives in brackets.
    """
    for score_key, vector_key, version in (("cvss3Score", "cvss3Vector", "3.0"),
                                           ("cvssScore", "cvssVector", "2.0")):
        text = (vuln.get(score_key) or "").strip()
        if not text:
            continue
        try:
            score = float(text)
        except ValueError:
            continue
        vector = (vuln.get(vector_key) or "").strip().strip("()")
        if vector.startswith("CVSS:3.1/"):
            version = "3.1"
        return score, version, vector
    return 0.0, "", ""


class _Parse:
    def __init__(self, mapping, clock):
        self.mapping = mapping
        self.clock = clock
        self.document = F.Document(CASSETTE, "rapid7", confidence_scale=CONFIDENCE_SCALE)
        self.scans = {}
        self.pending = []
        self.definitions = {}
        self.unmapped = set()
        self.run_ids = []

    def file(self, path):
        nodes = []
        for _, elem in ET.iterparse(path, events=("end",)):
            if elem.tag == "scan":
                scan_id = elem.get("id", "")
                self.scans[scan_id] = (elem.get("startTime", ""), elem.get("endTime", ""))
                if elem.get("name"):
                    self.run_ids.append(elem.get("name"))
            elif elem.tag == "node":
                try:
                    nodes.append(self.node(elem))
                except Exception as err:  # one malformed node must not lose the export
                    logger.error(f"Error parsing node {elem.get('address')!r} in {path}: {err}")
                elem.clear()
            elif elem.tag == "vulnerability":
                self.definition(elem)
                elem.clear()
        # Host blocks once the file's scans are all known, since a node's scan
        # window comes from the scans its tests name.
        for node in nodes:
            self.host(node)

    def node(self, node):
        """Reduce a node to what the document needs, before it is cleared."""
        names = [(n.text or "").strip() for n in node.findall("names/name")]
        tests = []
        for test in node.findall("tests/test"):
            tests.append((test, None))
        for endpoint in node.findall("endpoints/endpoint"):
            port = f"{endpoint.get('port', '')}/{endpoint.get('protocol', 'tcp')}"
            for test in endpoint.findall("services/service/tests/test"):
                tests.append((test, port))
        found = []
        scan_ids = set()
        for test, port in tests:
            if test.get("scan-id"):
                scan_ids.add(test.get("scan-id"))
            status = test.get("status", "")
            if not status.startswith(VULNERABLE_PREFIX):
                continue
            found.append({
                "vuln": (test.get("id") or "").lower(),
                "port": port,
                "status": status,
                "evidence": _text(test),
            })
        return {
            "address": node.get("address", ""),
            "alive": node.get("status", "alive") == "alive",
            "names": [n for n in names if n],
            "os": os_identity(_best_os(node)),
            "scan_ids": scan_ids,
            "found": found,
        }

    def definition(self, vuln):
        refs = vuln.findall("references/reference")
        self.definitions[(vuln.get("id") or "").lower()] = {
            "title": vuln.get("title", ""),
            "cvss": cvss_of(vuln),
            "summary": _text(vuln.find("description"))[:DESCRIPTION_CAP],
            "solution": _text(vuln.find("solution"))[:DESCRIPTION_CAP],
            "cves": sorted({(r.text or "").strip() for r in refs
                            if r.get("source", "").upper() == "CVE" and (r.text or "").strip()}),
            "kbs": sorted({(r.text or "").strip().upper().removeprefix("KB") for r in refs
                           if r.get("source", "").upper() == "MSKB" and (r.text or "").strip()}),
            "urls": [(r.text or "").strip() for r in refs
                     if r.get("source", "").upper() == "URL" and (r.text or "").strip()][:REFERENCE_CAP],
        }

    def host(self, node):
        address = node["address"]
        certname, mapped = X.certname_for(self.mapping, address, *node["names"])
        windows = [self.scans[s] for s in node["scan_ids"] if s in self.scans] or list(self.scans.values())
        starts = [self.clock.iso(s) for s, _ in windows]
        ends = [self.clock.iso(e) for _, e in windows]
        scan_end = max((e for e in ends if e), key=lambda e: F.iso_to_epoch(e) or 0, default="")
        scan_start = min((s for s in starts if s), key=lambda s: F.iso_to_epoch(s) or 0, default="")
        os_family, os_release = node["os"]
        X.record_host(
            self.document, certname,
            ipaddress=address,
            os_family=os_family,
            os_release=os_release,
            collection="rapid7",
            status="scanned" if node["alive"] else "unreachable",
            authenticated=False,
            scan_start=scan_start,
            scan_end=scan_end,
        )
        if not mapped and address not in self.unmapped:
            self.unmapped.add(address)
            self.document.unmapped.append({"identifier": address, "collection": "rapid7", "sent_as": certname})
        for found in node["found"]:
            self.pending.append((certname, scan_end, found))

    def result(self):
        missing = 0
        stale = 0
        for certname, scan_end, found in self.pending:
            if X.newer_scan(self.document.hosts[certname].get("scan_end"), scan_end):
                stale += 1  # a newer export of this host has the say
                continue
            definition = self.definitions.get(found["vuln"])
            if definition is None:
                missing += 1
                continue
            check_id = f"{CASSETTE}:{found['vuln']}"
            score, version, vector = definition["cvss"]
            self.document.check(
                check_id,
                name=definition["title"] or check_id,
                summary=definition["summary"],
                solution=definition["solution"] or "No solution available",
                fix_type=None,
                severity=F.severity_of(score),
                vendor_severity="",
                cvss_score=score,
                cvss_version=version,
                cvss_vector=vector,
                cves=definition["cves"],
                references=definition["urls"],
                kev=False,
            )
            evidence = found["evidence"]
            self.document.finding(
                certname=certname,
                check_id=check_id,
                detected_at=scan_end,
                confidence=CONFIDENCE_BY_STATUS.get(found["status"]),
                state="",
                port=found["port"],
                evidence=f"{found['status']}: {evidence}" if evidence else found["status"],
                packages=[],
                kbs=definition["kbs"],
            )
        if stale:
            logger.info(f"{stale} finding(s) from older exports of a host were superseded by a newer export")
        if missing:
            logger.warning(f"{missing} finding(s) name a vulnerability the export does not define, and were skipped")
        self.document.run_id = ", ".join(self.run_ids)
        return self.document


def parse_exports(paths, mapping=None, params=None):
    """Build the rapid7 document from every XML Export 2.0 file in paths."""
    try:
        clock = _Clock((params or {}).get("timezone") or "UTC")
    except ValueError as err:
        logger.error(f"rapid7: {err}; set it to the timezone the console's report uses")
        return None
    parse = _Parse(mapping, clock)
    for path in paths:
        try:
            parse.file(path)
        except ET.ParseError as err:
            logger.error(f"{path} is not a readable XML export: {err}")
    return parse.result()


def fetch(params, workdir):
    from lib.rapid7_client import generate_report
    return [generate_report(params["url"], params.get("username", ""), params.get("password", ""),
                            params.get("report", ""), workdir, ca_cert=params.get("ca_cert") or None,
                            timeout=int(params.get("timeout") or 1800))]


def main():
    return X.run(CASSETTE, "RAPID7", SUFFIXES, fetch, parse_exports)


if __name__ == "__main__":
    sys.exit(main())
