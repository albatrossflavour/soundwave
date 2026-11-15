"""
Generate an XML Export 2.0 report on an InsightVM or Nexpose console and fetch it.

The report is configured on the console, not here: its format, which sites it
covers and its timezone are choices the console's owner makes and can see.
This client only finds it by name, runs it, and downloads the result, so the
console user needs no more than permission to generate that report.

Paths, statuses and the gzip are from the console's v3 API specification
(help.rapid7.com/insightvm/en-us/api/api-v3.json). Output "is usually returned
in a GZip compressed format", so the first two bytes decide rather than an
assumption either way.
"""

import base64
import gzip
import logging
import os
import shutil

from lib import scanner_http as H

logger = logging.getLogger("transformer")

FORMAT = "xml-export-v2"
PAGE_SIZE = 500
_FAILED = ("aborted", "failed")


def _auth(username, password):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def find_report(base, auth, ca_cert, name):
    """The report called name, walking every page of the console's list."""
    page = 0
    while True:
        listing = H.call_json(f"{base}/api/3/reports?page={page}&size={PAGE_SIZE}",
                              auth_headers=auth, ca_cert=ca_cert)
        for report in listing.get("resources") or []:
            if report.get("name") == name:
                return report
        pages = (listing.get("page") or {}).get("totalPages", 0)
        page += 1
        if page >= pages:
            return None


def generate_report(url, username, password, report_name, dest_dir, ca_cert=None, timeout=1800,
                    interval=10):
    """Generate report_name and write its XML into dest_dir. Returns the path."""
    base = url.rstrip("/")
    auth = _auth(username, password)
    report = find_report(base, auth, ca_cert, report_name)
    if report is None:
        raise H.FetchError(f"no report called {report_name!r} on {base}; names are matched exactly")
    if report.get("format") != FORMAT:
        # Any other format parses as nothing, and an empty cassette pushed to
        # VR clears every node it covers, so this stops here instead.
        raise H.FetchError(f"report {report_name!r} is {report.get('format')!r}, not {FORMAT}")
    report_id = report["id"]

    instance = H.call_json(f"{base}/api/3/reports/{report_id}/generate", method="POST",
                           auth_headers=auth, ca_cert=ca_cert).get("id")
    if instance is None:
        raise H.FetchError(f"generating {report_name!r} returned no instance id")

    def complete():
        status = H.call_json(f"{base}/api/3/reports/{report_id}/history/{instance}",
                             auth_headers=auth, ca_cert=ca_cert).get("status")
        if status in _FAILED:
            raise H.ExportFailed(f"the console reports generating {report_name!r} {status}")
        return status == "complete"

    H.wait_for(complete, f"report {report_name!r}", timeout, interval)
    raw = os.path.join(dest_dir, f"report-{report_id}.raw")
    H.download(f"{base}/api/3/reports/{report_id}/history/{instance}/output", raw,
               auth_headers=auth, ca_cert=ca_cert, headers={"Accept": "*/*"})
    path = os.path.join(dest_dir, f"report-{report_id}.xml")
    gunzip_if_needed(raw, path)
    os.remove(raw)
    logger.info(f"Generated report {report_name!r} ({os.path.getsize(path)} bytes)")
    return path


def gunzip_if_needed(source, dest):
    """Copy source to dest, decompressing on the way if it is gzip."""
    with open(source, "rb") as probe:
        compressed = probe.read(2) == b"\x1f\x8b"
    opener = gzip.open if compressed else open
    with opener(source, "rb") as src, open(dest, "wb") as out:
        shutil.copyfileobj(src, out, H.CHUNK)
