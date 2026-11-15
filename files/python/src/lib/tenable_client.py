"""
Export scans as .nessus files from Nessus or Tenable Vulnerability Management.

Both serve the same scan API under the same paths and take the same
`X-ApiKeys` header, so one client covers a Nessus scanner on 8834 and
cloud.tenable.com. Tenable.sc has an API of its own and is not covered here;
its .nessus exports can still be dropped into the cassette's export directory.

A scan is named, not numbered, because the name is what a person sees in the
console and the ID changes if the scan is recreated. The export is always of a
completed run. A scan that is running right now exports whatever it has so
far, which would push a half-scanned estate and have VR replace every node's
findings with a partial set.

Tenable documents the paths at developer.tenable.com (scans-list,
scans-export-request, scans-export-status, scans-export-download). Whether a
Nessus Professional or Essentials licence issues API keys that can export is
not confirmed, and Tenable says it depends on the licence.
"""

import logging
import os
import urllib.parse

from lib import scanner_http as H

logger = logging.getLogger("transformer")


def _auth(access_key, secret_key):
    return {"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"}


def _completed_history(base, scan_id, auth, ca_cert):
    """The history_id of the scan's newest completed run, or None."""
    details = H.call_json(f"{base}/scans/{scan_id}", auth_headers=auth, ca_cert=ca_cert)
    runs = [h for h in (details.get("history") or []) if h.get("status") == "completed"]
    if not runs:
        return None
    newest = max(runs, key=lambda h: h.get("last_modification_date") or h.get("creation_date") or 0)
    return newest.get("history_id")


def find_scan(scans, name):
    """The scan called name, the most recently changed one if several share it."""
    matches = [s for s in scans if s.get("name") == name]
    if not matches:
        return None
    if len(matches) > 1:
        logger.warning(f"{len(matches)} scans are called {name!r}; exporting the most recently changed")
    return max(matches, key=lambda s: s.get("last_modification_date") or 0)


def export_scans(url, access_key, secret_key, scan_names, dest_dir, ca_cert=None, timeout=1800,
                 interval=10):
    """Export each named scan's latest completed run into dest_dir.

    Returns the paths written, one per scan, or raises FetchError if any scan
    could not be exported. It is all or nothing because the cassette replaces
    its previous file: written from some of the scans, it would drop the other
    scans' hosts with a fresh timestamp, and no staleness alert would fire for
    them. Every scan is still tried, so one run's log names every failure.
    """
    base = url.rstrip("/")
    auth = _auth(access_key, secret_key)
    listing = H.call_json(f"{base}/scans", auth_headers=auth, ca_cert=ca_cert)
    scans = listing.get("scans") or []
    paths, failed = [], []
    for name in scan_names:
        try:
            path = _export_one(base, auth, ca_cert, scans, name, dest_dir, timeout, interval)
        except H.FetchError as err:
            logger.error(f"Scan {name!r} not exported: {err}")
            path = None
        if path:
            paths.append(path)
        else:
            failed.append(name)
    if failed:
        raise H.FetchError(f"{len(failed)} of {len(scan_names)} scan(s) not exported "
                           f"({', '.join(repr(n) for n in failed)}), so the previous file is kept")
    return paths


def _export_one(base, auth, ca_cert, scans, name, dest_dir, timeout, interval):
    scan = find_scan(scans, name)
    if scan is None:
        logger.error(f"No scan called {name!r} on {base}; names are matched exactly")
        return None
    scan_id = scan["id"]
    query = ""
    if scan.get("status") != "completed":
        history_id = _completed_history(base, scan_id, auth, ca_cert)
        if history_id is None:
            logger.error(f"Scan {name!r} is {scan.get('status')!r} and has no completed run to export")
            return None
        logger.info(f"Scan {name!r} is {scan.get('status')!r}; exporting its last completed run")
        query = "?" + urllib.parse.urlencode({"history_id": history_id})

    started = H.call_json(f"{base}/scans/{scan_id}/export{query}", method="POST",
                          auth_headers=auth, body={"format": "nessus"}, ca_cert=ca_cert)
    file_id = started.get("file")
    if file_id is None:
        raise H.FetchError(f"export of {name!r} returned no file id: {started}")

    def ready():
        status = H.call_json(f"{base}/scans/{scan_id}/export/{file_id}/status",
                             auth_headers=auth, ca_cert=ca_cert).get("status")
        if status == "error":
            raise H.ExportFailed(f"Tenable reported the export of {name!r} failed")
        return status == "ready"

    H.wait_for(ready, f"export of {name!r}", timeout, interval)
    path = os.path.join(dest_dir, f"scan-{scan_id}.nessus")
    size = H.download(f"{base}/scans/{scan_id}/export/{file_id}/download", path,
                      auth_headers=auth, ca_cert=ca_cert, headers={"Accept": "*/*"})
    logger.info(f"Exported scan {name!r} ({size} bytes)")
    return path
