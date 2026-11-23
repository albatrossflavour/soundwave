"""
Exploit intelligence: CISA's KEV catalogue and FIRST's EPSS scores, joined onto checks by CVE.

Scanners disagree on whether they say a CVE is known exploited (Vuls and
Nessus do, Greenbone and Rapid7 never), and none of them carries EPSS. Both
feeds are free files published daily, so Soundwave reads them itself and
every cassette gets the same answer.

Two ways in, one directory. `download` fetches both files into it each run;
`directory` reads whatever someone copied there, for a node that cannot reach
the internet. A download that fails keeps the previous file, so a bad night
leaves yesterday's scores rather than none, and the feed timestamp metric is
what says how old they are.
"""

import csv
import gzip
import io
import json
import logging
import os
import tempfile
import urllib.request
from datetime import datetime, timezone

logger = logging.getLogger("transformer")

KEV_FILE = "known_exploited_vulnerabilities.json"
EPSS_FILE = "epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MODES = ("off", "download", "directory")


def fetch(url, path, timeout=120):
    """Download url to path, replacing it only once the whole file has arrived."""
    directory = os.path.dirname(path)
    handle, partial = tempfile.mkstemp(dir=directory, prefix=".partial-")
    try:
        with os.fdopen(handle, "wb") as out, urllib.request.urlopen(url, timeout=timeout) as response:
            while True:
                chunk = response.read(1 << 16)
                if not chunk:
                    break
                out.write(chunk)
        os.replace(partial, path)
    except BaseException:
        os.unlink(partial)
        raise


def _epoch(text, fmt):
    try:
        return int(datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp())
    except (TypeError, ValueError):
        return None


def load_kev(path):
    """({CVE IDs}, catalogue release epoch) from CISA's KEV JSON."""
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    cves = {v["cveID"].strip().upper() for v in document.get("vulnerabilities") or [] if v.get("cveID")}
    if not cves:
        raise ValueError("no vulnerabilities in the KEV catalogue")
    released = _epoch((document.get("dateReleased") or "")[:19], "%Y-%m-%dT%H:%M:%S")
    return cves, released


def load_epss(path):
    """({CVE: (score, percentile)}, score date epoch) from FIRST's EPSS CSV, gzipped or not.

    The file opens with a comment line, `#model_version:...,score_date:...`,
    before the cve,epss,percentile header.
    """
    with open(path, "rb") as raw:
        gzipped = raw.read(2) == b"\x1f\x8b"
    opener = gzip.open if gzipped else open
    scores, scored = {}, None
    with opener(path, "rb") as binary:
        text = io.TextIOWrapper(binary, encoding="utf-8")
        first = text.readline()
        if first.startswith("#"):
            for part in first[1:].strip().split(","):
                key, _, value = part.partition(":")
                if key == "score_date":
                    scored = _epoch(value[:10], "%Y-%m-%d")
            reader = csv.DictReader(text)
        else:
            reader = csv.DictReader(io.StringIO(first + text.read()))
        for row in reader:
            try:
                scores[row["cve"].strip().upper()] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
    if not scores:
        raise ValueError("no scores in the EPSS file")
    return scores, scored


def _epss_path(directory):
    """The EPSS file in the directory: the gzipped name the feed publishes, or a plain .csv someone unpacked."""
    for name in (EPSS_FILE, EPSS_FILE[:-3]):
        path = os.path.join(directory, name)
        if os.path.exists(path):
            return path
    return os.path.join(directory, EPSS_FILE)


def refresh(defaults):
    """Fetch both feeds when the mode is download. A failure is logged and keeps the previous file."""
    if defaults.get("threat_intel", "off") != "download":
        return
    directory = defaults.get("threat_intel_dir", "")
    timeout = int(defaults.get("threat_intel_timeout", 120))
    for name, url, filename in (
        ("KEV", defaults.get("kev_url") or KEV_URL, KEV_FILE),
        ("EPSS", defaults.get("epss_url") or EPSS_URL, EPSS_FILE),
    ):
        try:
            fetch(url, os.path.join(directory, filename), timeout)
            logger.info(f"threat intel: {name} downloaded from {url}")
        except Exception as err:
            logger.error(f"threat intel: {name} download from {url} failed, keeping any previous file: {err}")


def load(defaults):
    """(kev, epss, feeds) from the threat intel directory, or empty when the mode is off.

    feeds is {"kev"|"epss": publish epoch or None} for each feed that loaded.
    A feed that is missing or unreadable is logged and left out; the other
    still applies.
    """
    if defaults.get("threat_intel", "off") == "off":
        return set(), {}, {}
    directory = defaults.get("threat_intel_dir", "")
    kev, epss, feeds = set(), {}, {}
    for name, loader, path in (
        ("kev", load_kev, os.path.join(directory, KEV_FILE)),
        ("epss", load_epss, _epss_path(directory)),
    ):
        try:
            data, published = loader(path)
        except FileNotFoundError:
            logger.error(f"threat intel: no {name.upper()} file at {path}, so checks go without it")
            continue
        except Exception as err:
            logger.error(f"threat intel: {name.upper()} file {path} unreadable, so checks go without it: {err}")
            continue
        feeds[name] = published
        if name == "kev":
            kev = data
        else:
            epss = data
    return kev, epss, feeds


def enrich(documents, kev, epss):
    """Mark each check in each cassette with KEV and EPSS from its CVEs. Returns how many checks each feed touched.

    KEV stays sticky: a scanner that already said true is never overruled by
    a catalogue that has since dropped the CVE. EPSS is the highest score of
    any of the check's CVEs, with that CVE's percentile, because a check
    covering several CVEs is as urgent as its worst one.
    """
    marked = {"kev": 0, "epss": 0}
    for document in documents:
        for check in (document.get("checks") or {}).values():
            cves = [c.strip().upper() for c in check.get("cves") or [] if isinstance(c, str)]
            if kev and not check.get("kev") and any(c in kev for c in cves):
                check["kev"] = True
                marked["kev"] += 1
            scored = [epss[c] for c in cves if c in epss]
            if scored:
                check["epss"], check["epss_percentile"] = max(scored)
                marked["epss"] += 1
    return marked
