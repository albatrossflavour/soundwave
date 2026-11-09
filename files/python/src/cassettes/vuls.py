#!/usr/bin/env python3
"""vuls cassette: turn a Vuls run into the scanner-neutral findings file.

Vuls reports CVEs. Errata are what actually get applied, and what a human
recognises, so this groups a host's CVEs under the distro advisory that fixes
them and emits one check per advisory. On Oracle 9 that turns four thousand
kernel CVE rows into a handful of ELSA numbers before any filtering happens.

Two filters run, and both publish what they dropped:

  unfixed         a package the vendor has not fixed. `vuls report
                  -ignore-unfixed` keeps a CVE when *any* of its packages has a
                  fix, so the unfixed ones still arrive here.
  running-kernel  a kernel advisory for a different kernel stream. Vuls matches
                  UEK8 (6.12) advisories against a UEK7 (5.15) host; the fix is
                  real but this host cannot take it without changing kernel
                  stream, so it is not an update and not a finding.

Windows takes its own path. Its fixes are KBs held at CVE level rather than
versions on a package, so it groups by KB the way Linux groups by advisory, and
a CVE with no KB is kept rather than dropped: on Windows "Not fixed yet" usually
means the mitigation is an opt-in setting, which is something that can be done.

The format is docs/findings-file.md in the soundwave repo.
"""

import argparse
import json
import os
import re
import sys

try:
    import tomllib
except ModuleNotFoundError:
    # Python before 3.11, such as EL8 and EL9's 3.9. Only the server names are
    # read, from the config Puppet writes, so a pattern does.
    tomllib = None
from datetime import datetime, timezone

SCHEMA = "puppet-findings/1"
CASSETTE = "vuls"

SERVER_RE = re.compile(r'^\[servers\.(?:"([^"]+)"|([^\]\s]+))\]\s*$', re.M)

# Kernel packages, for the running-kernel filter only. A dash or end of string
# after the prefix, so kernelshark and linux-firmware are left alone.
KERNEL_RE = re.compile(r"^(kernel|linux-image|linux-headers|linux-modules|linux-tools)(-|$)")

# Advisory severity as the vendors spell it, mapped to the PE enum.
VENDOR_SEVERITY = {
    "CRITICAL": "critical",
    "IMPORTANT": "high",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "none",
}

# cveContents is keyed by source. The vendor's own view of a distro package
# beats NVD's, which scores the upstream flaw rather than the shipped build.
SOURCE_PREFERENCE = ("oracle", "redhat_api", "redhat", "ubuntu_api", "ubuntu", "debian",
                     "alma", "rocky", "amazon", "suse", "nvd", "euvd", "mitre")

SCAN_MODE = {"fast mode": "ssh-fast", "fast root mode": "ssh-fast-root",
             "deep mode": "ssh-deep", "offline mode": "ssh-offline",
             "fast offline mode": "ssh-fast-offline"}

# Every host block carries the same keys whether or not the result could be
# read, so a consumer never has to test for their presence.
EMPTY_HOST = {
    "ipaddress": "", "os_family": "", "os_release": "", "collection": "",
    "status": "unknown", "authenticated": False, "scan_start": "", "scan_end": "",
    "errors": [], "warnings": [],
}

DESCRIPTION_CAP = 2000
SAMPLE_CAP = 10
REFERENCE_CAP = 10
CHUNK = 1 << 20


def log(message):
    print(f"vuls cassette: {message}", file=sys.stderr)


def strip_epoch(version):
    """`0:6.12.0-102.el9uek` -> `6.12.0-102.el9uek`. `5.15.0-324` unchanged.

    fixedIn always carries an explicit epoch; an installed version carries one
    only when it is non-zero, so the two are not comparable as strings.
    """
    head, sep, tail = version.partition(":")
    return tail if sep and head.isdigit() else version


_SEGMENT_RE = re.compile(r"([0-9]+|[a-zA-Z]+|~)")


def vercmp(left, right):
    """Compare two upstream versions by RPM's rules. Returns -1, 0 or 1.

    Enough of rpmvercmp to answer "is this a downgrade": digit runs compare
    numerically, letter runs asciibetically, digits beat letters, and a tilde
    sorts before everything (pre-releases). Separators carry no meaning.
    """
    a = [s for s in _SEGMENT_RE.findall(left) if s]
    b = [s for s in _SEGMENT_RE.findall(right) if s]
    for x, y in zip(a, b):
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x.isdigit() and y.isdigit():
            if int(x) != int(y):
                return -1 if int(x) < int(y) else 1
            continue
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1
        if x != y:
            return -1 if x < y else 1
    if len(a) == len(b):
        return 0
    longer, sign = (a, 1) if len(a) > len(b) else (b, -1)
    return -sign if longer[len(min(a, b, key=len))] == "~" else sign


def upstream(version):
    """The version without its epoch or release: `30:7.2.0-11.el9` -> `7.2.0`."""
    return strip_epoch(version).split("-", 1)[0]


def major_minor(version):
    """The upstream major.minor of an RPM or dpkg version, or None."""
    upstream = strip_epoch(version).split("-", 1)[0]
    parts = [p for p in upstream.split(".") if p != ""]
    if len(parts) < 2:
        return upstream or None
    return f"{parts[0]}.{parts[1]}"


class _Stream:
    """Just enough incremental JSON to walk one object without holding it all.

    An Oracle 9 result is 561 MB *after* `-ignore-unfixed`: 4,310 kernel CVEs,
    each carrying seven vendors' write-ups and the UEK changelog. json.load on
    one of those is what OOM-killed this node during the trial. Almost all of
    that bulk is prose nothing downstream reads, so the file is walked a value
    at a time and reduced as it goes.
    """

    def __init__(self, handle):
        self.handle = handle
        self.buf = ""
        self.pos = 0
        self.decoder = json.JSONDecoder()

    def _fill(self):
        data = self.handle.read(CHUNK)
        if not data:
            return False
        if self.pos:
            self.buf = self.buf[self.pos:]
            self.pos = 0
        self.buf += data
        return True

    def peek(self):
        while True:
            while self.pos < len(self.buf) and self.buf[self.pos] in " \t\r\n":
                self.pos += 1
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            if not self._fill():
                return ""

    def take(self, char):
        if self.peek() != char:
            raise ValueError(f"expected {char!r} at byte {self.pos}")
        self.pos += 1

    def value(self):
        # raw_decode does not skip leading whitespace, and a pretty-printed
        # result has some before every value. Without this the decode fails,
        # the buffer refills looking for more input, and the "streaming" reader
        # quietly pulls the whole 561 MB file into memory before giving up.
        if not self.peek():
            raise ValueError("end of input where a value was expected")
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buf, self.pos)
                self.pos = end
                return value
            except ValueError:
                if not self._fill():
                    raise

    def members(self):
        """Yield (key, value) for one JSON object, decoding values lazily."""
        self.take("{")
        if self.peek() == "}":
            self.pos += 1
            return
        while True:
            key = self.value()
            self.take(":")
            yield key, self
            char = self.peek()
            if char == ",":
                self.pos += 1
                continue
            self.take("}")
            return


def read_result(path, on_cve):
    """Walk one Vuls result. Calls on_cve(cve_id, stream) per scanned CVE.

    Returns the top-level fields other than scannedCves. Those fields are
    written after scannedCves by Vuls, so the CVE reduction cannot see
    `packages`; the kernel filter runs once the whole file has been read.
    """
    top = {}
    with open(path, encoding="utf-8") as handle:
        stream = _Stream(handle)
        for key, value in stream.members():
            if key == "scannedCves":
                for cve_id, inner in value.members():
                    on_cve(cve_id, inner)
            else:
                top[key] = value.value()
    return top


def complete_run(complete_file):
    """The run the Vuls module recorded as finished, or None.

    Never the newest directory: a scan that overruns this run's schedule is
    still writing that one, and reading it would push half a scan.
    """
    try:
        with open(complete_file, encoding="utf-8") as handle:
            path = handle.read().strip()
    except OSError:
        return None
    return path if path and os.path.isdir(path) else None


def expected_servers(config_path, windows_path):
    """The certnames the run was configured to attempt, from both sources.

    Vuls writes no result file at all for a host it could not reach, so without
    this a node that has silently stopped being scanned is indistinguishable
    from a node with nothing wrong.

    Windows hosts are not in config.toml, because they are not scanned over SSH
    and Vuls has nothing to put there. Reading only config.toml files every
    Windows host as unmapped and drops it, findings and all.
    """
    expected = []
    try:
        with open(config_path, encoding="utf-8") as handle:
            text = handle.read()
        if tomllib:
            expected += list((tomllib.loads(text).get("servers") or {}).keys())
        else:
            expected += [quoted or bare for quoted, bare in SERVER_RE.findall(text)]
    # tomllib.TOMLDecodeError is a ValueError.
    except (OSError, ValueError) as err:
        log(f"cannot read expected servers from {config_path}: {err}")
    if windows_path:
        try:
            with open(windows_path, encoding="utf-8") as handle:
                expected += [h["certname"] for h in json.load(handle) if h.get("certname")]
        except (OSError, ValueError, TypeError) as err:
            log(f"cannot read expected Windows servers from {windows_path}: {err}")
    return sorted(set(expected))


def best_content(cve_contents):
    """The preferred vendor view of a CVE, as (score, version, vector, content)."""
    ordered = [s for s in SOURCE_PREFERENCE if s in cve_contents]
    ordered += [s for s in cve_contents if s not in SOURCE_PREFERENCE]
    for source in ordered:
        entries = cve_contents.get(source) or []
        if isinstance(entries, dict):
            entries = [entries]
        for entry in entries:
            for score_key, vector_key, version in (
                ("cvss40Score", "cvss40Vector", "4.0"),
                ("cvss3Score", "cvss3Vector", "3.1"),
                ("cvss2Score", "cvss2Vector", "2.0"),
            ):
                score = entry.get(score_key) or 0
                if score > 0:
                    return float(score), version, entry.get(vector_key, ""), entry
    # No score anywhere: still return a content block for its summary.
    for source in ordered:
        entries = cve_contents.get(source) or []
        if isinstance(entries, dict):
            entries = [entries]
        if entries:
            return 0.0, "", "", entries[0]
    return 0.0, "", "", {}


def severity_of(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def source_of(binary_name, src_index):
    return src_index.get(binary_name, binary_name)


def installed_version(packages, name):
    """`version-release` as the scanner reported it, epoch included."""
    entry = packages.get(name)
    if not entry:
        return None
    version = entry.get("version") or ""
    release = entry.get("release") or ""
    return f"{version}-{release}" if release else version


class Drops:
    """Filter counters, plus a bounded sample so a rule can be checked later."""

    def __init__(self):
        self.counts = {}
        self.hosts = {}
        self.samples = {}

    def add(self, filter_name, certname, sample):
        self.counts[filter_name] = self.counts.get(filter_name, 0) + 1
        self.hosts.setdefault(filter_name, set()).add(certname)
        bucket = self.samples.setdefault(filter_name, [])
        if len(bucket) < SAMPLE_CAP:
            bucket.append(sample)

    def to_list(self, reasons):
        return [
            {
                "filter": name,
                "reason": reasons.get(name, ""),
                "findings": count,
                "hosts": len(self.hosts.get(name, ())),
                "sample": self.samples.get(name, []),
            }
            for name, count in sorted(self.counts.items())
        ]


DROP_REASONS = {
    "unfixed": "the vendor has published no fix for this package",
    "different-stream": "the advisory's fix is an older build than the one installed",
    "running-kernel": "advisory fixes a different kernel stream from the one installed",
}


def keep_package(affected, packages, top, certname, cve, drops):
    """Decide one affected package. Returns its fixed version, or None to drop."""
    name = affected["name"]
    fixed = affected["fixedIn"]

    if affected["notFixedYet"] or not fixed:
        drops.add("unfixed", certname, {
            "certname": certname, "cve": cve["cve"], "package": name,
            "fix_state": affected["fixState"],
        })
        return None

    installed = installed_version(packages, name)
    if installed is None:
        # Affected but not installed. Nothing to compare against, so keep it
        # and let the evidence show the gap rather than dropping silently.
        return fixed

    # An advisory whose fix is an older build than what is installed is not an
    # update, whatever its epoch says. Oracle 9.8 ships qemu-guest-agent
    # 17:10.1.0-17.el9_8.5 and Vuls matches it against ELSAs fixing
    # 30:7.2.0-11.el9: a higher epoch on a parallel stream the host is not on,
    # and dnf offers nothing. Verified on the node, 2026-09-16.
    if vercmp(upstream(fixed), upstream(installed)) < 0:
        drops.add("different-stream", certname, {
            "certname": certname,
            "check_id": ", ".join(f"vuls:{a['id']}" for a in cve["advisories"]) or f"vuls:{cve['cve']}",
            "package": name,
            "installed": installed,
            "fixed": fixed,
        })
        return None

    if not KERNEL_RE.match(name):
        return fixed

    # A kernel advisory whose fix sits on a different upstream major.minor
    # belongs to another kernel stream: Vuls matches UEK8 (6.12) advisories
    # against a UEK7 (5.15) host. Running as well as installed, because a host
    # can have a newer kernel installed and not yet booted into it.
    running = (top.get("runningKernel") or {}).get("release") or ""
    streams = {s for s in (major_minor(installed), major_minor(running)) if s}
    if major_minor(fixed) in streams:
        return fixed

    drops.add("running-kernel", certname, {
        "certname": certname,
        "check_id": ", ".join(f"vuls:{a['id']}" for a in cve["advisories"]) or f"vuls:{cve['cve']}",
        "package": name,
        "installed": installed,
        "running": running,
        "fixed": fixed,
    })
    return None


def check_name(source_packages, advisory_id, distro):
    """What PE shows in its grouped list.

    Named by the source packages, because "Oracle: ELSA-2026-67165" means
    nothing until it is looked up. The ID stays: several advisories can share a
    package. Identical on every host in a push, which is what PE's grouping
    needs, since the package set is the union across the whole run.
    """
    shown = sorted(source_packages)
    label = ", ".join(shown[:3])
    if len(shown) > 3:
        label += f" +{len(shown) - 3} more"
    if not label:
        return f"{distro} {advisory_id}".strip()
    return f"{label}: {distro} {advisory_id}".strip()


def reduce_cve(cve_id, entry, advisory_text):
    """Strip a scanned CVE to what the findings file needs.

    Seven vendors' write-ups, every reference URL and the UEK changelog are
    ninety-nine per cent of the bytes and none of the content. Advisory text is
    interned by ID, because the same kernel changelog is attached to every one
    of the four thousand CVEs the advisory closes.
    """
    score, cvss_version, vector, content = best_content(entry.get("cveContents") or {})
    advisories = []
    for advisory in entry.get("distroAdvisories") or []:
        advisory_id = advisory.get("advisoryID")
        if not advisory_id:
            continue
        advisories.append({"id": advisory_id, "severity": advisory.get("severity", "")})
        advisory_text.setdefault(advisory_id, (advisory.get("description") or "")[:DESCRIPTION_CAP])
    confidences = entry.get("confidences") or []
    return {
        "cve": cve_id,
        "affected": [
            {
                "name": a.get("name", ""),
                "fixedIn": a.get("fixedIn", ""),
                "notFixedYet": bool(a.get("notFixedYet")),
                "fixState": a.get("fixState", ""),
            }
            for a in entry.get("affectedPackages") or []
        ],
        "advisories": advisories,
        "confidence": max((c.get("score") or 0 for c in confidences), default=0),
        "methods": sorted({c.get("detectionMethod", "") for c in confidences} - {""}),
        "score": score,
        "cvss_version": cvss_version,
        "vector": vector,
        "source_link": content.get("sourceLink", ""),
        "summary": (content.get("summary") or "")[:DESCRIPTION_CAP],
        "kev": bool(entry.get("kevs")),
    }


def result_family(path):
    """The OS family, from the head of the file, without reading the whole thing.

    Vuls writes family near the start, well inside the first read. Needed before
    streaming because Windows results are shaped differently enough to want
    their own path, and a Windows result is small enough not to need streaming.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096).decode("utf-8", "replace")
    except OSError:
        return ""
    match = re.search(r'"family"\s*:\s*"([^"]*)"', head)
    return match.group(1) if match else ""


# A CVE Microsoft closes with a setting rather than a KB. ADV advisories don't
# need listing, because guidance with no KB is what an ADV is.
OPT_IN_CVES = {"CVE-2013-3900"}


def opt_in_setting(advisory_id):
    return advisory_id.startswith("ADV") or advisory_id in OPT_IN_CVES


def windows_solution(cve_id, kbs, product):
    if kbs:
        return f"Apply {', '.join(kbs)} to {product}."
    if opt_in_setting(cve_id):
        return (f"Microsoft has published no KB for {cve_id}. The mitigation is a "
                "configuration change; see the advisory for the setting it names.")
    return (f"The feed names no KB for {cve_id} and doesn't say whether a patch or a "
            "setting closes it. Check the advisory.")


def parse_windows(path, drops):
    """A Windows result. Grouped by KB, the way Linux is grouped by advisory.

    Windows fixes are not on the package: `affectedPackages` carries the product
    with no `fixedIn`, and the KB that closes the CVE sits at CVE level in
    `windowsKBFixedIns`. Run through the Linux path every Windows finding is
    dropped as unfixed and the host publishes a confident zero.

    CVEs with no KB are kept rather than dropped, which looks like an exception
    to the unfixed filter and is not. On Windows "Not fixed yet" usually means
    the mitigation is an opt-in setting rather than a patch: ADV190023 is LDAP
    signing, CVE-2013-3900 is a WinVerifyTrust registry value. Something can be
    done about those, which is the whole test the unfixed filter applies.

    Usually is not always. CVE-2022-37966 has no KB in the feed and is not an
    opt-in setting, so only opt_in_setting() may claim a configuration change.
    """
    certname = os.path.basename(path)[: -len(".json")]
    with open(path, "rb") as handle:
        result = json.load(handle)
    if isinstance(result, list):
        result = result[0]

    certname = result.get("serverName") or certname
    errors = list(result.get("errors") or [])
    host = dict(EMPTY_HOST, **{
        "ipaddress": (result.get("ipv4Addrs") or [""])[0],
        "os_family": result.get("family", ""),
        "os_release": result.get("release", ""),
        "collection": "server-mode",
        "status": "scanned" if not errors else "partial",
        "authenticated": True,
        "scan_start": result.get("scannedAt", ""),
        "scan_end": result.get("reportedAt", "") or result.get("scannedAt", ""),
        "errors": errors,
        "warnings": list(result.get("warnings") or []),
    })

    per_check = {}
    for cve_id, entry in (result.get("scannedCves") or {}).items():
        kbs = [str(k) for k in (entry.get("windowsKBFixedIns") or []) if k]
        score, cvss_version, vector, content = best_content(entry.get("cveContents") or {})
        confidence = max((c.get("score") or 0 for c in entry.get("confidences") or []), default=0)
        products = sorted({a.get("name", "") for a in entry.get("affectedPackages") or []} - {""})
        product = products[0] if products else result.get("release", "Windows")

        check_id = f"vuls:{kbs[0]}" if kbs else f"vuls:{cve_id}"
        bucket = per_check.setdefault(check_id, {
            "cves": set(), "packages": {}, "sources": set(), "confidence": 0, "methods": set(),
            "score": 0.0, "cvss_version": "", "cvss_vector": "", "vendor_severity": "",
            "description": "", "references": set(), "kev": False, "kbs": kbs,
            "product": product, "fixable": bool(kbs), "opt_in": not kbs and opt_in_setting(cve_id),
            "name": f"{kbs[0]}: {product}" if kbs else f"{cve_id}: {product}",
            "solution": windows_solution(cve_id, kbs, product),
        })
        bucket["cves"].add(cve_id)
        bucket["confidence"] = max(bucket["confidence"], confidence)
        bucket["kev"] = bucket["kev"] or bool(entry.get("kevs"))
        if score > bucket["score"]:
            bucket["score"] = score
            bucket["cvss_version"] = cvss_version
            bucket["cvss_vector"] = vector
        if content.get("sourceLink"):
            bucket["references"].add(content["sourceLink"])
        if not bucket["description"]:
            bucket["description"] = (content.get("summary") or "")[:DESCRIPTION_CAP]

    return certname, host, per_check


def parse_result(path, drops):
    """One Vuls result file. Returns (certname, host block, per-check findings)."""
    # Vuls names each file after serverName, which the scan config sets to the
    # certname. It is needed for drop samples before the file has been read.
    certname = os.path.basename(path)[: -len(".json")]
    reduced = []
    advisory_text = {}

    def on_cve(cve_id, stream):
        entry = stream.value()
        affected = entry.get("affectedPackages") or []
        if not any(a.get("fixedIn") and not a.get("notFixedYet") for a in affected):
            for a in affected:
                drops.add("unfixed", certname, {
                    "certname": certname, "cve": cve_id, "package": a.get("name", ""),
                    "fix_state": a.get("fixState", ""),
                })
            return
        reduced.append(reduce_cve(cve_id, entry, advisory_text))

    try:
        top = read_result(path, on_cve)
    except (OSError, ValueError, RecursionError) as err:
        return certname, dict(EMPTY_HOST, status="partial",
                              errors=[f"result file could not be read: {err}"]), {}

    certname = top.get("serverName") or certname
    packages = top.get("packages") or {}
    src_index = {}
    for src in (top.get("SrcPackages") or {}).values():
        for binary in src.get("binaryNames") or []:
            src_index[binary] = src.get("name") or binary

    reported = top.get("reportedAt") or ""
    unreported = reported.startswith("0001-01-01")
    errors = list(top.get("errors") or [])
    warnings = list(top.get("warnings") or [])
    if unreported:
        errors.append("vuls report has not run against this result; no CVE data")

    host = dict(EMPTY_HOST, **{
        "ipaddress": (top.get("ipv4Addrs") or [""])[0],
        "os_family": top.get("family", ""),
        "os_release": top.get("release", ""),
        "collection": SCAN_MODE.get(top.get("scanMode", ""), top.get("scanMode", "")),
        "status": "scanned" if not errors else "partial",
        "authenticated": True,
        "scan_start": top.get("scannedAt", ""),
        "scan_end": top.get("scannedAt", "") if unreported else reported,
        "errors": errors,
        "warnings": warnings,
    })

    # check_id -> the pieces both the check block and its finding need.
    per_check = {}

    for cve in reduced:
        cve_id = cve["cve"]
        kept = {}
        for affected in cve["affected"]:
            fixed = keep_package(affected, packages, top, certname, cve, drops)
            if fixed:
                kept[affected["name"]] = fixed
        if not kept:
            continue

        score, cvss_version, vector = cve["score"], cve["cvss_version"], cve["vector"]
        confidence, methods, kev = cve["confidence"], cve["methods"], cve["kev"]

        if cve["advisories"]:
            targets = [(f"vuls:{a['id']}", a) for a in cve["advisories"]]
        else:
            targets = [(f"vuls:{cve_id}", None)]

        for check_id, advisory in targets:
            bucket = per_check.setdefault(check_id, {
                "cves": set(), "packages": {}, "sources": set(), "confidence": 0,
                "methods": set(), "score": 0.0, "cvss_version": "", "cvss_vector": "",
                "vendor_severity": "", "description": "", "references": set(), "kev": False,
            })
            bucket["cves"].add(cve_id)
            bucket["confidence"] = max(bucket["confidence"], confidence)
            bucket["methods"].update(methods)
            bucket["kev"] = bucket["kev"] or kev
            if score > bucket["score"]:
                bucket["score"] = score
                bucket["cvss_version"] = cvss_version
                bucket["cvss_vector"] = vector
            if cve["source_link"]:
                bucket["references"].add(cve["source_link"])
            if advisory:
                bucket["vendor_severity"] = advisory.get("severity", "") or bucket["vendor_severity"]
                if not bucket["description"]:
                    bucket["description"] = advisory_text.get(advisory["id"], "")
            elif not bucket["description"]:
                bucket["description"] = cve["summary"]
            for name, fixed in kept.items():
                bucket["packages"][name] = {
                    "name": name,
                    "arch": (packages.get(name) or {}).get("arch", ""),
                    "installed": installed_version(packages, name) or "",
                    # Verbatim, epoch and all. Stripping it made the evidence
                    # read "10.1.0-17.el9_8.5 is older than 7.2.0-43.el9",
                    # which is exactly backwards: the epoch was the difference.
                    "fixed": fixed,
                }
                bucket["sources"].add(source_of(name, src_index))

    return certname, host, per_check


def build(results_path, config_path, windows_path):
    drops = Drops()
    hosts = {}
    checks = {}
    findings = []
    unmapped = []

    expected = set(expected_servers(config_path, windows_path))
    seen = set()
    # A check's name comes from the source packages seen across every host, so
    # it can only be settled once they have all been read.
    check_sources = {}
    check_distro = {}
    check_names = {}
    check_solutions = {}

    for filename in sorted(os.listdir(results_path)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(results_path, filename)
        try:
            if result_family(path) == "windows":
                certname, host, per_check = parse_windows(path, drops)
            else:
                certname, host, per_check = parse_result(path, drops)
        except (OSError, ValueError, MemoryError) as err:
            log(f"{filename}: {err}")
            continue

        seen.add(certname)
        if expected and certname not in expected:
            unmapped.append({"identifier": certname, "collection": host.get("collection", ""),
                             "findings": len(per_check)})
            continue
        hosts[certname] = host

        for check_id, bucket in per_check.items():
            advisory_id = check_id.split(":", 1)[1]
            check_sources.setdefault(check_id, set()).update(bucket["sources"])
            check_distro.setdefault(check_id, host["os_family"].capitalize())
            if bucket.get("name"):
                check_names[check_id] = bucket["name"]
            if bucket.get("solution"):
                check_solutions[check_id] = bucket["solution"]
            existing = checks.get(check_id)
            candidate = {
                "name": "",
                "summary": bucket["description"],
                "solution": "",
                "fix_type": ("vendor-fix" if bucket.get("fixable", True)
                             else "mitigation" if bucket.get("opt_in") else "none-available"),
                # Derived from the score, so the two never disagree in the
                # console. The vendor's own rating is a different judgement
                # (Oracle calls a 5.6 CVSS important) and is kept beside it.
                "severity": severity_of(bucket["score"]),
                "vendor_severity": VENDOR_SEVERITY.get(bucket["vendor_severity"].upper(), ""),
                "cvss_score": round(bucket["score"], 1),
                "cvss_version": bucket["cvss_version"],
                "cvss_vector": bucket["cvss_vector"],
                "cves": sorted(bucket["cves"]),
                "references": sorted(bucket["references"])[:REFERENCE_CAP],
                "kev": bucket["kev"],
            }
            if existing is None:
                checks[check_id] = candidate
            else:
                # Same advisory on another host: union what can differ, keep the
                # worst score. Check-level fields must read the same everywhere.
                existing["cves"] = sorted(set(existing["cves"]) | set(candidate["cves"]))
                existing["kev"] = existing["kev"] or candidate["kev"]
                if candidate["cvss_score"] > existing["cvss_score"]:
                    existing.update({k: candidate[k] for k in
                                     ("cvss_score", "cvss_version", "cvss_vector", "severity")})

            packages = sorted(bucket["packages"].values(), key=lambda p: p["name"])
            kbs = bucket.get("kbs") or []
            if kbs:
                evidence = f"{bucket.get('product', 'Windows')} is missing {', '.join(kbs)}."
            elif bucket.get("fixable", True):
                evidence = "\n".join(
                    f"{p['name']} {p['installed'] or '(not installed)'} is older than {p['fixed']}"
                    for p in packages
                )
            elif bucket.get("opt_in"):
                evidence = (f"{bucket.get('product', 'Windows')}: no KB published. Microsoft "
                            "documents this as an opt-in setting rather than a patch, so the "
                            "mitigation is a configuration change.")
            else:
                evidence = f"{bucket.get('product', 'Windows')}: the feed names no KB for this."
            if bucket["methods"]:
                evidence += f"\nDetected by {', '.join(sorted(bucket['methods']))}."
            findings.append({
                "certname": certname,
                "check_id": check_id,
                "detected_at": host["scan_end"],
                "confidence": bucket["confidence"],
                "state": "fixable" if bucket.get("fixable", True) else "unfixed",
                "port": None,
                "evidence": evidence,
                "packages": packages,
                "kbs": kbs,
            })

    # Configured but no result file: Vuls writes nothing for a host it could not
    # reach, and a host that stops being scanned must not read as a clean one.
    for certname in sorted(expected - seen):
        hosts[certname] = dict(EMPTY_HOST, status="unreachable", errors=[
            "configured for scanning but the run produced no result"
        ])

    for check_id, check in checks.items():
        advisory_id = check_id.split(":", 1)[1]
        sources = check_sources.get(check_id, set())
        check["name"] = check_names.get(check_id) or check_name(sources, advisory_id, check_distro.get(check_id, ""))
        check["solution"] = check_solutions.get(check_id) or (
            f"Update {', '.join(sorted(sources))} to the version {advisory_id} ships."
            if sources else f"Apply {advisory_id}."
        )

    return hosts, checks, findings, drops, unmapped


def scanner_version(results_path):
    for filename in sorted(os.listdir(results_path)):
        if filename.endswith(".json"):
            try:
                with open(os.path.join(results_path, filename), "rb") as handle:
                    head = handle.read(4096).decode("utf-8", "replace")
                match = re.search(r'"scannedVersion":\s*"([^"]+)"', head)
                if match:
                    return match.group(1)
            except OSError:
                continue
    return ""


def main():
    parser = argparse.ArgumentParser(description="Build the vuls findings file from a Vuls run.")
    parser.add_argument("--results-dir", default="/var/lib/vuls/results")
    parser.add_argument("--config", default="/etc/vuls/config.toml")
    parser.add_argument("--windows-config", default="/etc/vuls/windows.json")
    parser.add_argument("--database", default="/var/lib/vuls/vuls.db")
    parser.add_argument("--complete-file", default="/var/lib/vuls/last-complete-run")
    parser.add_argument("--out", default="/var/lib/soundwave/cassettes/vuls.json")
    args = parser.parse_args()

    # No finished run is not a failure: the previous cassette stays in place,
    # and Soundwave's staleness alert says how old it is.
    results_path = complete_run(args.complete_file)
    if results_path is None:
        log(f"no complete Vuls run recorded in {args.complete_file}; {args.out} left as it was")
        return 0

    # What the run was asked to scan, kept beside it by the vuls module. This runs
    # nightly against a run up to a week old, and today's configuration would
    # report a node added since as unreachable in a run that never tried it.
    scanned = os.path.join(results_path, ".scanned")
    config = os.path.join(scanned, "config.toml")
    windows = os.path.join(scanned, "windows.json")
    if not os.path.isfile(config):
        config = args.config
    if not os.path.isfile(windows):
        windows = args.windows_config

    hosts, checks, findings, drops, unmapped = build(results_path, config, windows)

    # `Z` rather than isoformat's `+00:00`, because the findings API names
    # every timestamp of its own in `Z` and does not reach inside a producer's
    # feed to normalise it, so the one spelled differently was this one. And
    # null when the database cannot be read: "" read as a blank fetch time,
    # which is not what an unreadable file means.
    try:
        fetched = datetime.fromtimestamp(os.path.getmtime(args.database), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        fetched = None

    document = {
        "schema": SCHEMA,
        "cassette": {
            "name": CASSETTE,
            "scanner": "vuls",
            "scanner_version": scanner_version(results_path),
            "feed": {"name": "vuls-nightly-db", "version": "0", "fetched_at": fetched},
            "run_id": os.path.basename(results_path),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            # Vuls' detection confidence runs 0-100 (an OVAL
            # match is 100, a CPE guess 10), and each finding's confidence is
            # the highest of those. The findings API draws its bands at 70 and only on a
            # scale that is declared or assumed to be this one.
            "confidence_scale": {"min": 0, "max": 100, "kind": "vuls-confidence"},
        },
        "hosts": hosts,
        "checks": checks,
        "findings": findings,
        "dropped": drops.to_list(DROP_REASONS),
        "unmapped": unmapped,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    tmp = f"{args.out}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, args.out)

    scanned = sum(1 for h in hosts.values() if h["status"] == "scanned")
    dropped_total = sum(d["findings"] for d in document["dropped"])
    log(f"{len(hosts)} hosts ({scanned} scanned), {len(checks)} checks, "
        f"{len(findings)} findings, {dropped_total} dropped, run {document['cassette']['run_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
