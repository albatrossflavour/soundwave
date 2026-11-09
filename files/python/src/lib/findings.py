"""
The scanner-neutral findings file: building one, reading them, merging them.

Soundwave never parses a scanner. Each cassette writes one of these files and
Soundwave merges every file in the cassette directory into a single push. A
third scanner is another cassette, not another integration.

The format is docs/findings-file.md. Everything here is the code side of that
document; if the two disagree the document is what other people build against.
"""

import json
import logging
import os
import tempfile
from datetime import datetime, timezone

logger = logging.getLogger("transformer")

SCHEMA = "puppet-findings/1"

# Every host block carries the same keys whether or not the scan reached it, so
# a consumer never has to test for their presence.
EMPTY_HOST = {
    "ipaddress": "", "os_family": "", "os_release": "", "collection": "",
    "status": "unknown", "authenticated": False, "scan_start": "", "scan_end": "",
    "errors": [], "warnings": [],
}

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# How bad a per-host package state is, when two result rows for one check
# disagree. They should not, but a scanner that reported the same check twice
# has already shown it will, and the pessimistic answer is the safe one.
_STATE_ORDER = {"": 0, "fixable": 1, "pro-only": 2, "unfixed": 3}


def _fold_finding(existing, incoming):
    """Merge a repeated finding into the one already held.

    Evidence accumulates because that is the whole reason the rows differ;
    everything else takes the answer that understates least.
    """
    extra = (incoming.get("evidence") or "").strip()
    held = (existing.get("evidence") or "").strip()
    # Compared as whole pieces rather than as a substring: one result row's
    # evidence is regularly a prefix of another's ("group1" inside "group14"),
    # and a substring test silently drops the longer one.
    if extra and extra not in held.split("\n\n"):
        existing["evidence"] = f"{held}\n\n{extra}".strip()

    # A null confidence means the scanner does not rate its findings, so it
    # cannot be compared with a number and must not be read as zero.
    rated = [c for c in (existing.get("confidence"), incoming.get("confidence")) if c is not None]
    existing["confidence"] = max(rated) if rated else None

    if _STATE_ORDER.get(incoming.get("state", ""), 0) > _STATE_ORDER.get(existing.get("state", ""), 0):
        existing["state"] = incoming.get("state", "")

    seen = {p.get("name") for p in existing.get("packages") or []}
    for package in incoming.get("packages") or []:
        if package.get("name") not in seen:
            existing.setdefault("packages", []).append(package)
            seen.add(package.get("name"))

    for kb in incoming.get("kbs") or []:
        if kb not in (existing.get("kbs") or []):
            existing.setdefault("kbs", []).append(kb)


# How much a host status is worth when two cassettes disagree about the same
# host. Reaching it beats half-reaching it beats not reaching it.
_STATUS_ORDER = {"scanned": 4, "partial": 3, "auth_failed": 2, "unreachable": 1, "skipped": 1, "unknown": 0}


def _status_rank(status):
    return _STATUS_ORDER.get(status, 0)


def severity_of(score):
    """The PE severity enum for a CVSS-style 0-10 score."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def iso_to_epoch(text):
    """An ISO-8601 timestamp as epoch seconds, or None. Accepts Z and offsets.

    Go marshals an unset time as 0001-01-01T00:00:00Z and Vuls results are full
    of them, so that parses cleanly to a large negative number. Published as a
    scan end it reads as a host last scanned in year one, which fires every
    staleness alert at once and says nothing. Nothing before the epoch is a
    scan time, so treat the lot as absent.
    """
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    epoch = int(parsed.timestamp())
    return epoch if epoch > 0 else None


# A scan that has not happened yet is a clock, not a scan. Tolerance is for
# ordinary drift between a scanner host and this one, not for a timezone.
CLOCK_SKEW_TOLERANCE = 60


def clock_skew(hosts, now=None):
    """Seconds by which the newest scan end is in the future, or 0.

    Every timestamp in this format comes from somebody else's clock, and a
    cassette copies its scanner's rendering rather than re-deriving it.
    The openvas cassette passes Greenbone's `<end>` through untouched, so it is correct
    only because that container happens to run UTC; point it at a Greenbone
    running in a local timezone and it will emit local time wearing a `Z` and
    launder it into the format with nothing saying so.

    That is not hypothetical. The same mistake was live on the PE leg of this
    engine for months, rendering local time and stamping a literal `Z` on it,
    and it survived because it was consistently wrong: ordering still worked,
    so nothing looked broken. A future scan end is the one signature that
    cannot be explained away, so it gets reported rather than clamped.
    """
    reference = now if now is not None else int(datetime.now(timezone.utc).timestamp())
    ends = [iso_to_epoch((host or {}).get("scan_end", "")) for host in (hosts or {}).values()]
    ends = [e for e in ends if e]
    if not ends:
        return 0
    skew = max(ends) - reference
    return skew if skew > CLOCK_SKEW_TOLERANCE else 0


class Document:
    """One cassette's findings file, under construction."""

    def __init__(self, cassette, scanner, scanner_version=None, feed=None, run_id="", confidence_scale=None):
        self.cassette = cassette
        # what this cassette's confidence numbers are out of,
        # {min, max, kind}. The findings API draws its bands at 70, which only means
        # something on 0-100, and refuses to draw them on any other declared
        # scale rather than counting every finding low.
        self.confidence_scale = confidence_scale
        self.scanner = scanner
        # None when the scanner does not report one, and written as null: an
        # empty string or object reads as "reported, and blank", which the findings API
        # keeps apart from "not reported".
        self.scanner_version = scanner_version or None
        self.feed = feed or None
        self.run_id = run_id
        self.hosts = {}
        self.checks = {}
        self.findings = []
        self._findings_by_key = {}
        self.drops = Drops()
        self.unmapped = []

    def host(self, certname, **fields):
        self.hosts[certname] = dict(EMPTY_HOST, **fields)
        return self.hosts[certname]

    def check(self, check_id, **fields):
        """Record a check, keeping the worst score when hosts disagree.

        Check-level fields have to read the same on every host, so the only
        merge here is a union of CVEs and the higher score winning.
        """
        existing = self.checks.get(check_id)
        if existing is None:
            self.checks[check_id] = fields
            return fields
        existing["cves"] = sorted(set(existing.get("cves", [])) | set(fields.get("cves", [])))
        existing["kev"] = existing.get("kev", False) or fields.get("kev", False)
        if fields.get("cvss_score", 0) > existing.get("cvss_score", 0):
            for key in ("cvss_score", "cvss_version", "cvss_vector", "severity"):
                if key in fields:
                    existing[key] = fields[key]
        return existing

    def finding(self, **fields):
        """Record a finding, folding a repeat of the same check on the same port.

        The format promises one finding per certname, check and port. A scanner
        does not necessarily oblige: Greenbone returns a result row per piece of
        evidence, several per NVT per host, naming the offending URLs for a
        directory listing or the exact algorithms for a cipher check. Measured
        on the lab, 595 such groups covered 2,582 of the openvas cassette's 3,144 findings.

        Those are one finding carrying several pieces of evidence rather than
        several findings, and left apart they make a consumer count one weakness
        many times over. Folding here rather than in a cassette means the rule
        holds for every cassette that writes through this class, which is what
        stops the next one having to rediscover it.
        """
        key = (fields.get("certname", ""), fields.get("check_id", ""), fields.get("port"))
        existing = self._findings_by_key.get(key)
        if existing is None:
            self._findings_by_key[key] = fields
            self.findings.append(fields)
            return fields
        _fold_finding(existing, fields)
        return existing

    def to_dict(self):
        cassette = {
            "name": self.cassette,
            "scanner": self.scanner,
            "scanner_version": self.scanner_version,
            "feed": self.feed,
            "run_id": self.run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        # Absent rather than null when undeclared, so the shape of a cassette
        # that has not said is exactly the shape it always was.
        if self.confidence_scale is not None:
            cassette["confidence_scale"] = self.confidence_scale
        return {
            "schema": SCHEMA,
            "cassette": cassette,
            "hosts": self.hosts,
            "checks": self.checks,
            "findings": self.findings,
            "dropped": self.drops.to_list(),
            "unmapped": self.unmapped,
        }

    def write(self, path):
        """Replace the file in one step, so a reader never sees half of it."""
        directory = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{self.cassette}.", suffix=".tmp")
        with os.fdopen(fd, "w") as handle:
            json.dump(self.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
        scanned = sum(1 for h in self.hosts.values() if h["status"] == "scanned")
        logger.info(
            f"{self.cassette}: {len(self.hosts)} hosts ({scanned} scanned), "
            f"{len(self.checks)} checks, {len(self.findings)} findings, "
            f"{self.drops.total()} dropped -> {path}"
        )


SAMPLE_CAP = 10

# The correlation rule this engine implements. Named because the `correlated`
# record carries it, so a sample can be read against the rule that produced it
# rather than against whatever the code happens to do today.
CORRELATION_RULE = "cve-subject-fix-type"


def correlation_subject(finding):
    """What a finding is about, for deciding whether two describe one thing.

    A CVE alone is not enough. Greenbone reports CVE-2023-48795 twice on one
    host, once as an OpenSSH version check and once as an SSH protocol check,
    and a scanner covering several services reports one CVE against each of
    them. The subject is what separates those.

    Packages first, then KBs, then the port. A package finding and a service
    finding for one CVE are different work and must not land on the same
    subject, which is why the kind is part of the value rather than implied.
    """
    packages = tuple(sorted(p.get("name", "") for p in (finding.get("packages") or []) if p.get("name")))
    if packages:
        return ("package",) + packages
    kbs = tuple(sorted(kb for kb in (finding.get("kbs") or []) if kb))
    if kbs:
        return ("kb",) + kbs
    return ("port", finding.get("port") or "")


def _real_cves(check):
    """The check's CVE identifiers, ignoring anything that is not one.

    The vuls cassette puts Microsoft advisory IDs (`ADV190023`) in `cves`, so a plain read
    of the field would correlate on a string that is not a CVE and does not
    mean the same thing across scanners.
    """
    return [c for c in (check.get("cves") or []) if isinstance(c, str) and c.startswith("CVE-")]


def correlate(documents, exceptions=()):
    """Findings from any number of cassettes that describe the same weakness.

    Grouped by `(certname, CVE, subject, fix_type)`. Every part earns its place:
    the certname because a group can never span hosts, which is also what keeps
    this a per-host operation rather than an estate-sized one; the subject
    because a CVE is reported against several services and packages; the fix
    type because a patch and a mitigation for one CVE are two pieces of work
    and collapsing them is how a console offers a button that cannot help.

    **A check with no CVE does not correlate.** It passes through as itself.
    Measured on the lab, grouping them on an absent CVE joined "OpenSSH
    Unspecified Vulnerability" to "OpenSSL End of Life Detection" because both
    had no CVE, the same port bucket and the same fix type. Failing to
    correlate has to degrade rather than corrupt.

    **No transitive closure.** Groups are formed by key and never chained
    through a shared member. One Oracle check here carries 42 CVEs, and
    chaining would pull unrelated kernel errata into a single blob.

    `exceptions` is a list of check-ID pairs known to describe different work
    despite sharing a key. A group containing both members of a pair is left
    uncorrelated rather than split cleverly, because the pair is the evidence
    that the key cannot tell them apart.
    """
    banned = {frozenset(pair) for pair in exceptions}
    groups = {}
    for document in documents:
        cassette = (document.get("cassette") or {}).get("name") or "unknown"
        checks = document.get("checks") or {}
        for finding in document.get("findings") or []:
            check = checks.get(finding.get("check_id", ""))
            if check is None:
                continue
            subject = correlation_subject(finding)
            for cve in _real_cves(check):
                key = (finding.get("certname", ""), cve, subject, check.get("fix_type", ""))
                groups.setdefault(key, []).append((cassette, finding.get("check_id", "")))

    record = Correlations()
    for key in sorted(groups, key=lambda k: (k[0], k[1], k[2], k[3])):
        members = sorted(set(groups[key]))
        check_ids = {check_id for _, check_id in members}
        if len(check_ids) < 2:
            continue
        excepted = next((pair for pair in banned if pair <= check_ids), None)
        if excepted:
            record.excepted(key, sorted(excepted))
            continue
        record.add(key, members)
    return record


class Correlations:
    """What correlation joined, in the shape `dropped` already uses.

    A rule that quietly starts merging things that are not the same is worse
    than the duplicates it was written to remove, and the only defence that
    survives contact with a scanner nobody has seen yet is publishing what it
    did. Counts so a change shows up in metrics, a bounded sample so the rule
    can be checked without re-running a scan.
    """

    def __init__(self):
        self.groups = 0
        self.findings = 0
        self.cross_cassette = 0
        self.hosts = set()
        self.samples = []
        self.exceptions_applied = 0
        self.exception_samples = []

    def add(self, key, members):
        certname, cve, subject, fix_type = key
        self.groups += 1
        self.findings += len(members)
        self.hosts.add(certname)
        if len({cassette for cassette, _ in members}) > 1:
            self.cross_cassette += 1
        if len(self.samples) < SAMPLE_CAP:
            self.samples.append({
                "certname": certname,
                "cve": cve,
                "subject": ":".join(subject),
                "fix_type": fix_type,
                "joined": [{"cassette": c, "check_id": i} for c, i in members],
            })

    def excepted(self, key, pair):
        self.exceptions_applied += 1
        if len(self.exception_samples) < SAMPLE_CAP:
            self.exception_samples.append({
                "certname": key[0], "cve": key[1], "checks": pair,
            })

    def to_dict(self):
        return {
            "rule": CORRELATION_RULE,
            "groups": self.groups,
            "findings": self.findings,
            "cross_cassette_groups": self.cross_cassette,
            "hosts": len(self.hosts),
            "sample": self.samples,
            "exceptions_applied": self.exceptions_applied,
            "exception_sample": self.exception_samples,
        }


# A composed set larger than either of these
# is left as it was and counted. The reason is the one transitive closure was
# ruled out for: one Oracle kernel advisory carries 42 CVEs, and chaining
# through it would join unrelated errata into one record. Nothing on the lab
# comes near either figure; the largest set is three findings carrying three
# CVEs.
COMPOSE_MAX_FINDINGS = 5
COMPOSE_MAX_CVES = 10

# The fields a contributor entry carries, which is what the findings API slices it to.
CONTRIBUTOR_FIELDS = ("name", "check_id", "cvss_score", "confidence", "fix_type", "detected_at")


def composable_sets(documents, exceptions=()):
    """The findings that describe one weakness, as sets to compose.

    Built on `correlate`'s groups. A finding usually carries several CVEs, so
    it can sit in several groups: on the lab Greenbone's two pip advisory parts
    sit in three each. Composing group by group would hand VR three records
    carrying the same CVEs, so the groups that share a finding are one set.
    That is closure, which `correlate` refuses, and the cap is what makes it
    safe here: a set over COMPOSE_MAX_FINDINGS findings or COMPOSE_MAX_CVES
    CVEs is returned as capped and left alone, so a blob cannot form without
    being counted.

    Returns (sets, capped), each a list of member lists. A member is
    (cassette, finding, check), with the finding and check being the same
    dicts the documents hold, so a caller can recognise them by identity.
    """
    banned = {frozenset(pair) for pair in exceptions}
    entries = []
    groups = {}
    for document in documents:
        cassette = (document.get("cassette") or {}).get("name") or "unknown"
        checks = document.get("checks") or {}
        for finding in document.get("findings") or []:
            check = checks.get(finding.get("check_id", ""))
            if check is None:
                continue
            index = len(entries)
            entries.append((cassette, finding, check))
            subject = correlation_subject(finding)
            for cve in _real_cves(check):
                key = (finding.get("certname", ""), cve, subject, check.get("fix_type", ""))
                groups.setdefault(key, []).append(index)

    parent = list(range(len(entries)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for key in sorted(groups):
        members = groups[key]
        check_ids = {entries[i][1].get("check_id", "") for i in members}
        if len(check_ids) < 2 or any(pair <= check_ids for pair in banned):
            continue
        for i in members[1:]:
            parent[find(i)] = find(members[0])

    by_root = {}
    for i in range(len(entries)):
        by_root.setdefault(find(i), []).append(i)

    sets, capped = [], []
    for root in sorted(by_root):
        members = [entries[i] for i in by_root[root]]
        if len(members) < 2:
            continue
        cves = {c for _, _, check in members for c in _real_cves(check)}
        if len(members) > COMPOSE_MAX_FINDINGS or len(cves) > COMPOSE_MAX_CVES:
            capped.append(members)
        else:
            sets.append(members)
    return sets, capped


def _cvss_version_rank(check):
    try:
        return float(check.get("cvss_version") or 0)
    except (TypeError, ValueError):
        return 0.0


def _narrowest(members):
    """The member whose check carries the fewest CVEs, which is the composition rule for
    the score: the narrow check is the per-CVE record and the wide one is a
    roll-up carrying the worst member of its set. Ties go to the higher CVSS
    version, then the cassette name, so the choice is the same on every run."""
    return min(members, key=lambda m: (len(_real_cves(m[2])), -_cvss_version_rank(m[2]), m[0], m[1].get("check_id", "")))


def _union(lists):
    seen, out = set(), []
    for items in lists:
        for item in items or []:
            key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else item
            if key not in seen:
                seen.add(key)
                out.append(item)
    return out


def contributors(members):
    """One entry per contributing finding: what each scanner said, as provenance.

    Kept per contributor rather than folded, because this is what keeps
    per-source freshness alive through composition: the openvas cassette runs at midnight
    and the vuls cassette at 02:15, and a composed record with a single `detected_at`
    lets a dead scanner hide inside a live finding.
    """
    return [
        {
            "name": cassette,
            "check_id": finding.get("check_id", ""),
            "cvss_score": check.get("cvss_score"),
            "confidence": finding.get("confidence"),
            "fix_type": check.get("fix_type"),
            "detected_at": finding.get("detected_at"),
        }
        for cassette, finding, check in sorted(members, key=lambda m: (m[0], m[1].get("check_id", "")))
    ]


def compose_finding(members):
    """One finding for the set, by the composition field rules.

    It keeps the narrowest member's check ID, so every field this finding does
    not carry resolves from a check that exists in the catalogue. Confidence is
    the highest, state the most pessimistic, packages and KBs the union,
    `detected_at` the newest, and each member's own values survive in
    `contributors`.
    """
    _, base, _ = _narrowest(members)
    finding = dict(base)
    rated = [f.get("confidence") for _, f, _ in members if f.get("confidence") is not None]
    finding["confidence"] = max(rated) if rated else None
    finding["state"] = max((f.get("state", "") for _, f, _ in members), key=lambda s: _STATE_ORDER.get(s, 0))
    finding["packages"] = _union(f.get("packages") for _, f, _ in members)
    finding["kbs"] = _union(f.get("kbs") for _, f, _ in members)
    detected = [f.get("detected_at") for _, f, _ in members if f.get("detected_at")]
    if detected:
        finding["detected_at"] = max(detected)
    finding["contributors"] = contributors(members)
    return finding


def _score_source(members):
    """The check whose score the composed record carries.

    The composition rule is per CVE: a CVE takes the score of the narrowest check that
    carries it, because the narrow check is the per-CVE record and the wide one
    is a roll-up carrying the worst of its set. A composed record carries
    several CVEs, so it takes the **highest** of those per-CVE scores, and no
    CVE in it is ever shown lower than its own best source says.

    Found on the lab before this shipped: taking the set's narrowest member for
    the whole record showed scipy at 5.5 while carrying CVE-2023-29824, which
    only Greenbone reports and scores 9.8. The design expected that CVE to form
    a group of its own, which it does only when a second scanner reports it.
    """
    best = None
    for cve in {c for _, _, check in members for c in _real_cves(check)}:
        carrying = [m for m in members if cve in _real_cves(m[2])]
        narrow = _narrowest(carrying)[2]
        if best is None or (narrow.get("cvss_score") or 0) > (best.get("cvss_score") or 0):
            best = narrow
    return best or _narrowest(members)[2]


def compose_check(members):
    """The check a composed finding is described by in VR, by the composition rules.

    Score, version and vector from `_score_source`, the highest per-CVE score,
    and the severity derived from that score rather than inherited. CVEs and references are the
    union, KEV is sticky, and the name and summary are the narrowest member's
    with every other member attributed after it.
    """
    cassette, finding, narrow = _narrowest(members)
    check = dict(narrow)
    check["cves"] = _union(c.get("cves") for _, _, c in members)
    check["references"] = _union(c.get("references") for _, _, c in members)
    check["kev"] = any(c.get("kev") for _, _, c in members)
    scored = _score_source(members)
    for field in ("cvss_score", "cvss_version", "cvss_vector"):
        check[field] = scored.get(field)
    check["severity"] = severity_of(scored.get("cvss_score") or 0)
    others = [(ca, f, c) for ca, f, c in members if f is not finding]
    also = "; ".join(f"{c.get('name', '')} ({ca} {f.get('check_id', '')})" for ca, f, c in others)
    summary = narrow.get("summary", "") or ""
    check["summary"] = f"{summary} Also reported as: {also}." if summary else f"Also reported as: {also}."
    return check


def compose_for_vr(documents, checks, findings, exceptions=()):
    """The merged set with every composable set replaced by one record, for VR.

    Across cassettes, because VR holds one transformer's data per node and a
    weakness two scanners both report should be one row there. Each composed
    record gets a check of its own, keyed `composed:<narrowest check>@<host>`,
    because its CVEs and summary are the set's rather than any one check's.

    Returns (checks, findings, stats). The inputs are not modified.
    """
    sets, capped = composable_sets(documents, exceptions)
    consumed = {id(f) for members in sets for _, f, _ in members}
    checks = dict(checks)
    kept = [f for f in findings if id(f) not in consumed]
    for members in sets:
        finding = compose_finding(members)
        check_id = f"composed:{finding['check_id']}@{finding.get('certname', '')}"
        checks[check_id] = compose_check(members)
        finding["check_id"] = check_id
        kept.append(finding)
    return checks, kept, _composition_stats(sets, capped)


def compose_document(document, exceptions=()):
    """One cassette with its own composable sets composed, for the findings API.

    Within the cassette only: the findings API keys every finding by
    the scanner that produced it, so a stale scanner cannot hide inside a fresh
    one, and a set spanning two cassettes has no single cassette to be pushed
    under. The composed finding keeps the narrowest member's check ID, which is
    in this cassette's catalogue, and carries `contributors`.

    Returns (document, stats). The input is not modified.
    """
    sets, capped = composable_sets([document], exceptions)
    if not sets:
        return document, _composition_stats(sets, capped)
    consumed = {id(f) for members in sets for _, f, _ in members}
    composed = dict(document)
    composed["findings"] = [f for f in document.get("findings") or [] if id(f) not in consumed]
    composed["findings"].extend(compose_finding(members) for members in sets)
    return composed, _composition_stats(sets, capped)


def _composition_stats(sets, capped):
    return {
        "sets": len(sets),
        "findings": sum(len(m) for m in sets),
        "cross_cassette_sets": sum(1 for m in sets if len({c for c, _, _ in m}) > 1),
        "capped_sets": len(capped),
    }


class Drops:
    """Filter counters, plus a bounded sample so a rule can be checked later."""

    def __init__(self):
        self.counts = {}
        self.reasons = {}
        self.hosts = {}
        self.samples = {}

    def add(self, filter_name, reason, certname, sample):
        self.counts[filter_name] = self.counts.get(filter_name, 0) + 1
        self.reasons[filter_name] = reason
        self.hosts.setdefault(filter_name, set()).add(certname)
        bucket = self.samples.setdefault(filter_name, [])
        if len(bucket) < SAMPLE_CAP:
            bucket.append(sample)

    def total(self):
        return sum(self.counts.values())

    def to_list(self):
        return [
            {
                "filter": name,
                "reason": self.reasons.get(name, ""),
                "findings": count,
                "hosts": len(self.hosts.get(name, ())),
                "sample": self.samples.get(name, []),
            }
            for name, count in sorted(self.counts.items())
        ]


def read_cassettes(directory):
    """Every findings file in the cassette directory, newest-written last.

    A file that will not parse is logged and skipped rather than failing the
    push: one broken cassette must not take the other's findings with it.
    """
    try:
        names = sorted(f for f in os.listdir(directory) if f.endswith(".json"))
    except OSError as err:
        logger.error(f"Cannot read cassette directory {directory}: {err}")
        return []

    loaded = []
    for name in names:
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError) as err:
            logger.error(f"Cassette {path} unreadable, its findings are missing from this push: {err}")
            continue
        if document.get("schema") != SCHEMA:
            logger.error(f"Cassette {path} is schema {document.get('schema')!r}, expected {SCHEMA!r}; skipped")
            continue
        loaded.append(document)
    return loaded


def merge(documents):
    """Merge every cassette into one set of hosts, checks and findings.

    Hosts union: a host both cassettes saw keeps both sets of findings, and the
    later scan end wins for the host block. Checks cannot collide, because
    check IDs are namespaced by source. Findings are concatenated.

    Status is merged separately from the rest of the block, best wins. One
    cassette reaching a host is enough to say it was reached, and tying that to
    whichever record happens to carry the later scan end would let a cassette
    that could not reach the host overwrite the one that did.
    """
    hosts = {}
    checks = {}
    findings = []
    for document in documents:
        for certname, host in (document.get("hosts") or {}).items():
            incoming = dict(EMPTY_HOST, **host)
            existing = hosts.get(certname)
            if existing is None:
                hosts[certname] = incoming
                continue
            best = max(existing.get("status", ""), incoming.get("status", ""), key=_status_rank)
            if (incoming.get("scan_end") or "") > (existing.get("scan_end") or ""):
                hosts[certname] = incoming
            hosts[certname]["status"] = best
        for check_id, check in (document.get("checks") or {}).items():
            if check_id in checks:
                logger.warning(f"Check {check_id} seen in more than one cassette; keeping the first")
                continue
            checks[check_id] = check
        findings.extend(document.get("findings") or [])
    return hosts, checks, findings


def to_vr(hosts, checks, findings, min_confidence=70):
    """The merged set as PE Vulnerability Remediation wants it.

    Returns (host records, scan date epoch). A host that was scanned and has no
    findings is sent with an empty list on purpose: VR replaces a transformer's
    data per node on each push, so a node left out of the push keeps whatever
    it had. Dropping clean hosts is how a patched node shows its old findings
    forever.

    min_confidence is the QoD floor, applied here rather than by a cassette.
    VR has nowhere to put a confidence, so a low-confidence finding there is
    indistinguishable from a certain one; the findings file keeps the whole
    tail for anything that can reason about it.

    A finding whose confidence is null or absent is not filtered. The scale is
    Greenbone's QoD and not every scanner has one: Nessus offers only booleans
    and Qualys nothing per detection, so a cassette for either would have every
    finding scored zero by a `.get(..., 0)` default and dropped in full, under
    a log line that reads exactly like the floor working normally. Absent means
    the scanner did not say, which is not the same as saying nothing is there.
    """
    by_certname = {}
    for certname, host in hosts.items():
        if host.get("status") not in ("scanned", "partial"):
            continue
        by_certname[certname] = {
            "hostname": certname,
            "ipaddress": host.get("ipaddress", ""),
            "vulnerabilities": [],
        }

    orphans = set()
    below = 0
    unscored = 0
    unrated = 0
    for finding in findings:
        confidence = finding.get("confidence")
        if confidence is None:
            unrated += 1
        elif confidence < min_confidence:
            below += 1
            continue
        certname = finding.get("certname", "")
        record = by_certname.get(certname)
        if record is None:
            orphans.add(certname)
            continue
        check = checks.get(finding.get("check_id", ""))
        if check is None:
            logger.warning(f"Finding on {certname} references unknown check {finding.get('check_id')!r}")
            continue
        # VR's schema will not take a finding with no CVSS version, and there is
        # no honest value to invent: 0.0 is a real CVSS score meaning no impact,
        # so scoring an unscored finding that way understates it rather than
        # leaving it out. Microsoft's ADV advisories are the case on this lab.
        # They stay in the cassette, where a consumer can see them.
        if not check.get("cvss_version"):
            unscored += 1
            continue
        record["vulnerabilities"].append({
            "name": check.get("name", ""),
            "summary": check.get("summary", "") or "No description available",
            "solution": _solution(check, finding),
            "severity": check.get("severity", "none"),
            "cvss_score": check.get("cvss_score", 0.0),
            "cvss_version": check.get("cvss_version", ""),
            "packages": [p.get("name", "") for p in finding.get("packages") or [] if p.get("name")],
            "cves": check.get("cves", []),
        })
    if below:
        logger.info(f"{below} finding(s) below confidence {min_confidence}, kept in the cassettes and not pushed")
    if unrated:
        # Counted rather than passed over in silence: a cassette that suddenly
        # stops reporting confidence looks identical to one whose scanner never
        # had the notion, and the floor is doing nothing for either.
        logger.info(f"{unrated} finding(s) carry no confidence and were not filtered: "
                    "the scanner does not express one, which is not the same as a zero")
    if unscored:
        logger.info(f"{unscored} finding(s) carry no CVSS score, kept in the cassettes and not pushed: "
                    "VR has nowhere to put one and 0.0 would read as no impact")
    if orphans:
        logger.warning(f"{len(orphans)} host(s) had findings but no host block, so they are not in the push")

    scan_ends = [iso_to_epoch(h.get("scan_end", "")) for h in hosts.values()]
    scan_ends = [e for e in scan_ends if e]
    scan_date = max(scan_ends) if scan_ends else int(datetime.now(timezone.utc).timestamp())
    return list(by_certname.values()), scan_date


# What to say about a fix type VR cannot represent. Its only remediation action
# is a patch job, so each of these shows a console user a button that cannot
# close the finding. The prose is the only place left to say so.
#
# Every variant opens with the same five words, so it reads as a classification
# rather than four different alarms, and it is kept to one sentence of context
# because PE's console collapses newlines in this field: whatever is written
# here runs straight into the vendor's own text on the same line, however many
# blank lines separate them in the data. Measured on the lab 2026-09-17.
#
# It must not promise anything VR cannot show. An earlier version pointed the
# reader at the finding's evidence, which does not exist in VR and sent them
# looking for a field that was never pushed.
_FIX_TYPE_NOTE = {
    "mitigation": (
        "Not closable by a patch job. This needs a configuration change on the affected host."
    ),
    "workaround": (
        "Not closable by a patch job. No vendor fix exists; the avoidance is described below."
    ),
    "none-available": (
        "Not closable by a patch job. The vendor has published no fix yet."
    ),
    "will-not-fix": (
        "Not closable by a patch job. The vendor has declined to fix this, so the options are "
        "accepting the risk or removing the software."
    ),
}


def _solution(check, finding):
    """The solution text, with what VR's schema cannot carry said in prose.

    Two things have to be smuggled through, because VR holds neither.

    **The fix type**, which is the more important. VR's only remediation action
    is a patch job, so a mitigation finding offers a console user a button that
    cannot close it. On this lab that is 45 of the 87 findings VR sees, across
    12 checks: over half the board is unactionable by the one action the board
    offers, and nothing on it says so.

    **The per-host state**, where a fix exists but this node cannot take it.
    Ubuntu's ESM-only fixes are every package finding here, and without the
    sentence they look identical to an ordinary pending update.

    Both can apply at once, so both are said, fix type first: what kind of fix
    this is comes before whether this host could take it.
    """
    solution = check.get("solution", "") or "No solution available"
    notes = []

    note = _FIX_TYPE_NOTE.get(check.get("fix_type", ""))
    if note:
        notes.append(note)

    # VR has nowhere to put a composed record's sources, so they
    # go in the prose, in one sentence because the console collapses newlines.
    joined = finding.get("contributors") or []
    if len(joined) > 1:
        named = ", ".join(f"{c.get('name', '')} {c.get('check_id', '')}" for c in joined)
        notes.append(f"One weakness reported by {len(joined)} checks, shown here once: {named}.")

    state = finding.get("state", "")
    if state == "pro-only":
        notes.append("Fixed only in a subscription archive (Ubuntu Pro ESM or FIPS). Patchable "
                     "only on nodes with that subscription attached and the service enabled.")
    elif state == "unfixed":
        notes.append("No fix has been published for this package yet.")

    return "\n\n".join(notes + [solution])
