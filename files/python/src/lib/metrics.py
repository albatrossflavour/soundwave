"""
What the last run did, as a node_exporter textfile.

The transformer sat on a three-week-old report once and nothing noticed: the
unit succeeded every night, PE answered 409, and every board downstream kept
showing the old numbers as if they were current. So each run writes what an
alert needs to tell stale from quiet.

With cassettes the same trap comes back one level down. One push carries one
scan date, so a fresh openvas cassette would make a month-old vuls cassette look current.
Everything here is therefore labelled by cassette, and the scan end is per
host, which is finer than the per-task figure it replaces and is what a
blind-spot report wants anyway.

Everything but the run and success lines is only written when the run got far
enough to know it, so a failed run doesn't publish zeros that read as "no
findings". The last success time is carried over from the previous file.
"""

import logging
import os
import re
import tempfile
import time

logger = logging.getLogger("transformer")

PREFIX = "soundwave"
_LAST_SUCCESS = f"{PREFIX}_last_success_timestamp_seconds"
_LAST_SUCCESS_RE = re.compile(rf"^{_LAST_SUCCESS} (\S+)$", re.MULTILINE)


def _label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class RunMetrics:
    def __init__(self, path, clock=time.time):
        self.path = path
        self.clock = clock
        self.push_status = None
        self.findings = None
        self.hosts_pushed = None
        self.hosts_clean = None
        self.findings_api_hosts = None
        # {cassette: {generated_at, scan_end, findings, hosts{status: n}, dropped{filter: n}, unmapped}}
        self.cassettes = None
        # {(cassette, certname): epoch}
        self.host_scan_ends = None
        # Correlations.to_dict() from the last run, or None when correlation is off.
        self.correlated = None
        # Composition stats for the VR push, or None when composition is off.
        self.composed = None

    def _previous_success(self):
        try:
            with open(self.path) as fh:
                match = _LAST_SUCCESS_RE.search(fh.read())
            return float(match.group(1)) if match else None
        except (OSError, ValueError):
            return None

    def render(self, success):
        now = int(self.clock())
        last_success = now if success else self._previous_success()
        lines = []

        def metric(name, help_text, samples):
            samples = [s for s in samples if s[1] is not None]
            if not samples:
                return
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            for labels, value in samples:
                text = "{" + ",".join(f'{k}="{_label(v)}"' for k, v in labels.items()) + "}" if labels else ""
                lines.append(f"{name}{text} {value:g}" if isinstance(value, float) else f"{name}{text} {value}")

        metric(f"{PREFIX}_last_run_timestamp_seconds",
               "When Soundwave last finished a run, whatever happened.", [({}, now)])
        metric(f"{PREFIX}_last_run_success",
               "1 when the last run pushed to PE or PE already held that scan, 0 when it failed.",
               [({}, 1 if success else 0)])
        metric(_LAST_SUCCESS, "When a run last succeeded.",
               [({}, int(last_success) if last_success is not None else None)])
        metric(f"{PREFIX}_push_status_code", "HTTP status PE gave the last push.", [({}, self.push_status)])
        metric(f"{PREFIX}_findings", "Findings in the last push, across every cassette.",
               [({}, self.findings)])
        metric(f"{PREFIX}_hosts_pushed", "Hosts in the last push.", [({}, self.hosts_pushed)])
        metric(f"{PREFIX}_findings_api_hosts_accepted",
               "Hosts the findings API accepted on the last run. Absent when the API is not "
               "configured; below the pushed host count when some hosts were refused and swept.",
               [({}, self.findings_api_hosts)])
        if self.correlated:
            labels = {"rule": self.correlated.get("rule", "")}
            metric(f"{PREFIX}_correlated_groups",
                   "Groups of findings the last run judged to describe one weakness on one host. "
                   "Counted, not acted on, while correlation is in report-only mode.",
                   [(labels, self.correlated.get("groups"))])
            metric(f"{PREFIX}_correlated_findings",
                   "Findings inside those groups. The difference from the group count is how many "
                   "rows collapsing them would remove.",
                   [(labels, self.correlated.get("findings"))])
            metric(f"{PREFIX}_correlated_cross_cassette_groups",
                   "Groups drawing on more than one cassette. The rest are one scanner reporting a "
                   "weakness under two of its own check IDs.",
                   [(labels, self.correlated.get("cross_cassette_groups"))])
            metric(f"{PREFIX}_correlation_exceptions_applied",
                   "Groups left uncorrelated because a configured check pair is known to describe "
                   "different work despite sharing a key.",
                   [(labels, self.correlated.get("exceptions_applied"))])

        if self.composed:
            metric(f"{PREFIX}_composed_sets",
                   "Sets of findings the last run pushed to VR as one record each.",
                   [({}, self.composed.get("sets"))])
            metric(f"{PREFIX}_composed_findings",
                   "Findings inside those sets. The difference from the set count is how many rows "
                   "composing removed from VR.",
                   [({}, self.composed.get("findings"))])
            metric(f"{PREFIX}_composed_cross_cassette_sets",
                   "Composed sets drawing on more than one cassette.",
                   [({}, self.composed.get("cross_cassette_sets"))])
            metric(f"{PREFIX}_composition_capped_sets",
                   "Sets left uncomposed for exceeding the size cap, which is what stops one wide "
                   "advisory chaining unrelated findings into a single record. Non-zero is worth reading.",
                   [({}, self.composed.get("capped_sets"))])

        metric(f"{PREFIX}_hosts_clean",
               "Hosts pushed with no findings. They are sent on purpose: a host left out of a push "
               "keeps whatever VR already held for it.", [({}, self.hosts_clean)])

        if self.cassettes:
            items = sorted(self.cassettes.items())
            metric(f"{PREFIX}_cassette_clock_skew_seconds",
                   "Seconds by which a cassette's newest scan end sits in the future. Non-zero means "
                   "the scanner's clock or timezone is wrong and every age derived from it reads "
                   "fresher than it is. Alert on anything above zero.",
                   [({"cassette": name}, c.get("clock_skew")) for name, c in items])
            metric(f"{PREFIX}_cassette_generated_timestamp_seconds",
                   "When each cassette last wrote its findings file.",
                   [({"cassette": name}, c["generated_at"]) for name, c in items])
            metric(f"{PREFIX}_cassette_scan_end_timestamp_seconds",
                   "Newest scan end across the hosts in each cassette.",
                   [({"cassette": name}, c["scan_end"]) for name, c in items])
            metric(f"{PREFIX}_cassette_findings", "Findings each cassette contributed.",
                   [({"cassette": name}, c["findings"]) for name, c in items])
            metric(f"{PREFIX}_cassette_hosts", "Hosts each cassette reported, by what happened to them.",
                   [({"cassette": name, "status": status}, count)
                    for name, c in items for status, count in sorted(c["hosts"].items())])
            metric(f"{PREFIX}_cassette_dropped",
                   "Findings each cassette's filters removed. A filter that starts eating real "
                   "findings shows up here as a jump or a collapse.",
                   [({"cassette": name, "filter": filter_name}, count)
                    for name, c in items for filter_name, count in sorted(c["dropped"].items())])
            metric(f"{PREFIX}_cassette_unmapped",
                   "Hosts a cassette could not name by certname. PE matches on certname and drops "
                   "the rest without saying so.",
                   [({"cassette": name}, c["unmapped"]) for name, c in items])

        if self.host_scan_ends:
            metric(f"{PREFIX}_host_scan_end_timestamp_seconds",
                   "When each host was last scanned, per cassette.",
                   [({"cassette": cassette, "certname": certname}, end)
                    for (cassette, certname), end in sorted(self.host_scan_ends.items())])

        return "\n".join(lines) + "\n"

    def write(self, success):
        """Replace the file in one step, so node_exporter never reads half of it."""
        if not self.path:
            return
        directory = os.path.dirname(self.path) or "."
        try:
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{PREFIX}.", suffix=".tmp")
            with os.fdopen(fd, "w") as fh:
                fh.write(self.render(success))
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.path)
        except OSError as e:
            logger.error(f"Could not write metrics to {self.path}: {e}")
