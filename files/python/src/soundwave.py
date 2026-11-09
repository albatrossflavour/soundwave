"""
Soundwave: merge every cassette's findings and push the result to PE.

It never parses a scanner. Cassettes do that, each writing the scanner-neutral
findings file into the cassette directory; Soundwave reads whatever is there,
merges it, and pushes one set to PE Vulnerability Remediation under one
transformer ID.

Two things this has to get right, because getting either wrong loses data
without saying so:

  Every push carries the full merged set. VR replaces a transformer's data per
  node on each push, so pushing one cassette's latest alone wipes the other's.

  A host that was scanned and came back clean is pushed with an empty list, not
  left out. A node left out of a push keeps whatever VR already had, so
  dropping clean hosts is how a patched node shows its old findings forever.

Freshness is tracked per cassette, so a stale vuls cassette cannot hide behind a fresh
The openvas cassette.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import findings as F  # noqa: E402
from lib.config_helper import load_transformer_parameters  # noqa: E402
from lib.findings_api_client import push as push_findings  # noqa: E402
from lib.metrics import RunMetrics  # noqa: E402
from lib.pe_transformer_client import register_host, post_transformer_res_to_pe  # noqa: E402

logger = logging.getLogger("transformer")

TRANSFORMER_STATUS_CREATED = 201
TRANSFORMER_STATUS_PENDING = 202
TRANSFORMER_STATUS_EXISTS = 409
TRANSFORMER_MESSAGE_CREATED = "Transformer ID registered"
TRANSFORMER_MESSAGE_OTHER = "Another transformer with pending or active status exists"
MAX_RETRIES = 100
MIN_RETRIES = 1
MAX_RETRY_INTERVAL = 60
MIN_RETRY_INTERVAL = 1


def handle_registration(params):
    max_retries = max(MIN_RETRIES, min(int(params.get("max_retries", 1)), MAX_RETRIES))
    retry_interval = max(
        MIN_RETRY_INTERVAL, min(int(params.get("retry_interval", 1)), MAX_RETRY_INTERVAL)
    )
    logger.info(f"Max retries: {max_retries}, retry interval: {retry_interval}")

    res = None
    for _ in range(max_retries):
        res = register_host(params)
        if res["status"] not in [TRANSFORMER_STATUS_CREATED, TRANSFORMER_STATUS_PENDING]:
            return res
        logger.info(
            f"Registration pending with status {res['status']}. Retrying in {retry_interval} seconds."
        )
        time.sleep(retry_interval)
    return res


def register(pe_params):
    """Returns None to carry on, or an exit code to stop on."""
    if not bool(int(pe_params.get("register", 1))):
        logger.info("Registration disabled.")
        return None
    res = handle_registration(pe_params)
    if res["status"] == TRANSFORMER_STATUS_PENDING:
        logger.info("Registration successful. Transformer is Pending Activation.")
        return 0
    if res["status"] == TRANSFORMER_STATUS_EXISTS:
        if res["data"]["message"] == TRANSFORMER_MESSAGE_CREATED:
            logger.info("Transformer ID Registered and Active.")
            return None
        if res["data"]["message"] == TRANSFORMER_MESSAGE_OTHER:
            logger.error("Transformer with different ID is in Active or Pending State.")
            return 1
    logger.error(f"Registration failed. {res}")
    return 1


def record_cassettes(documents, metrics):
    """Per-cassette freshness and volume, for the metrics file."""
    metrics.cassettes = {}
    metrics.host_scan_ends = {}
    for document in documents:
        block = document.get("cassette") or {}
        name = block.get("name") or "unknown"
        hosts = document.get("hosts") or {}
        scan_ends = []
        for certname, host in hosts.items():
            end = F.iso_to_epoch(host.get("scan_end", ""))
            if end:
                scan_ends.append(end)
                metrics.host_scan_ends[(name, certname)] = end
        skew = F.clock_skew(hosts)
        if skew:
            logger.warning(
                f"Cassette {name} reports a scan ending {skew}s in the future. Its scanner's clock or "
                "timezone is wrong, and every age derived from it will read fresher than it is."
            )
        metrics.cassettes[name] = {
            "clock_skew": skew,
            "generated_at": F.iso_to_epoch(block.get("generated_at", "")),
            "scan_end": max(scan_ends) if scan_ends else None,
            "findings": len(document.get("findings") or []),
            "hosts": {
                status: sum(1 for h in hosts.values() if h.get("status") == status)
                for status in ("scanned", "partial", "unreachable", "unknown")
            },
            "dropped": {d.get("filter", ""): d.get("findings", 0) for d in document.get("dropped") or []},
            "unmapped": len(document.get("unmapped") or []),
        }


def _correlation_exceptions(defaults):
    """Check-ID pairs that must never be correlated, from configuration.

    Written as `a|b,c|d`. These are pairs the key provably cannot separate:
    the SSH protocol check and the OpenSSH version check both report
    CVE-2023-48795 on port 22 with the same fix type, and one is closed by
    upgrading a package while the other is closed by disabling algorithms.
    Configuration rather than code, because the list is evidence gathered from
    the sample and will grow with every scanner added.
    """
    raw = (defaults.get("correlation_exceptions") or "").strip()
    pairs = []
    for entry in raw.split(","):
        members = [part.strip() for part in entry.split("|") if part.strip()]
        if len(members) == 2:
            pairs.append(tuple(members))
        elif entry.strip():
            logger.warning(f"Ignoring correlation exception {entry.strip()!r}: expected two check IDs separated by |")
    return pairs


def report_correlations(documents, defaults, metrics):
    """Count what correlation would join, and say what it would have done.

    Report-only on purpose. Nothing downstream reads the result yet: VR still
    gets a row per finding and the findings API still gets each cassette verbatim. The
    counter comes first because overlap is currently invisible, and a rule
    nobody can see the effect of is one nobody can check.
    """
    if not bool(int(defaults.get("correlate", 0))):
        return None
    record = F.correlate(documents, _correlation_exceptions(defaults))
    metrics.correlated = record.to_dict()
    logger.info(
        f"correlation ({F.CORRELATION_RULE}): {record.groups} group(s) over {record.findings} finding(s) "
        f"on {len(record.hosts)} host(s), {record.cross_cassette} drawing on more than one cassette, "
        f"{record.exceptions_applied} left alone by exception. "
        + ("Acted on by composition below." if bool(int(defaults.get("compose_findings", 0)))
           else "Report only, nothing was merged.")
    )
    for sample in record.to_dict()["sample"]:
        joined = ", ".join(f"{m['cassette']}/{m['check_id']}" for m in sample["joined"])
        logger.info(f"  would join {sample['cve']} on {sample['certname']} ({sample['subject']}): {joined}")
    return record


def _findings_params(pe_params, defaults):
    """Connection details for the findings API, or None when it is off.

    Reuses the node's Puppet agent certificate, which is what both ends already
    authenticate with: the findings API authorises on its CN against
    the API's allowlist, so there is nothing else to configure.
    """
    host = (defaults.get("findings_api_host") or "").strip()
    if not host:
        return None
    return {
        "host": host,
        "port": defaults.get("findings_api_port", "10051"),
        "cert_verify": pe_params.get("cert_verify", 1),
        "cert_file": pe_params.get("cert_file"),
        "key_file": pe_params.get("key_file"),
        "ca_cert": pe_params.get("ca_cert"),
    }


def state_path(defaults):
    """Where the last scan date PE accepted is kept: `state_file`, or beside the cassette directory."""
    configured = (defaults.get("state_file") or "").strip()
    if configured:
        return configured
    cassette_dir = (defaults.get("cassette_dir") or "").rstrip("/")
    return os.path.join(os.path.dirname(cassette_dir), "pe-push-state.json") if cassette_dir else ""


def read_held_scan_date(path):
    """The scan date PE last accepted or already held, or None when nothing is recorded."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return int(json.load(f)["scan_date"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        logger.warning(f"Ignoring unreadable push state {path}: {e}")
        return None


def write_held_scan_date(path, scan_date):
    if not path:
        return
    try:
        with open(path, "w") as f:
            json.dump({"scan_date": int(scan_date),
                       "recorded": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}, f)
    except OSError as e:
        logger.warning(f"Could not write push state {path}: {e}")


def run(pe_params, defaults, metrics):
    """One Soundwave run. Returns the process exit code."""
    stop = register(pe_params)
    if stop is not None:
        return stop

    cassette_dir = defaults.get("cassette_dir", "")
    documents = F.read_cassettes(cassette_dir)
    if not documents:
        logger.error(f"No readable cassettes in {cassette_dir}; nothing to push")
        return 1
    logger.info(f"Merging {len(documents)} cassette(s): "
                f"{', '.join(sorted((d.get('cassette') or {}).get('name', '?') for d in documents))}")
    record_cassettes(documents, metrics)

    report_correlations(documents, defaults, metrics)

    hosts, checks, findings = F.merge(documents)
    composing = bool(int(defaults.get("compose_findings", 0)))
    if composing:
        checks, findings, stats = F.compose_for_vr(documents, checks, findings, _correlation_exceptions(defaults))
        metrics.composed = stats
        logger.info(f"composition: {stats['sets']} set(s) of {stats['findings']} finding(s) pushed to VR as one "
                    f"record each, {stats['cross_cassette_sets']} spanning cassettes, {stats['capped_sets']} "
                    f"left alone for exceeding {F.COMPOSE_MAX_FINDINGS} findings or {F.COMPOSE_MAX_CVES} CVEs")
    data, scan_date = F.to_vr(hosts, checks, findings, int(defaults.get("min_confidence", 70)))

    metrics.findings = sum(len(h["vulnerabilities"]) for h in data)
    metrics.hosts_pushed = len(data)
    metrics.hosts_clean = sum(1 for h in data if not h["vulnerabilities"])
    logger.info(f"Pushing {metrics.findings} finding(s) across {len(data)} host(s), "
                f"{metrics.hosts_clean} of them clean")

    # The findings API takes the whole findings file; VR takes the part its schema holds.
    # Independent on purpose: a findings API that is down, or not switched on,
    # must not stop the VR push, which is the one with a console behind it.
    #
    # One cassette, one run, one sweep. Not the merged set: the findings API keys
    # everything by cassette so a stale vuls cassette cannot hide behind a fresh
    # The openvas cassette, and merging on the way in would throw that away. The merge
    # above exists for VR, which holds one transformer's data per node.
    findings_params = _findings_params(pe_params, defaults)
    if findings_params:
        # Each cassette as the scanner wrote it, composed or not: composition
        # is for VR. The findings API takes raw findings per source and stores no
        # merged-record fields.
        accepted = [push_findings(findings_params, document) for document in documents]
        metrics.findings_api_hosts = sum(a for a in accepted if a is not None) if accepted else None

    # PE answers a repeat of a scan date it already holds with 409 before it
    # has read the body, and closes the connection. Under about 200 KB the
    # whole body had gone by then and the 409 was read; the 1.9 MB body the
    # 2026-10-18 Vuls scan produced was still being sent, so http.client saw
    # an EOF and every quiet night from 2026-10-20 counted as a failed push.
    # VR has no endpoint to ask what it holds, so the date it last accepted
    # (201) or already held (409) is kept here, and a scan it has is not sent.
    path = state_path(defaults)
    held = read_held_scan_date(path)
    if held is not None and scan_date <= held:
        logger.info(f"PE already holds scan date {_iso(held)} (recorded in {path}); not pushing scan date "
                    f"{_iso(scan_date)}. Nothing to do.")
        return 0

    res = post_transformer_res_to_pe(pe_params, data, scan_date)
    metrics.push_status = res["status"]

    if res["status"] == 201:
        logger.info("Results added successfully")
        write_held_scan_date(path, scan_date)
        return 0
    if res["status"] == 409:
        logger.info("Scan date is equal or prior to the last scan date. Nothing to do.")
        write_held_scan_date(path, scan_date)
        return 0
    logger.error(f"Error adding results: {res.get('data', res)}")
    return 1


def _iso(epoch):
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
    pe_params = load_transformer_parameters(section="PE")
    defaults = load_transformer_parameters(section="DEFAULT")
    metrics = RunMetrics(defaults.get("metrics_file", ""))
    try:
        code = run(pe_params, defaults, metrics)
    except Exception:
        logger.exception("Soundwave run failed")
        code = 1
    metrics.write(code == 0)
    return code


if __name__ == "__main__":
    sys.exit(main())
