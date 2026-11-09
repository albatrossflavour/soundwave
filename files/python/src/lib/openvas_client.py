"""
OpenVAS / Greenbone client.

Fetches scan reports from gvmd over GMP. On the Greenbone container host gvmd
only listens on a unix socket inside the container set, so rather than exposing
GMP over the network we run `gvm-cli` inside the existing gvm-tools container and
capture the GMP XML on stdout. That keeps the transformer's only external
dependency the docker CLI, which is already present on the scanner host.
"""

import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET

logger = logging.getLogger("transformer")


# Where the GMP credentials file is mounted inside the gvm-tools run, and where
# the container-local copy gvm-cli actually reads is written.
_CONTAINER_SECRET_PATH = "/run/secrets/gvm-tools.conf"
_CONTAINER_CONFIG_PATH = "/tmp/gvm-tools.conf"

# The image entrypoint is `gosu gvm "$@"`, and gvm-cli refuses to run as root,
# so it has to read its config as gvm (uid 1001). On the host uid 1001 is a real
# login account, so the host file stays root-only; instead this starts as root,
# copies it into the throwaway container filesystem readable only by gvm, then
# drops to gvm exactly as the stock entrypoint would. GMP arguments arrive as
# "$@", so the XML is never shell-expanded.
_WRAPPER = (
    f"install -o gvm -g gvm -m 0400 {_CONTAINER_SECRET_PATH} {_CONTAINER_CONFIG_PATH}"
    f' && exec gosu gvm gvm-cli --config {_CONTAINER_CONFIG_PATH} "$@"'
)


def _build_gmp_command(params, gmp_xml):
    """Assemble the docker + gvm-cli argv that pipes a GMP command to gvmd.

    Credentials come from gmp_config_file (Puppet-managed, root 0600) bind-mounted
    read-only into the container and read by `gvm-cli --config`. Passing them as
    --gmp-username/--gmp-password put the password in the argv of the docker
    client and of gvm-cli, readable by any local user through ps or /proc.
    """
    docker_cmd = params.get("docker_cmd", "docker").split()
    compose_file = params["compose_file"]
    service = params.get("gmp_service", "gvm-tools")
    socket_path = params.get("gmp_socket_path", "/run/gvmd/gvmd.sock")
    config_file = params["gmp_config_file"]
    # --no-deps: without it `compose run` starts gvm-tools' whole dependency
    # tree. That re-ran the one-shot setup containers every night and, after a
    # reboot had left the feed data containers stopped, started them, so they
    # wiped and recopied the VT volume under a running scanner. A read-only
    # report pull must not change the stack; if gvmd is down, fail and log.
    return [
        *docker_cmd,
        "compose",
        "-f",
        compose_file,
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "--entrypoint",
        "sh",
        "-v",
        f"{config_file}:{_CONTAINER_SECRET_PATH}:ro",
        service,
        "-c",
        _WRAPPER,
        # $0 for the sh -c script; everything after it becomes "$@".
        "gvm-cli",
        "socket",
        "--socketpath",
        socket_path,
        "--xml",
        gmp_xml,
    ]


def run_gmp(params, gmp_xml):
    """
    Run a single GMP command and return the parsed XML root element, or None.
    """
    cmd = _build_gmp_command(params, gmp_xml)
    # The command no longer carries credentials, but it does carry the GMP XML,
    # which can be large; log the fact of the call, not the argv.
    logger.info("Running GMP command via gvm-tools container")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=int(params.get("gmp_timeout", 300)),
        )
    except subprocess.TimeoutExpired:
        logger.error("GMP command timed out")
        return None
    if result.returncode != 0:
        logger.error(f"GMP command failed (rc={result.returncode}): {result.stderr.strip()}")
        return None
    try:
        return ET.fromstring(result.stdout)
    except ET.ParseError as e:
        logger.error(f"Could not parse GMP response: {e}")
        return None


def _select_last_reports(root, scan_name=""):
    """Pick each task's newest finished report from a get_tasks response.

    Returns a list of (report_id, scan_end), oldest first; empty when no task has
    finished a scan. gvmd records each task's last_report as its most recent Done
    report, so this needs no report listing. scan_name, when set, restricts the
    choice to the task with that exact name; it is matched here rather than in a
    GMP filter so quoting in the name can't break the XML.
    """
    picks = []
    for task in root.findall("task"):
        if scan_name and task.findtext("name", "") != scan_name:
            continue
        report = task.find("last_report/report")
        if report is None:
            continue
        end = report.findtext("scan_end", "")
        if end:
            picks.append((report.get("id"), end))
    # scan_end is an ISO-8601 Z string, so it sorts chronologically.
    return sorted(picks, key=lambda pick: pick[1])


def _latest_report_ids(params):
    """
    Find each task's most recent finished report, via its last_report.

    With several tasks (Puppet manages one per OS family), pushing only the
    newest report would leave PE holding one family's findings. So the newest
    report of every task is merged into one push instead.

    This used to list reports with `<get_reports filter="rows=-1
    sort-reverse=date"/>`. On get_reports, `filter` applies to the RESULTS inside
    each report; the report list takes `report_filter`, and without one gvmd used
    its default of rows=10 sort=name. So only the ten oldest reports were ever
    seen, and from the eleventh scan on the transformer resubmitted the same old
    report every night (22 Aug 2026 onwards on the lab) while PE rejected it
    with 409 as not newer. get_tasks honours its filter and gvmd tracks the last
    Done report per task, so asking the tasks sidesteps report listing entirely.
    """
    scan_name = params.get("scan_name", "").strip()
    root = run_gmp(params, '<get_tasks details="0" filter="rows=-1"/>')
    if root is None:
        return None

    picks = _select_last_reports(root, scan_name)
    if not picks:
        which = f"task '{scan_name}'" if scan_name else "any task"
        logger.error(f"No finished (Done) report found for {which}")
        return None
    for report_id, end in picks:
        logger.info(f"Selected report {report_id} (scan_end {end})")
    return picks


# gvmd silently clamps a get_reports response to 1000 result rows, even with
# rows=-1, so we page explicitly in chunks this size.
_PAGE_SIZE = 1000
# Backstop against an unbounded loop if gvmd ever ignores `first`: 1000 pages is
# a million results, far beyond any real report.
_MAX_PAGES = 1000


def _results_element(root):
    """Locate the inner <results> container in a get_reports response.

    An empty <results> element is falsy in ElementTree, so test for None
    explicitly rather than relying on `a or b`.
    """
    el = root.find(".//report/report/results")
    if el is None:
        el = root.find(".//results")
    return el


def _fetch_report(params, report_id):
    """Fetch one finished report, paging past gvmd's 1000-row cap.

    Returns the first page's root with every page's <result> rows merged into
    its <results> element, or None on failure.
    """
    logger.info(f"Fetching report {report_id}")
    root = None
    container = None
    seen_ids = set()
    first = 1
    for _ in range(_MAX_PAGES):
        # details=1 includes NVT metadata. levels MUST include 'c' (critical):
        # gvmd 22.x splits CVSS >= 9.0 into its own Critical band, and 'hml'
        # silently drops every critical finding. sort=id gives a unique total
        # order so page boundaries never skip or repeat a row (gvmd's default
        # severity sort has ties that do both).
        # min_qod=0 because the cassette records the QoD rather than applying a
        # cut with it. gvmd's default is 70, which silently drops the whole
        # low-confidence tail; the SSH Diffie-Hellman finding that is the best
        # mitigation candidate on this lab sits at QoD 30 on 23 hosts and never
        # appeared. Soundwave still applies a floor before pushing to VR, so
        # what PE sees is unchanged and the findings file keeps the rest.
        gmp = (
            f'<get_reports report_id="{report_id}" details="1"'
            f' filter="apply_overrides=1 levels=chml min_qod=0 sort=id'
            f' rows={_PAGE_SIZE} first={first}"/>'
        )
        page = run_gmp(params, gmp)
        if page is None:
            return None
        page_container = _results_element(page)
        page_results = page_container.findall("result") if page_container is not None else []

        if root is None:
            status = page.findtext(".//report/report/scan_run_status", "")
            if status != "Done":
                logger.error(f"Report {report_id} is {status or 'missing'}, not Done")
                return None
            root = page
            container = _results_element(root)
            # The container's own rows still need recording for dedup, since
            # gvmd's default result sort is not unique-stable across pages and a
            # tie row can otherwise reappear at the next page boundary.
            for result in (container.findall("result") if container is not None else []):
                seen_ids.add(result.get("id"))
        else:
            for result in page_results:
                rid = result.get("id")
                if rid in seen_ids:
                    continue
                seen_ids.add(rid)
                container.append(result)

        if len(page_results) < _PAGE_SIZE:
            break
        first += _PAGE_SIZE
    else:
        logger.warning(f"Stopped paging report {report_id} after {_MAX_PAGES} pages")

    total = len(container.findall("result")) if container is not None else 0
    logger.info(f"Fetched {total} result rows for report {report_id}")
    return root


def _merge_reports(roots):
    """Merge reports into the first one: results, host blocks, errors, scan_end.

    Results are deduplicated by id and hosts by address. The host blocks matter
    as much as the results: the openvas cassette builds a host block for every address the
    scan touched, so that a host with no findings can be told apart from a host
    the scan never reached. Merging only results left every task but the first
    with no hosts at all, which reads as "never scanned" for two thirds of the
    estate.
    """
    base = roots[0]
    inner = base.find(".//report/report")
    container = _results_element(base)
    if container is None:
        container = ET.SubElement(inner if inner is not None else base, "results")
    seen = {r.get("id") for r in container.findall("result")}
    latest = (inner.findtext("scan_end", "") if inner is not None else "")

    def address(host):
        return (host.findtext("ip") or "").strip()

    hosts_seen = {address(h) for h in (inner.findall("host") if inner is not None else [])}
    errors = inner.find("errors") if inner is not None else None

    for other in roots[1:]:
        other_container = _results_element(other)
        for result in (other_container.findall("result") if other_container is not None else []):
            if result.get("id") in seen:
                continue
            seen.add(result.get("id"))
            container.append(result)

        other_inner = other.find(".//report/report")
        if inner is not None and other_inner is not None:
            for host in other_inner.findall("host"):
                if address(host) in hosts_seen:
                    continue
                hosts_seen.add(address(host))
                inner.append(host)
            other_errors = other_inner.find("errors")
            for error in (other_errors.findall("error") if other_errors is not None else []):
                if errors is None:
                    errors = ET.SubElement(inner, "errors")
                errors.append(error)

        end = other.findtext(".//report/report/scan_end", "")
        if end > latest:
            latest = end

    if inner is not None and latest:
        scan_end = inner.find("scan_end")
        if scan_end is None:
            scan_end = ET.SubElement(inner, "scan_end")
        scan_end.text = latest
    return base


def get_latest_report(params):
    """
    Download each task's latest finished report, merged, as GMP XML to a temp file.

    Returns the path to the written file, or None on failure. The caller is
    responsible for removing the temp file once parsed.
    """
    picks = _latest_report_ids(params)
    if picks is None:
        return None

    roots = []
    for report_id, _ in picks:
        root = _fetch_report(params, report_id)
        if root is None:
            return None
        roots.append(root)
    merged = _merge_reports(roots)
    if len(roots) > 1:
        total = len(_results_element(merged).findall("result"))
        logger.info(f"Merged {len(roots)} reports into {total} result rows")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml", mode="w") as tmp:
        tmp.write(ET.tostring(merged, encoding="unicode"))
        report_path = tmp.name
    logger.info(f"Report written to {report_path}")
    return report_path
