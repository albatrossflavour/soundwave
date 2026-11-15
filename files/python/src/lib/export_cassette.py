"""
What a cassette reading a scanner's export file shares with every other one.

The nessus and rapid7 cassettes work the same way and differ only in the
format they parse. Each either fetches its exports over the scanner's API,
when `url` is set in its config section, or reads whatever has been dropped in
`export_dir`. Then it parses every file into one document and writes it.

One rule matters more than the rest. A run that gets nothing, because the API
was down or the directory was empty, writes nothing. The previous file stays
in place and its age is what the staleness alert reports. Writing an empty
cassette would instead say "this scanner saw no hosts", which is a claim, and
a false one.
"""

import logging
import os
import shutil
import sys
import tempfile

from lib import findings as F
from lib.config_helper import load_transformer_parameters
from lib.host_map import load_host_map
from lib.scanner_http import FetchError

logger = logging.getLogger("transformer")


def export_files(directory, suffixes):
    """Every file in directory ending in one of suffixes, oldest first."""
    try:
        names = os.listdir(directory)
    except OSError as err:
        logger.error(f"Cannot read export directory {directory}: {err}")
        return []
    paths = [os.path.join(directory, n) for n in names
             if n.lower().endswith(suffixes) and not n.startswith(".")]
    return sorted((p for p in paths if os.path.isfile(p)), key=os.path.getmtime)


def record_host(document, certname, **fields):
    """Add a host block, keeping the newer scan when two exports both cover it.

    A host in two exports is a host scanned twice, and the block describes
    the newer look. Which findings survive is the cassette's call, using
    newer_scan: a newer run of the same scan supersedes an older one's, or a
    vulnerability patched between them would never clear.
    """
    existing = document.hosts.get(certname)
    if existing is not None:
        old = F.iso_to_epoch(existing.get("scan_end", "")) or 0
        new = F.iso_to_epoch(fields.get("scan_end", "")) or 0
        if old >= new:
            return existing
    return document.host(certname, **fields)


def newer_scan(candidate, current):
    """Whether scan_end candidate is later than current. Unknown ends count as the epoch."""
    return (F.iso_to_epoch(candidate or "") or 0) > (F.iso_to_epoch(current or "") or 0)


def certname_for(mapping, address, *names):
    """(certname, mapped) for a host: the host map's answer, else the first name given."""
    certname = (mapping or {}).get(address)
    if certname:
        return certname, True
    return next((n for n in names if n), address), False


def run(cassette, section, suffixes, fetch, parse):
    """The cassette's main: get the exports, parse them, write the file.

    fetch(params, workdir) returns paths it wrote into workdir. parse(paths,
    mapping, params) returns a findings.Document. Exit status is non-zero when
    nothing was written, and the unit runs the cassette with a leading -, so
    the push still goes with the previous file.
    """
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
    params = load_transformer_parameters(section=section)
    # Every section inherits [DEFAULT], which is where cassette_dir lives.
    cassette_dir = params["cassette_dir"]
    mapping = load_host_map(params.get("host_map_file", ""))

    workdir = None
    try:
        if params.get("url"):
            # Beside the cassette directory rather than in /tmp, which is often
            # a small tmpfs, and these are the size of the estate.
            workdir = tempfile.mkdtemp(prefix=f".{cassette}-export-", dir=os.path.dirname(cassette_dir.rstrip("/")))
            try:
                paths = fetch(params, workdir)
            except FetchError as err:
                logger.error(f"{cassette}: {err}")
                paths = []
        else:
            paths = export_files(params.get("export_dir", ""), suffixes)
        if not paths:
            logger.error(f"{cassette}: no exports to read, so the previous file is left in place")
            return 1
        document = parse(paths, mapping, params)
        if document is None or not document.hosts:
            logger.error(f"{cassette}: the exports held no hosts, so the previous file is left in place")
            return 1
        document.write(os.path.join(cassette_dir, f"{cassette}.json"))
        return 0
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)
