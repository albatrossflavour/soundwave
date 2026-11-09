"""
Push the merged findings to a findings API.

The second consumer of the findings file, beside PE Vulnerability Remediation,
and the one that takes the whole of it rather than the part VR's schema can
hold. VR gets 87 findings on this lab; this gets all 3,144, with the QoD tail,
the fix types, the ports and the per-host evidence intact.

**Three calls, not one document**, which is the API's design and the reason it
was measured at 100,000 hosts where a single body capped out near 400:

    POST {action: checks, ...}    the catalogue, once
    POST {action: host, ...}      one per host
    POST {action: complete, ...}  closes the run

Closing the run sweeps every host it did not mention, so replacement is
all-or-nothing without an estate-sized request. Order is load-bearing: a host
pushed before its catalogue is refused, because resolving its fix types against
an empty catalogue would silently count them `unclassified`.

Per host it stays flat. The worst host on this lab is `puppet` at 737 findings,
296 KB raw and 7.8 KB gzipped, so the wire cost is bounded by the busiest host
rather than by the size of the estate. Bodies are gzipped and sent with an
explicit Content-Length: the endpoint refuses a chunked body with 411.
"""

import gzip
import json
import logging

from .api import call_rest_api

logger = logging.getLogger("transformer")

SCHEMA = "puppet-findings/1"
# Below this a body is smaller uncompressed than gzipped, once the header is
# counted. Only the per-host calls are ever near it.
GZIP_MIN_BYTES = 512


def _post(params, payload):
    """One call. Returns the API response dict."""
    body = json.dumps(payload).encode()
    # mTLS only: the endpoint authorises on the client certificate's CN against
    # the API's allowlist, so there is no token to send.
    headers = {"Content-Type": "application/json"}
    if len(body) >= GZIP_MIN_BYTES:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    # call_rest_api sets Content-Length from the body, which is what the
    # endpoint requires; it rejects a chunked request with 411.
    return call_rest_api(
        params["host"],
        "/api/v1/findings",
        port=int(params["port"]),
        method="POST",
        headers=headers,
        body=body,
        cert_verify=int(params.get("cert_verify", 1)),
        cert_file=params.get("cert_file"),
        key_file=params.get("key_file"),
        ca_cert=params.get("ca_cert"),
    )


def _ok(response, what):
    """True when a call succeeded, with the endpoint's own message when it did not.

    Every 422 names the field it objected to, which is the thing VR would not
    do, so it is worth logging verbatim rather than summarising.
    """
    if response is None:
        # call_rest_api swallows the exception and returns None, so this covers
        # a refused connection, a TLS failure, and a non-JSON error body alike.
        logger.error(f"findings API call for {what} failed before a response could be read")
        return False
    status = response.get("status")
    if status in (200, 201, 202, 204):
        return True
    detail = response.get("data")
    logger.error(f"findings API refused {what}: HTTP {status} {detail}")
    return False


def push(params, document):
    """Push **one cassette** as its own run. Returns hosts accepted, or None on failure.

    One cassette, one run, one name, one sweep. The merge that Soundwave does
    for VR must not happen here, and that is not a detail: the findings API keys
    everything by cassette precisely so a fresh openvas cassette cannot make a stale
    The vuls cassette read as current. Merge them on the way in and that property is gone,
    a dead cassette hides behind a live one, and the staleness alerting this
    whole design exists to support is quietly answering about the wrong thing.

    VR needs the merge because it holds one transformer's data per node and a
    partial push wipes what it does not mention. This endpoint has per-cassette
    replacement built in, so it needs the opposite. Applying VR's constraint
    here was the mistake; the cassette file is already exactly one run.

    A host that is refused is logged and skipped rather than failing the run:
    each host is its own call, so one bad host costs one host. Aborting on the
    first failure would give the estate back a single failure domain, which is
    what the per-host design exists to remove.
    """
    block = document.get("cassette") or {}
    name = block.get("name") or "unknown"
    hosts = document.get("hosts") or {}
    checks = document.get("checks") or {}

    by_host = {}
    for finding in document.get("findings") or []:
        by_host.setdefault(finding.get("certname", ""), []).append(finding)

    # The API's envelope key is `source`. It read `cassette` too until it stopped
    # naming any producer; this is the key its contract documents.
    envelope = {"schema": SCHEMA, "run_id": block.get("run_id") or "", "source": block}

    if not _ok(_post(params, dict(envelope, action="checks", checks=checks)), f"{name}'s check catalogue"):
        return None
    logger.info(f"findings API: {name}, {len(checks)} checks pushed")

    accepted = 0
    refused = []
    for certname, host in sorted(hosts.items()):
        payload = dict(envelope, action="host", certname=certname, host=host,
                       findings=by_host.get(certname, []))
        if _ok(_post(params, payload), f"{name}/{certname}"):
            accepted += 1
        else:
            refused.append(certname)

    # Complete anyway when some hosts were refused. The sweep removes hosts the
    # run did not mention, so a refused host loses its findings, which is
    # correct: they were not accepted. Not completing would instead leave the
    # whole previous run standing and hide that anything went wrong.
    if not _ok(_post(params, dict(envelope, action="complete")), f"{name}'s run completion"):
        return None

    if refused:
        logger.error(f"findings API: {name}, {len(refused)} host(s) refused and swept: "
                     f"{', '.join(refused[:5])}" + (" ..." if len(refused) > 5 else ""))
    logger.info(f"findings API: {name} complete, {accepted} of {len(hosts)} host(s) accepted")
    return accepted
