"""
HTTPS for cassettes that fetch their scanner's export over an API.

Standard library only, because Soundwave has no runtime dependencies and a
cassette is not the place to start adding them. Two rules a fetcher relies on:

  The certificate is always verified. A scanner with its own CA (Nessus signs
  its web server with one at install) is reached by naming that CA, never by
  turning verification off, because these requests carry API keys.

  Credentials go in unredirected headers, so a redirect to another host is not
  handed the keys.

A download goes to a file a chunk at a time. Exports are the size of the
estate, and the findings file's first rule is that nothing loads one whole.
"""

import http.client
import json
import logging
import shutil
import ssl
import time
import urllib.error
import urllib.request

logger = logging.getLogger("transformer")

TIMEOUT = 120
CHUNK = 1 << 20


class FetchError(Exception):
    """A scanner API call that did not give us what we asked for."""


class ExportFailed(FetchError):
    """The scanner itself says the export failed, so waiting longer will not help."""


def _context(ca_cert):
    if ca_cert:
        return ssl.create_default_context(cafile=ca_cert)
    return ssl.create_default_context()


def _request(url, method, auth_headers, body, headers):
    data = None
    request_headers = {"Accept": "application/json"}
    request_headers.update(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    for name, value in (auth_headers or {}).items():
        request.add_unredirected_header(name, value)
    return request


def _open(url, method="GET", auth_headers=None, body=None, ca_cert=None, headers=None, timeout=TIMEOUT):
    request = _request(url, method, auth_headers, body, headers)
    try:
        return urllib.request.urlopen(request, context=_context(ca_cert), timeout=timeout)
    except urllib.error.HTTPError as err:
        # The body usually says why (a scan still running, a key without the
        # permission), and it is short. The keys are in headers, not here.
        detail = err.read(500).decode("utf-8", "replace").strip()
        raise FetchError(f"{method} {url} answered {err.code}: {detail or err.reason}") from err
    except (urllib.error.URLError, OSError) as err:
        raise FetchError(f"{method} {url} failed: {getattr(err, 'reason', err)}") from err


def call_json(url, method="GET", auth_headers=None, body=None, ca_cert=None):
    """The JSON a call returns, or {} for an empty body."""
    try:
        with _open(url, method, auth_headers, body, ca_cert) as response:
            raw = response.read()
    except (http.client.HTTPException, OSError) as err:
        # A connection dropped mid-body is not an OSError (IncompleteRead), and
        # anything left unwrapped here skips every caller's per-scan handling.
        raise FetchError(f"{method} {url} broke off: {err!r}") from err
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError as err:
        raise FetchError(f"{method} {url} did not return JSON: {err}") from err


def download(url, path, auth_headers=None, ca_cert=None, headers=None):
    """Write a response body to path a chunk at a time. Returns the byte count."""
    try:
        with _open(url, "GET", auth_headers, None, ca_cert, headers) as response, open(path, "wb") as out:
            shutil.copyfileobj(response, out, CHUNK)
            return out.tell()
    except (http.client.HTTPException, OSError) as err:
        raise FetchError(f"GET {url} broke off: {err!r}") from err


def wait_for(probe, what, timeout, interval=10, clock=time.monotonic, sleep=time.sleep):
    """Call probe() until it returns something truthy, or give up after timeout seconds.

    probe returns a falsy value to mean "not yet". A FetchError from it (a 503,
    a reset connection) is a failed look, not a failed export, so it is logged
    and tried again until the deadline. ExportFailed, the scanner saying the
    export failed, propagates at once.
    """
    deadline = clock() + timeout
    last_error = None
    while True:
        try:
            result = probe()
        except ExportFailed:
            raise
        except FetchError as err:
            logger.warning(f"Checking on {what} failed, trying again: {err}")
            last_error, result = err, None
        if result:
            return result
        if clock() >= deadline:
            because = f"; the last check failed: {last_error}" if last_error else ""
            raise FetchError(f"{what} not ready after {timeout}s{because}")
        sleep(interval)
