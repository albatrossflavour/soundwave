"""
Name scanned hosts by their Puppet certname.

gvmd knows a host by the address it scanned and whatever reverse DNS said,
and PE matches findings to nodes by certname. Where reverse DNS and certname
differ, PE drops the host's findings without saying so; on the lab it dropped
the gateway that way. The node's own Puppet data knows which certname owns
which address, so the Greenbone profile writes that as a JSON object,
{"192.0.2.10": "puppet.example.com", ...}, and this renames each host before
the push. A host the map doesn't know keeps its reverse DNS name and is logged,
so a drop PE won't report is at least visible here.
"""

import json
import logging

logger = logging.getLogger("transformer")


def load_host_map(path):
    """The address to certname map at path, or None when there isn't one."""
    if not path:
        return None
    try:
        with open(path) as fh:
            mapping = json.load(fh)
    except (OSError, ValueError) as e:
        logger.error(f"Host map {path} unreadable, sending reverse DNS names: {e}")
        return None
    if not isinstance(mapping, dict):
        logger.error(f"Host map {path} is not a JSON object, sending reverse DNS names")
        return None
    return {str(k): str(v) for k, v in mapping.items() if k and v}


def apply_host_map(hosts, mapping):
    """Set each host's hostname to its certname where the map knows the address.

    Returns the hosts, changed in place, so the call reads as a step.
    """
    if mapping is None:
        return hosts
    unmapped = []
    for host in hosts:
        certname = mapping.get(host.get("ipaddress", ""))
        if certname:
            host["hostname"] = certname
        else:
            unmapped.append(host)
    for host in unmapped:
        logger.warning(
            f"No certname for {host.get('ipaddress')} ({host.get('hostname')}); "
            "sent under that name, and PE drops it unless it matches a certname"
        )
    logger.info(f"Named {len(hosts) - len(unmapped)} of {len(hosts)} host(s) by certname")
    return hosts
