"""
The findings file's os_family vocabulary, read from an OS CPE or a vendor name.

`os_family` is a shared vocabulary, not each cassette's own words. If every
cassette passed its scanner's spelling through, one host would be `canonical`
in one file and `ubuntu` in another, which is worse than the field being
absent. Every cassette maps its scanner's OS identity here, a CPE where it has
one and the vendor's name where it does not, so they all land on the same names.

The family names are Vuls's, deliberately, because the vuls cassette already
writes them and it reads a family name rather than a CPE. Keyed on the CPE
vendor, with the product only where a vendor ships more than one OS line.
"""

import logging
import re

logger = logging.getLogger("transformer")

_OS_FAMILY_BY_CPE_VENDOR = {
    "canonical": "ubuntu",
    "debian": "debian",
    "oracle": "oracle",
    "almalinux": "alma",
    "rocky": "rocky",
    "rockylinux": "rocky",
    "redhat": "redhat",
    "centos": "centos",
    "fedoraproject": "fedora",
    "amazon": "amazon",
    "suse": "suse",
    "opensuse": "opensuse",
    "microsoft": "windows",
}

# CPE 2.2 (cpe:/o:vendor:product:version) as Greenbone and Nessus write it, and
# CPE 2.3 (cpe:2.3:o:vendor:product:version) as Rapid7 can. Only an `o` part is
# an operating system; an application CPE is no answer at all.
_CPE_OS_RE = re.compile(
    r"^cpe:(?:/|2\.3:)o:(?P<vendor>[^:]+):(?P<product>[^:]+)(?::(?P<version>[^:]+))?"
)

# Scanners that name the OS vendor in words rather than a CPE (Rapid7), lower
# case. Oracle and Microsoft are not here: both ship more than one OS, so they
# are told apart by product in os_from_vendor.
_OS_FAMILY_BY_VENDOR_NAME = {
    "ubuntu": "ubuntu",
    "canonical": "ubuntu",
    "debian": "debian",
    "red hat": "redhat",
    "redhat": "redhat",
    "centos": "centos",
    "almalinux": "alma",
    "alma": "alma",
    "rocky": "rocky",
    "rocky linux": "rocky",
    "amazon": "amazon",
    "suse": "suse",
    "novell": "suse",
    "opensuse": "opensuse",
    "fedora": "fedora",
    "fedora project": "fedora",
}

# "Windows Server 2019 Standard Edition", "windows server 2008 r2",
# "Windows 10 Enterprise": the line and release, without the edition.
_WINDOWS_RE = re.compile(r"\bwindows[\s_]+(?P<server>server[\s_]+)?(?P<release>\d{1,4}|xp|vista)(?P<r2>[\s_]+r2)?(?![A-Za-z0-9])", re.I)

# Vendors already seen and reported as unmapped, so one unknown distro logs
# once per run rather than once per host.
_unmapped_os_vendors = set()


def os_from_cpe(cpe):
    """(os_family, os_release) from an OS CPE, or ("", "").

    Nessus follows the CPE with an arrow and a display name
    (`cpe:/o:canonical:ubuntu_linux:22.04 -> Canonical Ubuntu Linux 22.04`),
    so only the first word is read.

    An unrecognised vendor returns empty and says so. Guessing a family from a
    string nobody has checked is how a consumer ends up grouping two distros
    together, and an empty field at least reads as absent.
    """
    text = (cpe or "").strip().split(None, 1)
    match = _CPE_OS_RE.match(text[0]) if text else None
    if not match:
        return "", ""
    vendor = match.group("vendor").lower()
    family = _OS_FAMILY_BY_CPE_VENDOR.get(vendor, "")
    if not family:
        if vendor not in _unmapped_os_vendors:
            _unmapped_os_vendors.add(vendor)
            logger.warning(f"No os_family mapping for CPE vendor {vendor!r} ({cpe}); left empty")
        return "", ""
    version = (match.group("version") or "").strip()
    if version in ("*", "-"):
        version = ""
    if family == "windows":
        # Windows carries the release in the product, not the version:
        # cpe:/o:microsoft:windows_server_2022:standard_x64. The vuls cassette
        # writes "Windows Server 2022" from Vuls, so this has to render the same.
        # R2 arrives in the version: cpe:/o:microsoft:windows_server_2008:r2.
        return family, windows_release(f"{match.group('product')} {version}")
    return family, version


def windows_release(text):
    """"Windows Server 2022" from any of the ways scanners write it, or "".

    The vuls cassette writes Vuls's "Windows Server 2022", so every other
    cassette has to render the same, without the edition, or one host is
    described two ways.
    """
    match = _WINDOWS_RE.search(text or "")
    if not match:
        return ""
    release = match.group("release")
    release = release.upper() if release.lower() == "xp" else release.title()
    parts = ["Windows", "Server" if match.group("server") else "", release, "R2" if match.group("r2") else ""]
    return " ".join(p for p in parts if p)


def os_from_vendor(vendor, product="", version=""):
    """(os_family, os_release) from a vendor's name, product and version, or ("", "")."""
    vendor = (vendor or "").strip().lower()
    product = (product or "").strip()
    version = (version or "").strip()
    if vendor == "microsoft" and product.lower().startswith("windows"):
        return "windows", windows_release(product)
    if vendor == "oracle" and "linux" in product.lower():
        return "oracle", version
    family = _OS_FAMILY_BY_VENDOR_NAME.get(vendor, "")
    if not family:
        if vendor and vendor not in _unmapped_os_vendors:
            _unmapped_os_vendors.add(vendor)
            logger.warning(f"No os_family mapping for OS vendor {vendor!r} ({product}); left empty")
        return "", ""
    return family, version
