# Changelog

## 0.1.1

- The README links to the docs on GitHub, so they work on the Forge

## 0.1.0

First release. Merges vulnerability findings from any number of scanners, each read by its own cassette, and pushes one set into Puppet Enterprise's Vulnerability Remediation service. Ships with cassettes for Greenbone and Vuls.

- An install guide in `docs/guide/`, from a working scanner to findings in PE, with a check for each step that says what a good answer looks like
- Two cassettes: `openvas` reads Greenbone over GMP and is on by default, and `vuls` reads the last complete Vuls run and is off by default
- A cassette that fails leaves its previous file in place, so the push still goes
- Every push carries the full merged set, and a host scanned clean is pushed with an empty list, so patched nodes stop showing old findings
- Findings below `min_confidence` (70 by default) and findings with no CVSS score stay in the cassette files and aren't pushed
- `pe_host` defaults to the Puppet server that compiled the catalogue
- Runs on Ubuntu 22.04, 24.04, and 26.04, Debian 11 and 12, Red Hat 8 and 9, and AlmaLinux 9 and 10, on the system Python, 3.9 or later
