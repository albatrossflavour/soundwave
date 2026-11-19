# Changelog

## 0.2.2

- A transformer still pending in PE no longer stops the run. Soundwave skips the VR push and logs why, and still writes the cassette metrics and pushes to the findings API. In 0.2.1 the run ended at registration, so an unaccepted transformer looked like missing cassettes
- `metrics_file` gains `soundwave_vr_transformer_state`, 1 on what registration found: `active`, `pending`, `conflict`, `error`, or `unchecked`. A pending run still counts as a success in `soundwave_last_run_success`
- A findings API push that fails or raises, or a registration that raises, no longer stops the other outputs

## 0.2.1

- Supports Puppet 9 and `puppetlabs-node_encrypt` 4.x, so `pe_status_check` stops reporting the module's dependency caps

## 0.2.0

- Upgrading removes scripts the module no longer ships, where before a renamed or deleted one stayed on the node
- The openvas cassette now leaves `os_release` empty for a Windows host whose CPE names no release, in place of "Windows"
- Windows Server 2008 R2 and 2012 R2 keep their R2 in `os_release`

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
