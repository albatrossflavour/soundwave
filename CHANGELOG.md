# Changelog

## 0.4.0

- `soundwave::rbac_user`, declared on the PE primary, makes a `Soundwave` role that can register a transformer and push to VR and nothing else, and a `soundwave` user holding only that role. It checks the user's password each run and resets it if it has drifted
- `token_password` on the main class has the Soundwave node mint its own token with `rbac_token`, keep it in `token_file`, and renew it after `token_renew_after` (21 days, for a 30-day `token_lifetime`). Soundwave reads the file at the start of every run, so a renewed token needs no restart and no token is ever in a catalogue. See [PE access](https://github.com/albatrossflavour/soundwave/blob/main/README.md#pe-access)
- `pe_token` is now optional, and works as before. Set it or `token_password`, not both
- Both need [conductor-rbac](https://github.com/albatrossflavour/conductor-rbac) in the Puppetfile. It is not a metadata dependency, and the catalogue fails with a message naming it if either is used without it

## 0.3.0

- `threat_intel` marks every check with CISA KEV and FIRST EPSS, matched on CVE, so a finding from a scanner that doesn't report KEV (Greenbone, Rapid7) can still be ordered worst first. `download` fetches both feeds each run and keeps the previous file if a download fails. `directory` reads files copied into `threat_intel_dir`, for a node with no internet access. `off` is the default
- Checks in the cassette files and the findings API push gain `epss` and `epss_percentile`. `kev` is set from CISA's catalogue as well as from the scanner, and a true from the scanner is never cleared
- `threat_intel_in_vr` leads each finding's summary in PE with the KEV and EPSS marks, since VR's schema has no field for them. Off by default
- `metrics_file` gains `soundwave_threat_intel_feed_timestamp_seconds` and `soundwave_threat_intel_checks_marked`, both by `feed`

## 0.2.3

- A registration whose last answer is 201 (VR has just created the transformer) is `pending`, where 0.2.2 called it `error` and failed the run. That's the answer with `max_retries` at 1. Any answer Soundwave doesn't recognise, a rejected transformer included, is still `error`
- A cassette that breaks the cassette metrics no longer stops the findings API push, registration, or the VR push. The run still fails, and no cassette metrics are written for it, since half a set reads as real numbers
- `soundwave_last_success_timestamp_seconds` no longer advances on a pending run, so its age is how long VR has gone without the current scan. `soundwave_last_run_success` still counts a pending run as 1

## 0.2.2

- A transformer still pending in PE no longer stops the run. Soundwave skips the VR push and logs why, and still writes the cassette metrics and pushes to the findings API. In 0.2.1 the run ended at registration, so an unaccepted transformer looked like missing cassettes
- `metrics_file` gains `soundwave_vr_transformer_state`, 1 on what registration found: `active`, `pending`, `conflict`, `error`, or `unchecked`. A pending run still counts as a success in `soundwave_last_run_success`
- A findings API push or a registration that raises no longer stops the other outputs. A findings API push that returned a failure never did

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
