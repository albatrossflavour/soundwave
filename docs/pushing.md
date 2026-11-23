# What Soundwave sends to PE

## Why every push carries every finding

Every push carries the full merged set. VR replaces a transformer's data per node on each push, so pushing one cassette's findings on their own wipes the other's.

A host that was scanned and came back clean is pushed with an empty list. VR keeps whatever it had for a node left out of a push, so dropping clean hosts would leave a patched node showing its old findings indefinitely.

## Confidence

Cassettes record every finding with the scanner's own confidence (Greenbone's QoD, Vuls's detection confidence) and don't filter on it. Soundwave drops anything below `min_confidence` on the way into VR, because VR has nowhere to store a confidence and a QoD 30 finding there looks exactly like a certain one. The default, 70, is gvmd's own minimum. The cassette files keep every finding.

Soundwave also keeps findings with no CVSS score out of VR, and they stay in the cassette files. VR has no way to show a missing score, and 0.0 would read as no impact.

## Known exploited and EPSS

Whether a finding shows as known exploited depends on the scanner. Vuls and Nessus report CISA KEV, and Greenbone and Rapid7 don't, so their findings all read as not exploited. None of the supported scanners reports EPSS.

With `threat_intel` on, Soundwave reads CISA's KEV catalogue and FIRST's EPSS scores, matches them to each check's CVEs, and marks the check before anything is pushed, so every cassette gets the same answer.

- `download` fetches both files into `threat_intel_dir` at the start of each run. A failed download keeps the previous file and the run carries on
- `directory` reads whatever has been copied into `threat_intel_dir`, for a node with no internet access. The files are CISA's `known_exploited_vulnerabilities.json` and FIRST's `epss_scores-current.csv.gz` (or that file unpacked as `.csv`)
- `off` is the default

`kev_url` and `epss_url` can point `download` at an internal mirror.

EPSS is free to use and FIRST asks for attribution, so credit it wherever the scores are shown.

VR's schema has no field for either, so by default the PE console looks the same with `threat_intel` on. The marks go to the cassette files and the findings API. `threat_intel_in_vr` puts them at the front of each finding's summary in PE, for example `Known exploited (CISA KEV). EPSS 0.91, 99.8th percentile.`. VR has no banner or badge field, so the summary is the only place they can show.

`metrics_file` gains two metrics, each labelled by `feed` (`kev` or `epss`). `soundwave_threat_intel_feed_timestamp_seconds` is the feed's own publish date, so a feed that has stopped updating shows as old even when the download works. `soundwave_threat_intel_checks_marked` is how many checks the feed marked on the last run.

## Package remediation

VR carries a list of packages per finding, and PE marks a finding patchable on a node when one of them is among the node's available updates from `pe_patch`. Greenbone has no structured field for that, but its package checks print one block per vulnerable package:

```text
Vulnerable package:   curl
Installed version:    curl-7.68.0-1ubuntu2.25
Fixed version:      >=curl-7.68.0-1ubuntu2.25+esm3
```

The package name comes from the `Vulnerable package` line and nowhere else, so it's the bare name PE expects (`curl`, `libcurl3-gnutls`). Version checks on files and web applications have no package line and send an empty list, because their fixed version isn't something a node can install.

Ubuntu publishes some fixes only to Ubuntu Pro archives (versions with `~esm1`, `+esm1`, or `+fips1`). Those packages are still sent, so PE marks the finding patchable on a node with Pro attached and not on one without. The finding's solution text in PE says it's Pro-only.

Greenbone names every distro advisory `Ubuntu: Security Advisory (USN-7917-1)`. The openvas cassette renames it `fonttools: Ubuntu USN-7917-1`, from the advisory's package list, so PE's list says which package it affects.

## Troubleshooting

PE refuses a scan date it already holds with a 409, before reading the body, and closes the connection. With a large body that shows up here as an SSL EOF rather than a 409. Soundwave records the scan date PE last accepted in `/var/lib/soundwave/pe-push-state.json` and doesn't resend it. To force a push, for example after VR has been reset, delete that file.
