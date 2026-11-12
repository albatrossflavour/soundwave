# What Soundwave sends to PE

## Why every push carries every finding

Every push carries the full merged set. VR replaces a transformer's data per node on each push, so pushing one cassette's findings on their own wipes the other's.

A host that was scanned and came back clean is pushed with an empty list. VR keeps whatever it had for a node left out of a push, so dropping clean hosts would leave a patched node showing its old findings indefinitely.

## Confidence

Cassettes record every finding with the scanner's own confidence (Greenbone's QoD, Vuls's detection confidence) and don't filter on it. Soundwave drops anything below `min_confidence` on the way into VR, because VR has nowhere to store a confidence and a QoD 30 finding there looks exactly like a certain one. The default, 70, is gvmd's own minimum. The cassette files keep every finding.

Soundwave also keeps findings with no CVSS score out of VR, and they stay in the cassette files. VR has no way to show a missing score, and 0.0 would read as no impact.

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

## A second destination

`findings_api_host` (default unset) also sends each cassette, unmerged and with every confidence, to a findings API on `findings_api_port` (default 10051). It's for the author's own consumer, whose API isn't published, so leave it unset. Each cassette goes as its own source in three calls: the list of checks the scanner ran, then one call per host, then a completion that clears hosts the run didn't mention. Bodies are gzipped, and the client authenticates with the node's agent certificate. That push is independent of the VR one, so a findings API that's down doesn't stop findings reaching PE.

## Troubleshooting

PE refuses a scan date it already holds with a 409, before reading the body, and closes the connection. With a large body that shows up here as an SSL EOF rather than a 409. Soundwave records the scan date PE last accepted in `/var/lib/soundwave/pe-push-state.json` and doesn't resend it. To force a push, for example after VR has been reset, delete that file.
