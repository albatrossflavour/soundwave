# soundwave

Soundwave merges vulnerability findings from any number of scanners and pushes one set into Puppet Enterprise's Vulnerability Remediation (VR) service. It sends the same `add-results` payload as Puppet's `nessus_transformer`, so PE matches findings to managed nodes the same way.

Each scanner plugs in as a cassette, and adding a scanner means adding a cassette, with no change to Soundwave itself. The module ships with two: `openvas`, for Greenbone installed by [`albatrossflavour-openvas`](https://github.com/albatrossflavour/openvas), and `vuls`, for Vuls installed by [`albatrossflavour-vuls`](https://github.com/albatrossflavour/vuls). With the openvas cassette on, Soundwave goes on the Greenbone host, because that cassette reaches gvmd through the stack's own container.

To install it, follow [the install guide](docs/guide/README.md), which starts from a working scanner and ends with findings in PE. This README is the reference the guide links to.

## Cassettes

Soundwave never parses a scanner itself, and knows nothing about any of them. A cassette reads one scanner and writes the scanner-neutral findings file described in [docs/findings-file.md](docs/findings-file.md), and Soundwave merges every file in the cassette directory and pushes the result. Supporting another scanner means writing another cassette.

| Cassette | Scanner | Mostly finds | Turned on by |
|---|---|---|---|
| `openvas` | Greenbone, over GMP | Network, TLS, and configuration problems, and Ubuntu and Debian package advisories | `openvas_cassette`, on by default |
| `vuls` | Vuls, from the run the vuls module last recorded as complete | EL package errata and Windows KBs | `vuls_cassette`, off by default |

Cassettes can overlap, and Soundwave counts the findings that look like the same weakness reported by two scanners, and by default still sends both. See [Correlating](docs/findings-file.md#correlating).

## How it works

One systemd timer runs three steps in order:

1. The openvas cassette pulls every task's latest finished report from gvmd and writes `openvas.json` into the cassette directory. gvmd only listens on a unix socket inside its containers, so the cassette runs `gvm-cli` inside the stack's own `gvm-tools` container, and GMP never goes on the network.
2. The vuls cassette, when it's on, reads the run named in `/var/lib/vuls/last-complete-run` and writes `vuls.json`. It never reads the newest run directory, which may be a scan still in progress, and with no complete run it leaves the previous file alone.
3. Soundwave registers with PE if it hasn't already, merges every cassette in the directory, and posts to the VR API on port 8146.

A cassette that fails leaves its previous file in place and the push still goes, so a Vuls problem doesn't hold back Greenbone's findings or the other way round. The failed cassette's file then ages, which is what `soundwave_cassette_generated_timestamp_seconds` is for (see `metrics_file`).

The `run_soundwave` Bolt task starts a run on demand.

## Why every push carries every finding

Every push carries the full merged set. VR replaces a transformer's data per node on each push, so pushing one cassette's findings on their own wipes the other's.

A host that was scanned and came back clean is pushed with an empty list. VR keeps whatever it had for a node left out of a push, so dropping clean hosts would leave a patched node showing its old findings indefinitely.

## Confidence

Cassettes record every finding with the scanner's own confidence (Greenbone's QoD, Vuls's detection confidence) and don't filter on it. Soundwave drops anything below `min_confidence` on the way into VR, because VR has nowhere to store a confidence and a QoD 30 finding there looks exactly like a certain one. The default, 70, is gvmd's own minimum. The cassette files keep every finding.

Soundwave also keeps findings with no CVSS score out of VR, and they stay in the cassette files. VR has no way to show a missing score, and 0.0 would read as no impact.

## Requirements

- Puppet Enterprise with Vulnerability Remediation enabled, and a PE RBAC token with permission to push to it
- TCP 8146 open from the Soundwave node to the PE primary, where the VR service listens. Without it registration times out, and the log says it couldn't reach the host and port
- Puppet 8 and an agent certificate. Secrets are encrypted to it with `node_encrypt`, and the push authenticates with it
- Greenbone from `albatrossflavour-openvas` on the same node, for the openvas cassette
- Vuls from `albatrossflavour-vuls` on the same node, for the vuls cassette
- Python 3.9 or later from the OS. Ubuntu 22.04, 24.04, and 26.04, Debian 11 and 12, Red Hat 8 and 9, and AlmaLinux 9 and 10 are supported. A bare install on AlmaLinux 9 and 10 and Ubuntu 26.04 was tested on 2026-11-09, and the author runs it on Ubuntu 24.04

## Usage

Soundwave reads Greenbone as a GMP user, and doesn't create one. The openvas module creates a read-only one with `openvas::scan_observer_user` and `openvas::scan_observer_password`, which can see the managed tasks and their reports and nothing else, and Soundwave logs in with those same two settings. On the Greenbone node, with `include openvas` already there:

```yaml
openvas::scan_observer_user: 'reader'
openvas::scan_observer_password: >
  ENC[PKCS7,...]
soundwave::pe_token: >
  ENC[PKCS7,...]
```

```puppet
include soundwave
```

Run the agent once before the first Soundwave run, so the user exists in gvmd. The reconciler won't create it while a scan is running. If the openvas cassette logs `Response Error 400. Authentication failed`, gvmd has refused the user and password, and the PE token isn't involved.

Soundwave also picks up the openvas module's `scan-hosts.json`, so findings reach PE under each node's certname. Add `soundwave::vuls_cassette: true` when Vuls runs on the same node.

Without Greenbone, set `soundwave::openvas_cassette: false` and leave out the GMP settings. Soundwave then goes on whichever node the cassettes you use need.

The first run registers Soundwave with PE. Accept the pending transformer on the vulnerabilities page in the PE console, and each run after that pushes findings.

## Parameters

`REFERENCE.md` has the full list. The ones you're most likely to set:

- `pe_token` (required): the PE token for VR
- `gmp_username` and `gmp_password` (default: `openvas::scan_observer_user` and `openvas::scan_observer_password`): the GMP account that reads reports. With no observer the user is `admin`, and the password has to be set
- `pe_host` (default: the Puppet server that compiled the catalogue): the PE primary to push to. Set it when that server is a compiler, or when there is no server at all
- `openvas_cassette` (default `true`) and `vuls_cassette` (default `false`): which cassettes run before each push
- `min_confidence` (default `70`): the confidence below which findings stay out of VR
- `sync_schedule` (default `daily`): the systemd `OnCalendar` expression for the timer
- `scan_name` (default unset): read only the named task's report, rather than every task's latest
- `host_map_file` (default: the openvas module's `scan-hosts.json` with the openvas cassette on, otherwise unset): a JSON object of scanned address to certname, such as `{"192.0.2.10": "web01.example.com"}`. PE matches findings to nodes by certname, and gvmd only knows the address and its reverse DNS name, so where those differ PE drops the host's findings without saying so. The openvas module writes this file from PuppetDB, as `scan-hosts.json` in its install directory
- `metrics_file` (default unset): a node_exporter textfile written on each run. It carries each cassette's age, scan end time, and finding and host counts, and the run's own success, push status code, and counts. Alert on the timestamps rather than on the unit succeeding: a push PE refuses as a repeat can still leave the unit green
- `vuls_results_dir`, `vuls_complete_file`, `vuls_config`, `vuls_windows_config`, and `vuls_database`: where the vuls cassette finds the vuls module's results. The defaults are that module's own paths
- `cassette_dir` (default `/var/lib/soundwave/cassettes`): where cassettes write their files. Set `cassette_group` (default `root`) when a cassette runs as another user, outside Soundwave's own service, and needs to write there
- `post_body_filepath` (default unset): write the JSON sent to PE here, for debugging

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

## Tests

```shell
pdk test unit
cd files/python && python3 -m pytest tests -q
```

The Python tests need pytest. On Debian and Ubuntu, `python3 -m venv` fails without the `python3-venv` package, and `uvx pytest tests -q` is the quickest way round that.

## Origin

The structure, the PE client (`api.py`, `pe_transformer_client.py`, `config_helper.py`), and the systemd, Python, and `node_encrypt` scaffolding come from Puppet's `nessus_transformer`. The Greenbone client, the cassettes, and the findings format are this module's own.

## Limitations

- PE accepts one vulnerability integration, so run one Soundwave per PE and add each scanner as a cassette
- The openvas cassette has to run on the Greenbone host, because it reaches gvmd through the stack's own container
- No Litmus acceptance tests. The unit specs cover every resource, and the install was tested by hand on AWS
