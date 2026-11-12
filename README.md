# soundwave

Soundwave merges vulnerability findings from any number of scanners and pushes one set into Puppet Enterprise's Vulnerability Remediation (VR) service. It sends the same `add-results` payload as Puppet's `nessus_transformer`, so PE matches findings to managed nodes the same way.

Each scanner plugs in as a cassette, and adding a scanner means adding a cassette, with no change to Soundwave itself. The module ships with two: `openvas`, for Greenbone installed by [`albatrossflavour-openvas`](https://github.com/albatrossflavour/openvas), and `vuls`, for Vuls installed by [`albatrossflavour-vuls`](https://github.com/albatrossflavour/vuls). With the openvas cassette on, Soundwave goes on the Greenbone host, because that cassette reaches gvmd through the stack's own container.

## Cassettes

Soundwave never parses a scanner itself, and knows nothing about any of them. A cassette reads one scanner and writes the scanner-neutral findings file described in [docs/findings-file.md](docs/findings-file.md), and Soundwave merges every file in the cassette directory and pushes the result.

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

## Requirements

- Puppet Enterprise with Vulnerability Remediation enabled, and a PE RBAC token with permission to push to it
- TCP 8146 open from the Soundwave node to the PE primary, where the VR service listens. Without it registration times out, and the log says it couldn't reach the host and port
- Puppet 8 and an agent certificate. Secrets are encrypted to it with `node_encrypt`, and the push authenticates with it
- Greenbone from `albatrossflavour-openvas` on the same node, for the openvas cassette
- Vuls from `albatrossflavour-vuls` on the same node, for the vuls cassette
- Python 3.9 or later from the OS. Ubuntu 22.04, 24.04, and 26.04, Debian 11 and 12, Red Hat 8 and 9, and AlmaLinux 9 and 10 are supported. A bare install on AlmaLinux 9 and 10 and Ubuntu 26.04 was tested on 2026-11-09, and the author runs it on Ubuntu 24.04

## Getting started

Install and scan with Greenbone or Vuls first, using [the openvas guide](https://github.com/albatrossflavour/openvas/blob/main/docs/guide/README.md) or [the vuls guide](https://github.com/albatrossflavour/vuls/blob/main/docs/guide/README.md). Each works without Soundwave and ends by handing over to [the Soundwave install guide](docs/guide/README.md), which goes from a working scanner to findings in PE one step at a time, with a check at the end of each.

## Reference

- Why every push carries every finding, the confidence and CVSS filters, package remediation, the second destination, and forcing a push: [what Soundwave sends to PE](docs/pushing.md)
- The findings file every cassette writes, and correlation: [findings file](docs/findings-file.md)
- Every parameter: [REFERENCE.md](REFERENCE.md)
- What changed in each release: [CHANGELOG.md](CHANGELOG.md)

## Limitations

- PE accepts one vulnerability integration, so run one Soundwave per PE and add each scanner as a cassette
- The openvas cassette has to run on the Greenbone host, because it reaches gvmd through the stack's own container
- No Litmus acceptance tests. The unit specs cover every resource, and the install was tested by hand on AWS

## Development

```shell
pdk test unit
cd files/python && python3 -m pytest tests -q
```

The Python tests need pytest. On Debian and Ubuntu, `python3 -m venv` fails without the `python3-venv` package, and `uvx pytest tests -q` is the quickest way round that.

## Origin

The structure, the PE client (`api.py`, `pe_transformer_client.py`, `config_helper.py`), and the systemd, Python, and `node_encrypt` scaffolding come from Puppet's `nessus_transformer`. The Greenbone client, the cassettes, and the findings format are this module's own.
