# soundwave

[Vulnerability Remediation](https://help.puppet.com/pe/current/topics/advanced-patching-vulnerability-remediation.htm) (VR) in Puppet Enterprise Advanced takes findings from one vulnerability integration. Soundwave is that integration, so every scanner's findings are gathered and merged in one place and pushed into VR together, where PE matches them to your nodes and shows which ones Puppet can patch.

Each scanner plugs in as a cassette, and the module ships with cassettes for [Greenbone](https://github.com/albatrossflavour/openvas) and [Vuls](https://github.com/albatrossflavour/vuls). A cassette reads one scanner and writes a scanner-neutral [findings file](docs/findings-file.md), and Soundwave merges every cassette's file and pushes one set. Adding a scanner means adding a cassette, with no change to Soundwave or to PE.

## Cassettes

| Cassette | Reads | Mostly finds | Turned on by |
|---|---|---|---|
| `openvas` | Greenbone, from the openvas module | Network, TLS, and configuration problems, and Ubuntu and Debian package advisories | `openvas_cassette`, on by default |
| `vuls` | Vuls, from the vuls module | EL package errata and Windows KBs | `vuls_cassette`, off by default |

Each cassette reads its scanner on the node it runs on, so Soundwave goes on the scanner node, and with both scanners they share it. Where two scanners report what looks like the same weakness, Soundwave counts it and by default still sends both. See [Correlating](docs/findings-file.md#correlating).

## How it works

A nightly systemd timer runs each cassette that's turned on, then registers with PE if it hasn't already, merges the cassette files, and posts the result to VR. A cassette that fails leaves its previous file in place and the push still goes, so one scanner's problem doesn't hold back the others. `metrics_file` reports each cassette's age, so a stale one shows up. The `run_soundwave` Bolt task starts a run on demand.

## Requirements

- Puppet Enterprise Advanced with [VR enabled](https://help.puppet.com/pe/current/topics/advanced-patching.htm), and a PE RBAC token that can push to it
- TCP 8146 open from the Soundwave node to the PE primary, where VR listens
- Puppet 8 and an agent certificate. Secrets are encrypted to it with `node_encrypt`, and the push authenticates with it
- Python 3.9 or later from the OS, on Ubuntu 22.04, 24.04, or 26.04, Debian 11 or 12, Red Hat 8 or 9, or AlmaLinux 9 or 10

## Getting started

Get a scanner working first with [the openvas guide](https://github.com/albatrossflavour/openvas/blob/main/docs/guide/README.md) or [the vuls guide](https://github.com/albatrossflavour/vuls/blob/main/docs/guide/README.md). Each ends by handing over to [the Soundwave install guide](docs/guide/README.md), which goes from a working scanner to findings in VR, with a check at the end of each step.

## Reference

- What Soundwave sends to VR and why, and forcing a push: [what Soundwave sends to PE](docs/pushing.md)
- The findings file every cassette writes, and correlation: [findings file](docs/findings-file.md)
- Every parameter: [REFERENCE.md](REFERENCE.md)
- What changed in each release: [CHANGELOG.md](CHANGELOG.md)

## Development

```shell
pdk test unit
cd files/python && python3 -m pytest tests -q
```

The Python tests need pytest. On Debian and Ubuntu, `python3 -m venv` fails without the `python3-venv` package, and `uvx pytest tests -q` is the quickest way round that. There are no Litmus acceptance tests, and the install was tested by hand on AWS.
