# soundwave

[Vulnerability Remediation](https://help.puppet.com/pe/current/topics/advanced-patching-vulnerability-remediation.htm) (VR) in Puppet Enterprise Advanced takes findings from one vulnerability integration. Soundwave is that integration, so every scanner's findings are gathered and merged in one place and pushed into VR together, where PE matches them to your nodes and shows which ones Puppet can patch.

Each scanner plugs in as a cassette, and the module ships with cassettes for [Greenbone](https://github.com/albatrossflavour/openvas) and [Vuls](https://github.com/albatrossflavour/vuls). A cassette reads one scanner and writes a scanner-neutral [findings file](https://github.com/albatrossflavour/soundwave/blob/main/docs/findings-file.md), and Soundwave merges every cassette's file and pushes one set. Adding a scanner means adding a cassette, with no change to Soundwave or to PE.

## Cassettes

| Cassette | Reads | Mostly finds | Turned on by |
|---|---|---|---|
| `openvas` | Greenbone, from [the openvas module](https://github.com/albatrossflavour/openvas) | Network, TLS, and configuration problems, and Ubuntu and Debian package advisories | `openvas_cassette`, on by default |
| `vuls` | Vuls, from [the vuls module](https://github.com/albatrossflavour/vuls) | EL package errata and Windows KBs | `vuls_cassette`, off by default |

Each cassette reads its scanner on the node it runs on, so Soundwave goes on the scanner node, and with both scanners they share it. Where two scanners report what looks like the same weakness, Soundwave counts it and by default still sends both. See [Correlating](https://github.com/albatrossflavour/soundwave/blob/main/docs/findings-file.md#correlating).

## How it works

A nightly systemd timer runs each cassette that's turned on, records the cassette metrics, and pushes each cassette to the findings API if `findings_api_host` is set. It then registers with PE if it hasn't already, merges the cassette files, and posts the result to VR. A cassette that fails leaves its previous file in place and the push still goes, so one scanner's problem doesn't hold back the others. `metrics_file` reports each cassette's age, so a stale one shows up, and whether VR has accepted the transformer. Until it has, the VR push is skipped and the metrics are written anyway. The `run_soundwave` Bolt task starts a run on demand.

With `threat_intel` on, every check is also marked with CISA KEV and FIRST EPSS, whether or not its scanner reports them. See [what Soundwave sends to PE](https://github.com/albatrossflavour/soundwave/blob/main/docs/pushing.md).

## Requirements

- Puppet Enterprise Advanced with [VR enabled](https://help.puppet.com/pe/current/topics/advanced-patching.htm), and a PE RBAC token that can push to it, or [a PE user the primary manages](#pe-access) so the node mints its own
- TCP 8146 open from the Soundwave node to the PE primary, where VR listens
- Puppet 8 or 9 and an agent certificate. Secrets are encrypted to it with `node_encrypt`, and the push authenticates with it
- Python 3.9 or later from the OS, on Ubuntu 22.04, 24.04, or 26.04, Debian 11 or 12, Red Hat 8 or 9, or AlmaLinux 9 or 10

## PE access

Soundwave authenticates to VR with a PE RBAC token. There are two ways to give it one, and the class takes exactly one of them.

`pe_token` is a token made by hand and passed in, as [the install guide](https://github.com/albatrossflavour/soundwave/blob/main/docs/guide/01-pe.md) does. It works anywhere, but it sits in the catalogue and someone has to replace it before it expires.

`token_password` lets the primary own Soundwave's PE user and the Soundwave node mint its own token. The primary declares `soundwave::rbac_user`, which makes a `Soundwave` role that can register a transformer and push to VR and nothing else, and a `soundwave` user holding only that role. The Soundwave node is given the same password. Each Puppet run there, `rbac_token` checks the token in `token_file` and mints a new one when it is missing, no longer valid, or older than `token_renew_after`, then revokes the old one. Soundwave reads the file at the start of every run, so a renewed token is picked up with no restart, and no token is ever in a catalogue.

Both need the RBAC types from [conductor-rbac](https://github.com/albatrossflavour/conductor-rbac), the fork whose `rbac_token` renews. It is not a dependency in `metadata.json`, since only this setup needs it, so add it to the Puppetfile:

```ruby
mod 'rbac',
  git:    'git@github.com:albatrossflavour/conductor-rbac.git',
  branch: 'modernise'
```

Pass the password through `node_encrypt::secret`, on both sides. A `Sensitive` class parameter is still written into the catalogue in plaintext, because class parameters are recorded there. `node_encrypt::secret` encrypts it to the node the catalogue is for, so the catalogue carries ciphertext only that node can open.

On the primary:

```puppet
class { 'soundwave::rbac_user':
  password => node_encrypt::secret(lookup('soundwave::rbac_password')),
}
```

On the Soundwave node:

```puppet
class { 'soundwave':
  token_password => node_encrypt::secret(lookup('soundwave::rbac_password')),
}
```

The node mints its token from `pe_host`, the PE primary, on port 4433. Set `token_server` and `token_port` if the console is somewhere else. Tokens last `token_lifetime` (30 days) and are replaced after `token_renew_after` (21 days), so the agent has a week of runs to renew one before it expires.

## Getting started

Get a scanner working first with [the openvas guide](https://github.com/albatrossflavour/openvas/blob/main/docs/guide/README.md) or [the vuls guide](https://github.com/albatrossflavour/vuls/blob/main/docs/guide/README.md). Each ends by handing over to [the Soundwave install guide](https://github.com/albatrossflavour/soundwave/blob/main/docs/guide/README.md), which goes from a working scanner to findings in VR, with a check at the end of each step.

## Reference

- What Soundwave sends to VR and why, and forcing a push: [what Soundwave sends to PE](https://github.com/albatrossflavour/soundwave/blob/main/docs/pushing.md)
- The findings file every cassette writes, and correlation: [findings file](https://github.com/albatrossflavour/soundwave/blob/main/docs/findings-file.md)
- Every parameter: [REFERENCE.md](https://github.com/albatrossflavour/soundwave/blob/main/REFERENCE.md)
- What changed in each release: [CHANGELOG.md](https://github.com/albatrossflavour/soundwave/blob/main/CHANGELOG.md)

## Development

```shell
pdk test unit
cd files/python && python3 -m pytest tests -q
```

The Python tests need pytest. On Debian and Ubuntu, `python3 -m venv` fails without the `python3-venv` package, and `uvx pytest tests -q` is the quickest way round that. There are no Litmus acceptance tests, and the install was tested by hand on AWS.
