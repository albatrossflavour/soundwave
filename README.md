# soundwave

[Vulnerability Remediation](https://help.puppet.com/pe/current/topics/advanced-patching-vulnerability-remediation.htm) (VR) in Puppet Enterprise Advanced takes findings from one vulnerability integration. Soundwave is that integration, so every scanner's findings are gathered and merged in one place and pushed into VR together, where PE matches them to your nodes and shows which ones Puppet can patch.

Each scanner plugs in as a cassette, and the module ships with cassettes for [Greenbone](https://github.com/albatrossflavour/openvas) and [Vuls](https://github.com/albatrossflavour/vuls). A cassette reads one scanner and writes a scanner-neutral [findings file](https://github.com/albatrossflavour/soundwave/blob/main/docs/findings-file.md), and Soundwave merges every cassette's file and pushes one set. Adding a scanner means adding a cassette, with no change to Soundwave or to PE.

## Requirements

- Puppet Enterprise Advanced with [VR enabled](https://help.puppet.com/pe/current/topics/advanced-patching.htm), and a PE RBAC token that can push to it, or [a PE user the primary manages](#pe-access) so the node mints its own
- TCP 8146 open from the Soundwave node to the PE primary, where VR listens
- Puppet 8 or 9 and an agent certificate. Secrets are encrypted to it with `node_encrypt`, and the push authenticates with it
- Python 3.9 or later from the OS, on Ubuntu 22.04, 24.04, or 26.04, Debian 11 or 12, Red Hat 8 or 9, or AlmaLinux 9 or 10
- A working scanner on the same node. Each cassette reads its scanner locally, so Soundwave goes on the scanner node. To use both scanners, run them on the same node

## Installing

Get a scanner working first with [the openvas guide](https://github.com/albatrossflavour/openvas/blob/main/docs/guide/README.md) or [the vuls guide](https://github.com/albatrossflavour/vuls/blob/main/docs/guide/README.md). Each ends by handing over to [the Soundwave install guide](https://github.com/albatrossflavour/soundwave/blob/main/docs/guide/README.md), which goes from a working scanner to findings in VR, with a check at the end of each step.

The only setting Soundwave has to be given is how it gets its PE token, `pe_token` or `token_password`, as [PE access](#pe-access) covers.

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

## Cassettes

| Cassette | Reads | Mostly finds | Turned on by |
|---|---|---|---|
| `openvas` | Greenbone, from [the openvas module](https://github.com/albatrossflavour/openvas) | Network, TLS, and configuration problems, and Ubuntu and Debian package advisories | `openvas_cassette`, on by default |
| `vuls` | Vuls, from [the vuls module](https://github.com/albatrossflavour/vuls) | EL package errata and Windows KBs | `vuls_cassette`, off by default |

## What a run does

A systemd timer starts a run nightly, and the `run_soundwave` task starts one on demand. Each run:

1. Runs every cassette that's turned on. One that fails leaves its previous file in place and the run carries on
2. Marks every check with CISA KEV and FIRST EPSS, if `threat_intel` is on
3. Sends each cassette, unmerged, to the findings API, if `findings_api_host` is set
4. Registers with PE, if it hasn't already. PE holds a new integration as pending until someone accepts it in the console
5. Merges the cassette files and posts the result to VR. This is the only part skipped while PE still has the integration pending
6. Writes `metrics_file`, if set, with each cassette's age and whether PE has accepted the integration

## Optional settings

| Setting | What it does | Read |
|---|---|---|
| `metrics_file` | Writes each run's result as a node_exporter textfile, so a stale cassette or an integration nobody has accepted can be alerted on | [Install guide, step 3](https://github.com/albatrossflavour/soundwave/blob/main/docs/guide/03-accept.md) |
| `min_confidence` | The confidence a finding needs to reach VR, 70 by default. The cassette files keep every finding | [Confidence](https://github.com/albatrossflavour/soundwave/blob/main/docs/pushing.md#confidence) |
| `threat_intel`, `threat_intel_in_vr` | Marks every check with CISA KEV and FIRST EPSS, whether or not its scanner reports them, and can show the marks in PE | [Known exploited and EPSS](https://github.com/albatrossflavour/soundwave/blob/main/docs/pushing.md#known-exploited-and-epss) |
| `correlate`, `compose_findings` | Counts where two scanners report what looks like the same weakness, and can send each such set to VR as one record. By default both are sent | [Correlating](https://github.com/albatrossflavour/soundwave/blob/main/docs/findings-file.md#correlating) |
| `findings_api_host` | Sends every cassette, unmerged and with every finding, to a findings API as well as to VR | [Install guide, step 4](https://github.com/albatrossflavour/soundwave/blob/main/docs/guide/04-findings-api.md) |

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
