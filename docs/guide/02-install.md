# 2. Install Soundwave

## Why

This installs Soundwave and its nightly timer, and the first run registers it with PE.

## Before you start

- Step 1 done, with the token encrypted
- The module and its dependencies (`puppet-python`, `puppet-systemd`, `puppetlabs-stdlib`, and `puppetlabs-node_encrypt`) in your Puppetfile, and deployed to the scanner's environment
- With Greenbone, [the openvas guide's step 5](https://github.com/albatrossflavour/openvas/blob/main/docs/guide/05-soundwave.md) done, so the observer user logs in
- With Vuls, a complete run recorded, as in [the vuls guide's step 5](https://github.com/albatrossflavour/vuls/blob/main/docs/guide/05-soundwave.md)

## Do it

In Hiera, at a level the scanner node reads:

```yaml
soundwave::pe_token: ENC[PKCS7,...]
```

Add the cassettes you need. The openvas cassette is on by default and the vuls one is off:

```yaml
soundwave::vuls_cassette: true        # with Vuls
soundwave::openvas_cassette: false    # without Greenbone
```

If the scanner's catalogue is compiled by a compiler rather than the primary, also set `soundwave::pe_host` to the primary, as step 1 says.

The openvas cassette needs nothing else here. It logs in with `openvas::scan_observer_user` and `openvas::scan_observer_password`, and reads the module's host map, by itself.

Add the class to the scanner's profile, run the agent, then start a run:

```puppet
include soundwave
```

```sh
sudo puppet agent -t
sudo systemctl start soundwave.service
sudo journalctl -u soundwave.service -o cat -n 40
```

## Done when

The log has a line from each cassette you turned on, such as:

```text
openvas: 35 hosts (24 scanned), 177 checks, 1351 findings, 0 dropped -> /var/lib/soundwave/cassettes/openvas.json
vuls cassette: 31 hosts (31 scanned), 1083 checks, 1177 findings, 11371 dropped, run 2026-11-08T22-00-15+1100
```

Your counts will differ. The vuls cassette's `dropped` counts findings it set aside because no fix exists yet, or the fix is for another package stream or kernel, and the cassette file records each one.

On this first run the log also has:

```text
Registration successful. Transformer is Pending Activation.
```

## If it fails

| You see | Because | Do |
|---|---|---|
| `Response Error 400. Authentication failed` | gvmd refused the observer login. The PE token isn't involved | [The openvas guide's step 5](https://github.com/albatrossflavour/openvas/blob/main/docs/guide/05-soundwave.md) |
| The catalogue fails with `set soundwave::gmp_password` | The openvas cassette is on, and no observer is set | Set the observer in [the openvas guide's step 5](https://github.com/albatrossflavour/openvas/blob/main/docs/guide/05-soundwave.md), or turn the openvas cassette off |
| `Could not reach <primary>:8146` | The port is blocked, or the name resolves elsewhere | Step 1 |
| `vuls cassette: no complete Vuls run recorded` | Vuls hasn't finished a run | [The vuls guide's step 4](https://github.com/albatrossflavour/vuls/blob/main/docs/guide/04-scan.md) |
| `Transformer with different ID is in Active or Pending State.` | Another integration is registered with PE | Remove it in PE. PE accepts one |

A cassette that fails leaves its previous file and the run carries on, so read the whole log.

## Next

[Accept it in PE](03-accept.md).
