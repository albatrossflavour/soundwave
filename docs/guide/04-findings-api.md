# 4. Send every finding to a findings API

## Why

VR's schema has no field for a confidence, a port, or a fix type, and Soundwave keeps findings below `min_confidence` or with no CVSS score out of it. With `findings_api_host` set, each run also sends every cassette to a findings API, unmerged and with every finding, so whatever reads it sees each scanner on its own and how old that scanner's data is.

This step is optional, and the API isn't published yet, so skip it unless you run something that serves it.

The findings API push goes on every run, including while the transformer is still pending in PE, so step 3 doesn't have to be done first.

## Before you start

- Step 2 done
- The findings API turned on, on a host the Soundwave node can reach on TCP 10051
- The Soundwave node's certname on that API's push allowlist. Soundwave authenticates with its Puppet agent certificate, so there's no token or password to set here, and the API's own certificate has to come from the same PE CA

## Do it

In Hiera, beside the settings from step 2:

```yaml
soundwave::findings_api_host: <host>
```

The port defaults to 10051. Set [`findings_api_port`](../../REFERENCE.md#-soundwave--findings_api_port) if yours differs.

Run the agent, then start a run:

```sh
sudo puppet agent -t
sudo systemctl start soundwave.service
sudo journalctl -u soundwave.service -o cat --since -10min | grep -E 'findings API|SSL error|Could not reach'
```

The run logs an `API call to /api/v1/findings returned status` line for every host, so the `grep` keeps the lines that matter.

## Done when

The log has two lines from each cassette, such as:

```text
findings API: openvas, 177 checks pushed
findings API: openvas complete, 35 of 35 host(s) accepted
```

`metrics_file`, if set, has `soundwave_findings_api_hosts_accepted` with the hosts accepted across every cassette.

Check the log or that metric, not the unit's exit status. A findings API push that fails is logged and the run carries on to VR, so the unit still succeeds and `soundwave_last_run_success` stays at 1.

## If it fails

| You see | Because | Do |
|---|---|---|
| No `findings API:` lines at all | `findings_api_host` hasn't reached the node, or no cassette file could be read | Check `findings_api_host` in `/opt/puppetlabs/soundwave/python/config.ini`, and that the cassettes logged their lines as in step 2 |
| `Could not reach <host>:10051` | The port is blocked, the API isn't turned on, or the name resolves elsewhere. The message ends "to PE" even when the host it couldn't reach is the findings API | Check the firewall between the two, and that the API is listening |
| `SSL error`, then `failed before a response could be read` | The API's certificate isn't from the PE CA this node trusts, or the API doesn't trust this node's | Both ends need certificates from the same PE CA |
| `findings API refused openvas's check catalogue: HTTP 403` | This node's certname isn't on the API's push allowlist | Add it there |
| `host(s) refused and swept` | The API refused those hosts and accepted the others. Each refusal is logged above it with the field the API objected to | Fix the field the message names. The API keeps the other hosts' findings and drops the refused hosts' |

## Next

[What Soundwave sends to PE](../pushing.md) covers what goes to VR and why.
