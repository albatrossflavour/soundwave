# 3. Accept it in PE

## Why

PE holds a new integration as pending until someone accepts it, and pushes nothing from it until then.

## Before you start

- Step 2 done, with `Transformer is Pending Activation` in the log

## Do it

In the PE console, accept the pending transformer on the vulnerabilities page. Then start another run:

```sh
sudo systemctl start soundwave.service
sudo journalctl -u soundwave.service -o cat -n 40
```

## Done when

The log has:

```text
Transformer ID Registered and Active.
Results added successfully
```

and the vulnerabilities page in the PE console shows findings against your nodes.

From then on the timer runs nightly. A night with no new scan logs `PE already holds scan date ...; not pushing`, which is normal. To watch it, set `metrics_file` and alert on the cassette timestamps. See [Parameters](../../README.md#parameters).

## If it fails

| You see | Because | Do |
|---|---|---|
| `Registration successful. Transformer is Pending Activation.` again | It hasn't been accepted | Accept it in the console |
| `Error adding results` | PE refused the push | The message carries PE's reason, such as a token that has expired or can't push to Vulnerability Remediation |
| A scanned node has no findings in PE | PE matches findings to nodes by certname, and the scanner reported another name | With Greenbone, check the node's address is in `/opt/greenbone-community-container/scan-hosts.json`. See `host_map_file` in [Parameters](../../README.md#parameters) |
| Findings you expected are missing | Below `min_confidence`, or with no CVSS score | See [Confidence](../../README.md#confidence). The cassette files keep them |
| PE was reset and nothing is pushed | Soundwave remembers the last scan date PE accepted | See [Troubleshooting](../../README.md#troubleshooting) |

## Next

To add a scanner later, follow its guide, then turn its cassette on as in step 2.
