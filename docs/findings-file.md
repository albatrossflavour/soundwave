# The findings file

**Soundwave is the engine. Cassettes are inputs. This file is the interface between them, and it is the only interface there is.**

That separation is the point of the whole design, so it is worth being blunt about what it obliges. A cassette reads one scanner and writes this format. Soundwave reads this format and knows nothing else: not Greenbone, not Vuls, not what a KB is. Everything downstream, VR and any findings API set in `findings_api_host`, reads the same shape.

**A new scanner is a new cassette and must cost nothing else.** No new field negotiated for it, no `if scanner == "x"` in the engine, no second endpoint, no change to this document. If adding one needs any of those, the interface was wrong and the fix belongs here rather than in the cassette. The test is not whether a third cassette can be made to work; it is whether it can be added without anyone touching Soundwave.

Two cassettes fill it today: the openvas cassette reads Greenbone, the vuls cassette reads Vuls.

**Cassettes may overlap, and that is expected rather than a fault.** Two of them can cover the same host, the same package and the same CVE. Nothing in the format prevents it and nothing in the engine does either: a cassette is forbidden from knowing what another one covers, which is the whole point of the separation. Joining what overlaps is Soundwave's job and is described under [Correlating](#correlating).

## Scale, and what it obliges

**Everything below was measured on a 24-node test estate. A Puppet estate is 100,000 nodes.** The ratios hold; the absolute numbers do not, and the difference changes the design rather than the tuning. Written down here because the format is the durable part and a cassette author needs the constraints before they write one, not after.

Measured on 2026-09-16, and extrapolated straight:

| Measured at 24 nodes | Per node | At 100,000 nodes |
| --- | --- | --- |
| `openvas.json`, 1.5 MB | 65 KB | **6.5 GB** for one cassette |
| 3,144 findings | 131 | **13.1 million findings** |
| 190 checks | n/a, checks are shared | low thousands, it barely grows |
| Merged VR push, 114 findings | 4.75 | **475,000 findings in one request** |
| Oracle 9 Vuls result, 561 MB | 561 MB for one host | tens of TB a day at three days' retention |

Four things follow, and they are obligations rather than advice.

**Nothing may load a whole file.** The vuls cassette already streams its input a value at a time because `json.load` on one 561 MB result OOM-killed the scanner. The same rule applies to this format: a cassette writes incrementally and a consumer reads incrementally. At 6.5 GB a `json.load` is not slow, it is impossible, and the fact that it works at 24 nodes is exactly why it gets written.

**Checks are the thing that scales, findings are not.** Normalising checks out of findings is not tidiness. A check is estate-wide and there are thousands; a finding is per host and per check and there are millions. Anything a consumer can answer from `checks` alone stays constant as the estate grows. Anything that walks `findings` grows linearly, so it belongs in a query rather than in a report.

**One bad record must not reject the set.** Measured, not theorised: a single host with an empty `ipaddress` made VR refuse a 117-finding push across all 24 hosts, answering `400 schema-validation-exception` with the message "Value does not match schema" and naming neither the field nor the host. That is survivable at 24 nodes and is a nightly estate-wide outage at 100,000. A consumer of this format must validate per record, reject per record, and say which record. The push it makes onwards must shard, and a failure must have a blast radius of one host.

**A certname is data, not a label.** `hosts` is keyed by certname and that is right, because the file is the place per-host detail belongs. Prometheus is not: one series per certname per cassette is 200,000 series from one textfile. Metrics derived from this file aggregate by cassette, OS family and status; the certname stays in the file where something can join to it on demand.

### Where the current implementation stands against that

Honest, so nobody mistakes the test estate for the product: the vuls cassette streams, Soundwave does not. `read_cassettes` loads each file whole, the push is one request for the whole estate, and `soundwave_host_scan_end_timestamp_seconds` carries a certname label. All three are fine at 24 nodes and none survives 2,000. They are implementation debt against this specification, not a change to it.

## Why not just push to VR

VR's schema is the floor, not the ceiling. Per node it stores `package_names` and nothing else; per vulnerability, `name`, `summary`, `solution`, `severity`, `cvss_score`, `cvss_version`. No port, no confidence, no fix type, no per-host evidence, and the only remediation it offers is a patch job.

On the test estate the patch path is empty and the configuration path is not. Everything that makes a finding actionable by Puppet gets thrown away at the VR boundary, so it has to be written down somewhere before it crosses.

## Shape

```json
{
  "schema": "puppet-findings/1",
  "cassette": { ... },
  "hosts":    { "<certname>": { ... } },
  "checks":   { "<check_id>": { ... } },
  "findings": [ { ... } ],
  "dropped":  [ { ... } ],
  "unmapped": [ { ... } ]
}
```

Checks are normalised out of findings because both consumers want them that way. A findings API asks "which hosts have this check" and VR groups by vulnerability name. Leaving the vendor's prose inline would repeat a kilobyte of advisory text 23 times for the one sshd setting.

Everything that can vary per host lives in a finding. Everything that cannot lives in a check. If a cassette finds a check-level field varying across hosts, it has two checks and needs two IDs.

### cassette

```json
{
  "name": "vuls",
  "scanner": "vuls",
  "scanner_version": "0.40.1",
  "feed": {
    "name": "vuls-nightly-db",
    "version": "0",
    "fetched_at": "2026-09-16T00:32:48+10:00"
  },
  "run_id": "2026-09-16T02:15:09+10:00",
  "generated_at": "2026-09-16T02:19:41+10:00",
  "confidence_scale": {"min": 0, "max": 100, "kind": "vuls-confidence"}
}
```

`feed.fetched_at` is not decoration. The whole EL failure in the Vuls trial was a nightly database a day behind the errata, and it presented as missing coverage. A consumer that can see the feed's age can say "nothing found, and the data was 26 hours old" instead of "nothing found".

`run_id` is the cassette's own scan identifier, for tracing a finding back to the run that produced it.

**`scanner_version` and `feed` are `null` when the scanner does not report them**, never `""` or `{}`. A consumer keeps a key sent as `null` apart from one sent empty, and an empty value says "reported, and blank" when the truth is "not reported". The openvas cassette sends both as `null`: gvmd's report carries neither.

`confidence_scale` says what the numbers in each finding's `confidence` are out of. A findings API may draw confidence bands at 70, Greenbone's default minimum QoD and the floor Soundwave applies for VR, and 70 only means something on 0-100: a cassette declaring any other range gets no bands drawn rather than every finding counted low. Both cassettes are 0-100, the openvas cassette's as Greenbone's QoD and the vuls cassette's as Vuls' detection confidence, and they say so. Optional, and a reader should assume 0-100 when it is absent, and say it is assuming. `kind` is free text a reader can use; nothing interprets it.

### hosts

Keyed by certname. Every host the cassette **attempted**, findings or not.

```json
"alma8.example.com": {
  "ipaddress": "192.0.2.5",
  "os_family": "alma",
  "os_release": "8.10",
  "collection": "ssh-fast",
  "status": "scanned",
  "authenticated": true,
  "scan_start": "2026-09-16T02:15:09+10:00",
  "scan_end": "2026-09-16T02:15:31+10:00",
  "errors": [],
  "warnings": []
}
```

A host with no findings still appears. The trial made the case: Rocky 9 reported zero CVEs and was right, Alma 8 reported zero CVEs and was missing an errata the feed had not caught up with. From the findings alone those are the same node. From the host block they are not.

`status` is one of `scanned`, `partial`, `auth_failed`, `unreachable`, `skipped`. `authenticated` is separate because an unauthenticated scan completes: Greenbone happily returns a full network scan without `Auth-SSH-Success`, and the findings are real but the package list is absent. Both fields tell a consumer which hosts it can't see into.

`collection` says how the data was gathered: `ssh-fast`, `ssh-deep`, `local`, `server-mode`, `gmp`. It is the difference between "this host has no findings" and "this host was looked at through a keyhole".

**A cassette copies its scanner's timestamp; it does not re-derive it, and that makes it somebody else's clock.** The openvas cassette passes Greenbone's `<end>` through untouched, so its `Z` is genuine only because that container happens to run UTC. Point a cassette at a scanner running in a local timezone and it will emit local time wearing a `Z`, and the format will carry the lie unchanged into every age computed from it. This is not hypothetical: the same mistake was live on this engine's own PE leg for months, rendering local time and stamping a `Z` on it, and it survived because it was consistently wrong, so ordering still worked and nothing looked broken.

Soundwave therefore checks: a cassette whose newest `scan_end` is in the future logs a warning and publishes `soundwave_cassette_clock_skew_seconds`, which should be alerted on above zero. A future scan end is the one signature a timezone error cannot hide behind, and reporting it is better than clamping it, because a clamped age reads as perfectly fresh.

`scan_end` is per host. VR takes one scan date for the whole push, which is how a week-old family reads as current; the file keeps the real thing so a consumer that cares can use it.

### checks

Keyed by `check_id`, which is `<source>:<id>` and must be stable across runs and unique across cassettes.

| Source | Example | From |
|---|---|---|
| `greenbone` | `greenbone:1.3.6.1.4.1.25623.1.0.117839` | NVT OID |
| `vuls` | `vuls:ELSA-2026-67165` | `distroAdvisories[].advisoryID` |
| `vuls` | `vuls:KB5042322` | Windows KB |
| `vuls` | `vuls:CVE-2024-3094` | `cveID`, when there is no advisory |

Namespacing is what makes collisions impossible without coordination. It also means a check ID tells you which cassette to go and ask.

```json
"vuls:ELSA-2026-67165": {
  "name": "openssl: Oracle ELSA-2026-67165",
  "summary": "...",
  "solution": "...",
  "fix_type": "vendor-fix",
  "severity": "high",
  "vendor_severity": "high",
  "cvss_score": 7.5,
  "cvss_version": "3.1",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "cves": ["CVE-2026-1234"],
  "references": ["https://linux.oracle.com/errata/ELSA-2026-67165.html"],
  "kev": false
}
```

`name` is what PE shows in its grouped list, so it has to be identical on every host and mean something on its own. "Oracle: Security Advisory (ELSA-2026-67165)" means nothing until it is looked up; the package names are what a human recognises. This is already how the openvas cassette names Ubuntu advisories.

`fix_type` says what kind of fix exists, if any. The vocabulary is the format's own and the meanings below are the definition; the shape was taken from Greenbone's `solution_type`, which had the distinctions that matter, but a value means what this table says rather than what any one scanner's tag means.

| Value | Meaning |
|---|---|
| `vendor-fix` | A patch or a newer package exists |
| `mitigation` | A configuration change reduces or removes the exposure |
| `workaround` | Something else avoids it, short of a config change |
| `none-available` | Known, nothing to do yet |
| `will-not-fix` | The vendor has declined |
| `null` | This scanner has no such vocabulary and cannot answer the question |

This is the field a mitigation rule catalogue selects on. Mitigation findings are where Puppet earns its keep, and they are indistinguishable from patch findings by the time VR sees them.

**`null` is not `none-available`, and it is not an empty string.** `none-available` is a positive claim that nothing exists to do. An empty value means the check said nothing. `null` means the tool does not make this distinction at all, so no answer it gave could be trusted either way. They must stay apart: fold "cannot answer" into "said nothing" and a whole cassette's output reads as a scanner that found nothing worth mitigating.

### Mapping a scanner onto it

Every cassette maps its scanner's own vocabulary onto the values above. What the mapping refuses to invent matters more than what it fills in.

| Scanner | Mapping |
|---|---|
| Greenbone | `solution_type` tag, direct |
| Tenable | `has_patch` to `vendor-fix`; `vendor_unpatched` to `none-available`; `unsupported_by_vendor` to `will-not-fix`; **no mitigation equivalent, so `null`** |
| Qualys | `PATCHABLE` 1 to `vendor-fix`, 0 to `none-available`; **no mitigation equivalent, so `null`** |

Nessus has no `solution_type`: it is absent from the ReportItem template and from Tenable's plugin attribute list, and the nearest things are the booleans `has_patch`, `vendor_unpatched` and `unsupported_by_vendor`. Qualys has `PATCHABLE`, also a boolean, and in the KnowledgeBase rather than the detection response. Neither can tell a mitigation from a vendor fix, which is the one distinction this field exists for.

So a cassette for either writes `null` and says so, rather than guessing. A mapping that guessed would put a scanner-specific judgement inside the field a rule catalogue selects on, which is how a tool that cannot see mitigations starts asserting there are none.

`severity` is the PE enum (`critical`, `high`, `medium`, `low`, `none`) derived from `cvss_score`, kept alongside the score so nobody re-derives it with a different cut.

`vendor_severity` is the same enum holding the vendor's own rating, where it publishes one, and it is a different judgement rather than a worse one. Oracle rates ELSA-2025-20551 important at CVSS 5.6, because it knows how the package is built and shipped. Putting both in means a console can show one without the other looking like a bug, which is what happens when a check reads "5.6, high".

`kev` says CISA has this in the Known Exploited Vulnerabilities catalogue. It is not in VR's schema and does not need to be: it is the single best field for ordering "worst first", and the worst-first ordering is the whole user interface of a mitigation tool.

### findings

One per `(certname, check_id, port)`. Flat array.

The port is in the key because a scanner reports the same weakness on more than one service of a host, and those are genuinely different findings. What is not a different finding is the same check on the same port reported several times, which is what Greenbone does: a result row per piece of evidence, naming the offending URLs for a directory listing or the exact algorithms for a cipher check. Measured on the test estate, 595 such groups covered 2,582 of the openvas cassette's 3,144 findings, and folding them brings the cassette to 1,157 without losing a word of evidence.

Those rows are one finding carrying several pieces of evidence. Left apart, every consumer counts one weakness many times, and the count it reports is a property of how chatty the scanner was. `Document.finding()` folds them: evidence accumulates, confidence takes the higher, packages and KBs union, and the per-host state takes the worse of the two. A cassette that writes through that class gets the rule for free and cannot break it by accident.

```json
{
  "certname": "oracle9.example.com",
  "check_id": "vuls:ELSA-2026-67165",
  "detected_at": "2026-09-16T02:15:31+10:00",
  "confidence": 100,
  "state": "fixable",
  "port": null,
  "evidence": "openssl 1:3.5.5-6.0.1.el9_8 is older than 1:3.5.8-1.0.1.el9_8",
  "packages": [
    {
      "name": "openssl",
      "arch": "x86_64",
      "installed": "1:3.5.5-6.0.1.el9_8",
      "fixed": "1:3.5.8-1.0.1.el9_8"
    }
  ],
  "kbs": []
}
```

`confidence` is 0 to 100, or `null` when the scanner has no such notion. Greenbone's QoD goes in unchanged; Vuls's `confidences[].score` takes the highest, and its `detectionMethod` goes in `evidence`. Same scale, same meaning: how much the scanner is guessing. The SSH DHE finding sits at QoD 30 and gets dropped before VR ever sees it, which is precisely why the number has to survive into the file rather than being applied as a cut by the cassette.

`state` is one of:

| Value | Meaning |
|---|---|
| `fixable` | A fix exists and this host can take it |
| `unfixed` | The vendor has published nothing |
| `pro-only` | A fix exists but only in a subscription archive the node is not attached to |
| `""` | Not a package finding at all. A TLS protocol or a directory listing has no package state, and inventing one would make it sortable alongside things it is not comparable with |

`pro-only` is currently a sentence of English prepended to the solution text. Every Ubuntu package finding on the test estate was ESM-only and no node has Pro attached, so this is the difference between 87 findings and an honest zero. A field can be counted; prose cannot.

`packages[].installed` carries epoch and release exactly as the scanner reported them. It is what the running-kernel filter compares against, and what anyone auditing a dropped finding needs.

`port` is the port as the scanner names it, `22/tcp` or `general/icmp`, and null for anything that is not about a port. It keeps the protocol because that is half of what identifies the service. A consumer can use it to join a finding to the service that owns it through PuppetDB, which is the one thing the scanner's own text never says.

`evidence` is the per-host raw text: Greenbone's result description (which names the exact offending key exchange algorithms, cipher suites and URLs), or the rendered package or KB comparison from Vuls. A rule parses it; a human reads it when no rule exists yet.

### dropped

Every filter a cassette applies, with counts.

```json
{
  "filter": "running-kernel",
  "reason": "advisory fixes a different kernel stream from the one installed",
  "findings": 4263,
  "hosts": 4,
  "sample": [
    {
      "certname": "oracle9.example.com",
      "check_id": "vuls:ELSA-2025-20530",
      "package": "kernel-uek-core",
      "installed": "5.15.0-324.217.5.2.el9uek",
      "fixed": "0:6.12.0-102.36.5.2.el9uek"
    }
  ]
}
```

A filter that quietly starts eating real findings is worse than the noise it was written to remove. Publishing the count means a jump or a collapse shows up in metrics, and the bounded sample (ten entries) means someone can check the rule still does what it says without re-running the scan.

Dropping unfixed CVEs, advisories for a package stream the host is not on, and hotpatch KBs on editions that cannot take them all go here.

The stream filters are worth spelling out, because between them they are everything the vuls cassette produced on the test estate.

| Filter | Rule |
|---|---|
| `different-stream` | The advisory's fixed build is *older* than the installed one, comparing upstream versions and ignoring epoch |
| `running-kernel` | A kernel package whose fixed upstream major.minor is neither the installed nor the running one |

Both say the same thing: the advisory belongs to a parallel stream this host is not on, so applying it is not an update. They need two rules because the two cases point in opposite directions. Oracle 9.8 ships `qemu-guest-agent 17:10.1.0-17.el9_8.5` and Vuls matches it against ELSAs fixing `30:7.2.0-11.el9`, where a higher epoch hides an older build; the same host runs UEK7 `5.15.0` and gets matched against UEK8 `6.12.0` advisories, where the build really is newer but on a kernel stream the host would have to change to take. `dnf` offers neither. Both were checked on the node on 2026-09-16.

The epoch is why this cannot be left to a plain version comparison. By RPM's ordering `30:7.2.0` genuinely is newer than `17:10.1.0`, and the vendor is using the epoch to keep two streams apart rather than to say "upgrade to this".

### unmapped

Hosts the cassette scanned but could not resolve to a certname.

```json
{ "identifier": "192.0.2.99", "collection": "gmp", "sent_as": "gateway.lan" }
```

They are still sent, under whatever name the scanner had, because that name sometimes is the certname and dropping them would lose findings the transformer used to deliver. `sent_as` says what was used. PE matches on certname and silently drops anything else, so without this list a host falling out of PE looks identical to a host with nothing wrong.

## Writing the file

`/var/lib/soundwave/cassettes/<name>.json`, written to `<name>.json.tmp` and renamed, so a reader never sees a half-written file.

Soundwave reads every `*.json` in that directory. A cassette whose `generated_at` is older than its expected interval is an alert, not a silent omission: a stale vuls cassette must not be able to hide behind a fresh openvas cassette.

**One file per cassette is a convenience at small scale, not part of the contract.** At estate scale a cassette writes a set of files under `<name>/` and the rename applies to the set, with `generated_at` in a small manifest beside them. What the contract fixes is the record shapes and the directory, so a cassette may shard however suits its scanner and a consumer must not assume it will find exactly one file.

## Adding a cassette

The interface is the product, so the bar for a new one is that nothing else moves.

A cassette has to do four things: resolve every host to a certname, emit a host block for every host it attempted whether or not it found anything, namespace its `check_id` under a source nobody else uses, and report every filter it applied into `dropped` with a count. That is the whole obligation.

It must not need a new top-level key, a field that only it populates, special handling in Soundwave, or a change to this document. If it does, the interface is missing something general and this document is where that gets fixed, once, for every cassette including the ones not written yet. A field added for one scanner is how a neutral format stops being neutral.

Two things are deliberately not the cassette's business. **Which findings reach VR** is the engine's decision, so a cassette applies no confidence floor and drops nothing for being low-scoring; it records what its scanner said and why. **What another cassette covers** is nobody's business but Soundwave's, so a cassette never checks whether a host is already covered and never trims its output to avoid an overlap. Report everything the scanner found; the engine sorts out what turns out to be the same thing twice.

## Merging

Soundwave's job, and worth stating because getting it wrong loses data silently.

**Every push carries the full merged set.** VR replaces a transformer's data per node on each push. Pushing one cassette's latest alone wipes the other's.

**Full set does not have to mean one request, and at scale it must not.** The rule is that every node in the set is represented on every push, not that they travel together. At 100,000 nodes one request is roughly half a million findings and, worse, one failure domain: the empty `ipaddress` that cost a 24-node push cost all 24 hosts, and would cost all 100,000. Shard by node, keep the set complete across the shards, and let a rejected shard fail alone and name itself.

Hosts union. A host in both cassettes keeps both sets of findings and both scan ends. Checks union, and cannot collide because IDs are namespaced. The push's scan date is the newest `scan_end` across everything, which is what PE already stores and what the transformer already sends.

**A finding with no CVSS score is held back too.** VR's schema rejects one, and there is no honest substitute: 0.0 is a real CVSS value meaning no impact, so scoring an unscored finding that way understates it rather than leaving it out. Microsoft's ADV advisories arrive this way, and PE answered the whole push with `400 schema-validation-exception` until they were held back. They stay in the cassette, where a consumer that can represent "known, unscored" can see them.

**The confidence floor is applied here, not by a cassette.** VR has nowhere to put a confidence, so a QoD 30 finding there reads exactly like a certain one; Soundwave drops anything below `min_confidence` (70, gvmd's own default) on the way in. The cassettes keep the whole tail, which is the only reason the file is useful to anything that can reason about confidence. On the test estate that is the difference between the 87 findings PE shows and the 3,144 the scanner actually has an opinion about, and the best mitigation candidate, SSH Diffie-Hellman on 23 hosts, sits at QoD 30 in the second group.

**A null confidence is not filtered.** The scale is Greenbone's QoD and not every scanner has one: Nessus offers only the booleans `potential_vulnerability` and `exploited_by_nessus`, and Qualys nothing per detection. Treating absent as zero drops every finding such a cassette produces, under a log line that reads exactly like the floor working normally, so a cassette that cannot rate its findings writes `null` and Soundwave counts them separately rather than cutting them. A cassette must not invent a number to get past the floor: whatever it picked would make the floor either lethal or meaningless for that scanner, and it would put a scanner-specific judgement inside a format that exists to hold none.

**A host that was scanned and came back clean is pushed with an empty list.** VR replaces a transformer's data per node on each push, and a node left out of a push keeps whatever it already had. Sending only hosts with findings is how a node that has been patched goes on showing its old findings indefinitely.

## Correlating

Two scanners report the same weakness on one host under different names, and nothing in the format stops them: check IDs are namespaced precisely so they stay distinguishable, and a cassette is forbidden from knowing what another one covers. Soundwave is the only component that sees every cassette, so joining them is its job and nobody else's.

**Report-only unless `compose_findings` is on.** With it off, groups are counted and sampled, nothing is merged, VR still gets a row per finding and a findings API still gets each cassette verbatim. The count came before the merge because overlap is otherwise invisible, and a rule whose effect nobody can see is a rule nobody can check. With it on, the groups are acted on as described under [Composing](#composing).

The key is `(certname, CVE, subject, fix_type)`.

| Part | Why it is in the key |
|---|---|
| `certname` | A group can never span hosts, which is also what keeps this a per-host operation over a few hundred findings rather than an estate-sized one |
| CVE | The only identifier three scanners agree on. There is no usable bridge between Greenbone OIDs, Nessus plugin IDs and Qualys QIDs |
| subject | `packages` if the finding has them, else `kbs`, else `port`. A CVE gets reported against several services and packages, and a package fix is not a service mitigation |
| `fix_type` | A patch and a mitigation for one CVE are two pieces of work. Collapsing them is how a console offers a button that cannot close the finding |

Three rules that are not tuning.

**A check with no CVE does not correlate.** It passes through as itself. Grouping on an absent CVE joined "OpenSSH Unspecified Vulnerability" to "OpenSSL End of Life Detection" on the test estate, because both had no CVE, the same port bucket and the same fix type. Failing to correlate must degrade rather than corrupt.

**Only real CVE identifiers count.** The vuls cassette puts Microsoft advisory IDs in `cves`, and correlating on `ADV190023` joins on a string that does not mean the same thing across scanners.

**No transitive closure.** Groups form by key and never chain through a shared member. One Oracle check here carries 42 CVEs, and chaining would pull unrelated kernel errata into one blob.

### What it will get wrong, and what to do about it

The key cannot separate every case and no field in any scanner's output would let it. `greenbone:...114238` is an SSH protocol check and `greenbone:...118572` is an OpenSSH version check; both report `CVE-2023-48795` on port 22 with the same fix type, and one is closed by upgrading a package while the other is closed by disabling algorithms. Measured on the test estate that is 5 groups of 43.

So correlation publishes what it joined, in the same shape `dropped` uses and for the same reason: counts so a change shows up in metrics, and a bounded sample so the rule can be audited without re-running a scan. Pairs the key provably cannot tell apart go in `correlation_exceptions` and are left uncorrelated rather than split cleverly, because the pair is the evidence that the key cannot see the difference.

A scanner that covers everything, rather than the platform-split pair here, will find more of these. The exception list is a permanent part of the mechanism, not a workaround for one bad pair.

### Composing

`compose_findings` turns the groups into records.

**A set, not a group.** A finding usually carries several CVEs, so it can sit in several groups: Greenbone's pip advisory arrives in three parts, two of which carry all three CVEs. Composing group by group would give VR three records carrying the same CVEs, so the groups that share a finding are composed as one set. That is closure, which correlation itself refuses, and **a cap** is what makes it safe: a set over 5 findings or 10 CVEs is left as it was and counted in `soundwave_composition_capped_sets`, so one 42-CVE kernel advisory cannot chain unrelated errata into a single record without the metrics saying so.

**What the record carries.** CVEs, references, packages and KBs are the union. Confidence is the highest, KEV is sticky, and the state is the most pessimistic. The name and summary are the narrowest member's, with every other member named after it. The **score is the highest per-CVE score**: each CVE is scored by the narrowest check that carries it, because the narrow check is the per-CVE record and a wide one is a roll-up carrying the worst of its set, and the record takes the highest of those. Taking the narrowest member for the whole record was tried first and would have shown scipy at 5.5 while carrying a CVE that only Greenbone reports, at 9.8.

**Where it goes.**

| Consumer | What it gets |
|---|---|
| VR | One record per set, across cassettes. VR has nowhere to put the sources, so the solution opens with one sentence naming the checks the record came from |
| Findings API | Each cassette pushed on its own and as the scanner wrote it, not composed at all, so a consumer can keep every source apart and a stale scanner cannot hide inside a fresh one |

Measured on the test estate before it shipped: 8 sets over 18 findings, 2 of them spanning cassettes, none capped. VR goes from 86 records to 80, and **no CVE on any host is lost or shown at a different score** than it was before.

## Filling it from Greenbone

Everything the format asks for is in the GMP report already, and most of it is thrown away by the current parser.

| Field | GMP source |
|---|---|
| `check_id` | `<nvt oid="...">` |
| `fix_type` | `solution_type` tag |
| `confidence` | `<qod><value>` |
| `port` | `<port>` |
| `evidence` | `<description>` |
| `state` | `pro-only` from the ESM and FIPS version patterns already detected |
| `authenticated` | `Auth-SSH-Success` / `Auth-SMB-Success` host details |
| `os_family`, `os_release` | `best_os_cpe` host detail |

**`os_family` is a shared vocabulary, not each cassette's own words.** Greenbone gives the OS as a CPE (`cpe:/o:canonical:ubuntu_linux:24.04:-:lts`) and Vuls gives a family name, and if a cassette simply passes its scanner's spelling through then one host is `canonical` in one file and `ubuntu` in the other, which is worse than the field being absent. Every cassette maps onto the same set: `ubuntu`, `debian`, `rocky`, `alma`, `oracle`, `redhat`, `centos`, `fedora`, `amazon`, `suse`, `opensuse`, `windows`. A vendor nobody has mapped yet writes an empty family and logs that it did, rather than inventing one.

Windows is the awkward one and worth spelling out: the release lives in the CPE product (`windows_server_2022`) rather than the version field, so it is rendered from there as `Windows Server 2022`.

**`os_release` is the scanner's own precision and the two do not always agree.** Greenbone fingerprints Debian as `12.15` where Vuls reports `12`, so the same host carries a different release in each cassette's file. Neither is wrong and neither is normalised here, because truncating one to match the other would invent a rule for one distro. Anything joining on `os_release` across cassettes needs to know that; anything joining on `os_family` does not.

## Filling it from Vuls

Per-host result JSON, after `vuls report`. Field names as of v0.40.1.

| Field | Vuls source |
|---|---|
| `certname` | `serverName`, which the scan config already sets to the certname |
| `os_family`, `os_release` | `family`, `release` |
| `scan_end` | `scannedAt` |
| `check_id` | `scannedCves[].distroAdvisories[].advisoryID`, else `cveID` |
| `confidence` | max of `scannedCves[].confidences[].score` |
| `cves` | `cveID` |
| `severity`, `cvss_*` | `cveContents[<source>][].cvss3Score` and friends, vendor source preferred |
| `packages[].fixed` | `affectedPackages[].fixedIn` |
| `packages[].installed` | `packages[<name>]`, joined as `version-release`; epoch is already in `version` |
| `state` | `affectedPackages[].notFixedYet` |
| `errors`, `warnings` | `errors`, `warnings` |

Three things to know.

`affectedPackages` carries only the fixed version, so the installed version has to be joined from the top-level `packages` map.

`fixedIn` always carries an explicit epoch (`0:6.12.0-...`) while `packages[].version` carries one only when it is non-zero (`1:3.5.5`, but `5.15.0`), so a string comparison of the two is wrong before normalisation.

**A result file does not fit in memory.** An Oracle 9 result is 561 MB *after* `vuls report -ignore-unfixed`, measured 2026-09-16: 4,310 CVEs, each carrying seven vendors' write-ups plus the UEK changelog, and the changelog is repeated on every one of the 4,263 CVEs its advisory closes. `json.load` on that needs about 3 GB and is what OOM-killed the scanner during the trial. The vuls cassette walks the file a value at a time and keeps a reduced form, which brings a run of every node in under 2 GB. Anything else reading these files needs to do the same.

### Two places Vuls is silent by construction, and silence there is not safety

Both follow from filters that are right, and both mean **a host that shows nothing may still be exposed**. Stated here so nobody reads an empty row as a clean host.

**Debian and Ubuntu without ESM will never show an actionable finding.** Those hosts detect 2,400 to 3,500 CVEs each, and `-ignore-unfixed` removes essentially all of them, because without an ESM subscription there is no fixed package to point at. Correct, since a finding with no fix is not work a patch job can do, and it means VR **systematically under-reports Debian-family exposure**, for as long as the host has no ESM. Greenbone still sees them, as package findings marked `pro-only` where an ESM fix exists.

**An Oracle host on a kernel stream the vendor has moved past reports nothing about that kernel.** Advisories for UEK 6.12 on a host running UEK 5.15 are dropped as `running-kernel`, which is right because an advisory for another stream does not apply. On the test estate that is 8,526 of the vuls cassette's 8,624 drops, constant run to run because the kernel does not change. The consequence is that such a host reports **no** kernel findings rather than reporting that it is on a stream nobody is fixing any more, and that absence is itself the finding.
