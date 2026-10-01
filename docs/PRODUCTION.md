# Production qualification and operator workflow

Livewire's supported use case is repeatable testing on an explicitly selected
device and isolated network. The CLI is the primary interface. Version 1 has a
separate [software-lab release profile](V1_QUALIFICATION.md), using controlled
Windows/Linux protocol peers and Linux virtual packet networks. Physical
NIC/device qualification and the human pilot remain pending. See the release's
manifest for its completed evidence; historical RC results do not qualify a
changed build.

## Inspect, select, preview, replay, retain evidence

Run these examples from a writable directory. Replace the example target,
interface names, and session IDs with those from your lab and `check` output.
Windows packet commands need the complete Npcap device name from `ifaces`.
Socket application replay needs neither packet-driver elevation nor `-i`.

```sh
livewire doctor
livewire doctor -json -out-dir .
livewire ifaces
livewire check issue.pcap -details
livewire live issue.pcap -session tcp-0 -dry-run
livewire live issue.pcap -session tcp-0 -t 192.168.1.50 -report application.json
livewire bundle -report application.json -o application-support.zip
```

Transport exercises supported TCP/UDP/ICMP behavior without claiming application
equivalence. Wire injects captured frames unchanged; it has no retargeting or
reply-equivalence claim. Inspect captured destinations before using it.

```sh
livewire doctor -i eth1
livewire live issue.pcap -mode transport -session tcp-0 -dry-run
livewire live issue.pcap -mode transport -session tcp-0 -i eth1 -t 192.168.1.50 -report transport.json
livewire reproduce issue.pcap -session tcp-0 -dry-run
livewire reproduce issue.pcap -session tcp-0 -i eth1 -report wire.json
```

For a two-interface DUT, use `livewire help lab` and the topology examples in
DOCUMENTATION.md. Map every captured endpoint to its intended live side before
running. `lab` uses its existing `-profile` flag (not `-mode`) and requires
different client/server interfaces. It does not provide application equivalence.

```sh
livewire doctor -i eth1
livewire doctor -i eth2
livewire check issue.pcap -details
livewire lab -in issue.pcap -client-iface eth1 -server-iface eth2 -topology topology.json -profile transport -report dut.json -evidence dut.pcapng
livewire bundle -report dut.json -evidence dut.pcapng -o dut-support.zip
```

Automatic inspection remains useful. `live` uses fresh application
sessions without a mode prompt. Advanced `-mode auto` retains v1.0.0 transport
selection for unrecognized TCP. Never choose a different execution path merely
to hide a blocker. Resolve missing security inputs or select the
intended exchange. `livewire help troubleshoot` contains further recovery steps.

## Diagnostics and reports

`doctor [-i <interface>] [-json] [-out-dir <existing-directory>]` sends no
traffic, opens no capture handle, and changes no host configuration. It creates,
writes, syncs, and removes one temporary output probe. It does not reserve disk
space. JSON stdout contains version, platform, interface, outputDir, ready, and
findings with code/severity/message/nextAction. Exit 0 means no local blockers;
exit 1 means a blocker or diagnostic execution error. Help exits 0.

Without `-i`, missing packet prerequisites are warnings because offline and
socket workflows remain usable. With `-i`, a missing/down interface, unavailable
packet backend, or known missing Linux CAP_NET_RAW is a blocker. Windows
elevation and RST-guard checks remain warnings because needs depend on Npcap
policy and replay mode. Driver access and target behavior are confirmed only by
the controlled replay, not by a successful doctor result.

Reports add `status`: matched, different, incomplete, unverified, cancelled,
or wire. Explicit wire dry-run reports use preview. Existing fields and exit
codes remain available. Automation must inspect report status: the existing
report-oriented `live` exit policy can return zero after recording an
incomplete attempt. Exit zero alone is not a pass/fail assertion. A cancelled
repeated run retains completed-attempt counts; its overall status is cancelled. A send-only or unchecked exchange
cannot establish a match. Errors during execution/cleanup override completion.
Capture hashes identify the loaded byte stream, even when the source changes
during CLI or dashboard replay. Selected/excluded packet accounting is retained.

If a target stops responding, inspect the incomplete result and timeout before
retrying. SSH timeout now covers the complete attempt, including command/channel
waits. FTP control and data connections honor cancellation and bounded I/O.
Normal cancellation must release owned interfaces and temporary RST guards
within two seconds in qualification. Forced termination or machine failure still
requires checking firewall/interface state; a killed process cannot report its
own cleanup as successful.

For output failures, choose a new report path and check permissions/free space.
Existing evidence is never overwritten. If saving evidence fails after replay,
the CLI exits with an error; it must not imply a report was saved. Bundles contain
redacted metadata and digests, not captures, plaintext payloads, or private keys.

## Support and qualification matrix

| Capability | Automated evidence | Field status |
|---|---|---|
| Windows amd64 CLI/application replay | Native tests and loopback peers | Physical NIC/DUT qualification pending |
| Linux amd64 | Native tests, loopback peers and isolated virtual Ethernet labs | Physical NIC/DUT qualification pending |
| Linux arm64 | Cross-build only | Provisional until native execution |
| HTTP/1, DNS/TCP, Modbus/TCP, MQTT 3.1.1/5, DNP3, plaintext/TLS, FTP/FTPS, SSH | Independent local peers through stateful `live` | Qualify the actual DUT workflow |
| Stateless `reproduce` and compatibility `replay` | Exact packet bytes/order/count across protocol fixtures; no application comparison | Validate the actual interface and captured addresses |
| DNS/UDP, UDP, ICMPv4/v6, stateful TCP, captured TCP, wire | Independent captures across virtual interfaces; adaptive TCP loss/reordering checks | Physical packet and cleanup checks required |
| Two-interface field lab | Parser/model/backend tests | Physical DUT topology qualification required |
| Dashboard | API and JavaScript state tests | Visual/keyboard checks pending |
| HTTP/2, HTTP/3 semantics; arbitrary mixed secure exchanges | Outside current scope | Unsupported |

Windows artifacts remain unsigned; verify official download checksums and
provenance. Authenticode publisher trust is a separate distribution limitation.
Security fixes target the 1.x line; older lines receive no
routine backports. A current support claim requires the recorded qualification
matrix, not merely a cross-build or unit test pass.

The default parser limits are 512 MiB decoded packet data, 1,000,000 records,
and 16 MiB per record/block. These are input limits, not RAM limits. The synthetic
512 MiB UDP fixture used about 1.6 GB process memory on this Windows host;
one million minimum-size records used about 0.9 GB. Other protocols, session
counts, reassembly, adapters, and concurrent work can use more. Split large
captures and leave memory headroom. Reproduce measurements for the target host.

## Maintainer qualification and release promotion

The release workflow validates the profile declared by the manifest. Version 1
uses `software-lab`, whose required protocol matrices and two-hour command soaks
are described in [V1_QUALIFICATION.md](V1_QUALIFICATION.md). A lab manifest must
explicitly keep physical and human-pilot qualification false. It cannot satisfy
the field profile. The following procedure retains the full `physical` profile
for later device qualification; an omitted profile also means `physical`.

```sh
go run ./scripts/qualify corpus -output coverage/corpus-new
go run ./scripts/qualify benchmark -output coverage/benchmark-new
go run ./scripts/qualify init qualification/physical-candidate.json
go run ./scripts/qualify record -output coverage/doctor-new -- livewire doctor -json
go run ./scripts/qualify validate -version 1.2.0 -artifacts dist/v1.2.0 qualification/physical-candidate.json
```

Output directories/files must be new. The corpus generates synthetic fixtures
through named Go tests and rejects missing or skipped tests. The benchmark runs
six isolated worker processes and measures loading, planning, sampled heap, and
observed OS peak RSS. Over-limit cases must fail with the expected parser limit,
not a crash. Preserve the metrics, including the source digest.

`record` runs exactly the argv after `--`, without a shell; it does not infer
targets. Use file-based credentials, never secret arguments. Logs need review
before sharing. Exit-code agreement is only one observation: the recorder never
marks behavior or cleanup verified. A recorder timeout kills the child; inspect
and restore host state before another run. It is not a cancellation test.

Populate the manifest with the final packaged Windows/Linux binary SHA-256,
exact OS/driver/NIC/DUT/firmware, and three consecutive passes for every scenario
listed in the template. Each run must record expected and observed behavior,
cleanup verification, and evidence path/SHA-256; cancellation records also need
measured cancelSeconds. Record actual commands and packet/report evidence in the
referenced file. For deliberate failure scenarios, a pass means correct failure
and recovery, not an exit-zero replay. Never disable a real interface or fill
a real disk outside the dedicated test host/volume.

On each platform, repeat the selected supported workflow for at least two hours.
Use `go run ./scripts/qualify soak -output coverage/soak-new -seconds 7200 -- livewire live issue.pcap -t 192.168.1.50`
on the selected lab host. Every attempt has separate transcripts; report-path
arguments may contain `{attempt}` for unique filenames. The harness stops on
an unexpected exit and leaves behavior/cleanup qualification pending review.
Record start/end times, attempts, memory/handle samples, exceptions, and
before/after interface and firewall state. Require no crashes, stuck runs, leaked
interfaces, or residual temporary rules. An operator must verify cleanup.

Browser evidence must name browser/version and cover desktop/narrow widths,
keyboard navigation, inspecting/selecting sessions, changing intent/security
inputs, rejecting stale previews, start/stop, differences, and report downloads.

Five engineers each perform the five tasks named in the template without
coaching: inspect/select, preview/replay, compare results, repeat/stop, and bundle.
Record task outcomes and time from installed prerequisites to first successful
replay. Require at least 23/25 completions and median time at most 600 seconds.
No user identifiers beyond anonymous distinct pilot IDs are needed. Capture
blockers/confusion and add sanitized reproductions to the corpus before retesting.

Keep unintended transmission, false verification, secret exposure, crashes,
failed cleanup, and unresolved pilot failures in blockingFindings. The stable
release workflow validates the manifest, source digest, packaged binary hashes,
and referenced evidence. Missing, changed, or failing evidence blocks publication.
RC tags remain explicitly prereleases. This gate verifies records; it cannot
replace an operator's honest observations. Review/redact evidence before committing
it under qualification/. Do not commit credentials or customer captures.

Build the final versioned packages before qualification, then record results against
those exact bytes. The builder refuses an existing version directory; use a
fresh `-OutputRoot` for reproducibility checks. It validates the source version
before creating an output directory and never deletes a previous release.
Run `GOTOOLCHAIN=go1.26.7` with the existing release builder (on PowerShell, set
`$env:GOTOOLCHAIN='go1.26.7'` first).
After the declared profile's gates pass, tag/publish the tested version using the existing
release workflow. Do not rename an RC and assume different binaries were tested.

For downgrade/recovery, stop active runs, check host cleanup, retain evidence,
and extract a checksum-verified previous release into a separate directory.
Invoke its executable explicitly and verify `version`. New 0.9 flags/statuses
are not guaranteed in older versions. Returning to 0.8 reintroduces known replay
regressions and lacks candidate fixes; it is a troubleshooting comparison, not a
security recommendation. Preserve immutable artifacts and publish fixes as new
patch versions rather than replacing existing downloads.
