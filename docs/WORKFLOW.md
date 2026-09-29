# Replay an exchange deliberately

For prerequisite diagnostics, failure recovery, supported platforms, and the
stable qualification procedure, see [PRODUCTION.md](PRODUCTION.md). Run
`livewire doctor` before choosing a packet interface.

This guide describes version 1. Automatic inspection identifies available
replay routes; replay intent is a separate choice. The release's
[qualification scope](V1_QUALIFICATION.md) states which software tests passed
and which field checks remain outstanding.

## Inspect, select, preview, run

```sh
livewire check issue.pcap -details
livewire reproduce issue.pcap -mode application -session tcp-0 -dry-run
livewire reproduce issue.pcap -mode application -session tcp-0 -t 192.168.1.50
```

Use the session IDs shown for that capture. Repeat `-session` to include more
than one exchange. Selecting FTP control or data includes the entire related
group. Changing the capture can change its session IDs; inspect it again.

Without selection, the whole capture is in scope. Background ARP or unsupported
traffic can block that scope. Select the intended exchange instead of forcing
all traffic through a different driver. Reports retain excluded packet indexes
and counts. A match describes selected sessions only.

| Intent | Behavior |
|---|---|
| `application` | Uses supported application adapters or fresh TLS/FTP/SSH sessions; no implicit transport fallback. |
| `transport` | Uses supported stateful transport behavior, without interpreting application messages. Confirmed encrypted sessions needing fresh security state are blocked. Unrecognized binary payloads can be exercised as transport data without claiming application equivalence. |
| `wire` | Injects selected captured frames at recorded timing. Requires `-i`; no target rewriting or reply comparison. |
| `auto` | Keeps compatibility protocol routing, with explicit blockers and the same preview. |

Plain application/transport targets are IP addresses and use captured ports.
Secure targets accept `host:port`. Socket-based application replay does not need
a packet interface or packet-driver elevation. Packet drivers still do.

`-dry-run` inspects the capture, validates the chosen mode and supplied target,
and shows requirements and report destinations. It sends nothing and writes no
report. Missing credentials are listed as requirements; preview alone does not
prove keys/certificates will work against a live peer. A blocked preview exits
nonzero. `check` remains an inspection command and can successfully describe a
blocked capture; inspect its structured readiness when automating.

## Reproduce an application fault or a TCP fault

Use `livewire help reliability` for the terminal version of this workflow.
Choose the observable failure first: a different response, a reset, a stalled
request, a device crash, or a timing threshold. Retain device logs and a packet
capture from the test run to check that symptom independently of reply matching.

For supported application protocols over TCP, `-mode application` uses fresh OS TCP
connections. The OS maintains sequence numbers, acknowledgements, retransmission,
and flow control; adapters maintain supported application identifiers and state.
Captured segmentation and packet loss are not reproduced by a socket replay.
The target also needs the relevant firmware, configuration, authentication,
and starting data. A PCAP alone does not restore those conditions. HTTP setup
and response-dependent tokens can be declared with `-scenario`; see
[RELIABILITY_IMPLEMENTATION.md](RELIABILITY_IMPLEMENTATION.md).

For a packet-level TCP issue, preview and run the transport route:

```sh
livewire reproduce issue.pcap -mode transport -session tcp-0 -dry-run
livewire reproduce issue.pcap -mode transport -session tcp-0 -t 192.168.1.50 -i <connection> -details -run-timeout 2m
```

The transport driver needs a captured handshake and maps captured client
sequence/ACK numbers to a fresh live peer. It preserves captured client
segmentation, flags, retransmissions, and pacing. It does not implement a full
TCP sender with congestion control, live window adaptation, and a SACK recovery
queue. A changed server response length or network path can prevent the captured
packet pattern from being valid. The `-exact-tcp` alias selects this behavior;
it cannot promise identical network or device state.

To investigate intermittent application behavior:

```sh
livewire reproduce issue.pcap -mode application -session tcp-0 -t 192.168.1.50 -n 5 -strict-exit -run-timeout 10m
```

Each attempt opens a fresh connection. Reset required target data between runs
when testing depends on it. Add `-under-load` for supported captured pacing and
cross-session overlap; worker bounds and live response delays can shift actual
sends, so inspect reported timing. Secure drivers currently support functional
replay only. `-strict-exit` makes incomplete, different, unverified, or wire-only
results fail automation; it does not turn reply matching into a fault detector.

Use `-state-dir <new-dir>` to record durable progress and `-resume <dir>` with
the same inputs to recover after interruption. Resume skips confirmed completed
session boundaries or starts eligible sessions fresh. It never restores an old
TCP connection, TLS state, or the device's internal state. Uncertain writes
require an explicit recovery contract.

## Secure exchanges

```sh
livewire reproduce tls.pcap -mode application -t device.example:443 -keylog sslkeys.log -ca device-ca.pem
livewire check ftps.pcap -mode application -keylog sslkeys.log -details
livewire reproduce ssh.pcap -mode application -t device:22 -user operator -key device.key -host-key device.pub -cmd "show status" -expect ready
```

FTPS negotiation is decrypted offline to associate data sessions when a matching
key log is supplied. No key log is consumed merely because it exists nearby.
Multiple independent secure exchanges require explicit session selection; this
version does not coordinate arbitrary mixed secure sessions in one run.

SSH always requires a pinned host key in the primary workflow. Passwords, key
material, command bodies, and response bodies are excluded from reports. SSH
output evidence contains lengths and digests. Blank expectations do not count
as verification. TLS identity verification remains enabled by default.

Fresh secure sessions support functional replay. Timing/exact-transport options
and actual-packet output are rejected instead of silently ignored. Add `-n 5`
for fresh repeated attempts and `-gap 0s` for no settle delay.

## Dashboard

Run `livewire web -dir ./captures` and open the local URL printed by the command.
Put capture files in that directory, select one, choose replay intent in
**Replay intent & settings**, then use **Inspect & preview**. Select sessions
in the coverage table and inspect again. Review the target before **Start replay**.

TLS/FTP/SSH inputs appear only for a fresh-session route. Key logs, CA files,
private keys, and pinned public keys must be in the dashboard working directory.
Supported private-key suffixes are `.key`, `.pem`, or `.txt`; pinned host keys
use `.pub` or `.txt`. These files are read through the existing rooted file API.

Changing a capture, mode, session selection, rule pack, key log, or UDP boundary
invalidates the preview. A changed capture digest rejects a stale start. Start
is disabled during active work; Stop remains available. Results distinguish a
match, difference, incomplete exchange, unverified completion, and wire-only
execution. Detailed differences and downloadable reports appear after the run.

**Two-sided DUT** is an independent topology choice. Its preview uses the actual
two-sided actor plan. Choose transport or wire intent: the lab does not provide
application-semantic equivalence. Full-capture topology mapping remains required;
session selection and fresh secure application replay are one-sided features.

## Compatibility and API additions

- `live <capture>` aliases `reproduce`, including flags on either side of the
  positional capture. `live -in <capture>` keeps the historical TCP engine.
- Noninteractive commands without `-mode` retain automatic routing. Interactive
  reproduction asks for intent unless an explicit mode/profile was provided.
- `-wire` and `-profile wire` select explicit wire replay. Existing protocol
  commands remain available for compatibility.
- `/api/plan` accepts `mode`, `sessions`, `shape` (`one`/`lab`), and
  `secure.keylog`. It returns shared `readiness`, `mode`, selected/excluded packet
  counts, and `captureDigest` alongside existing fields.
- `/api/run` adds `mode`, `sessions`, `captureDigest`, and `secure` inputs:
  `keylog`, `ca`, `serverName`, `user`, `password`, `privateKey`, `hostKey`,
  `commands`, `expects`, `timeoutSeconds`, `insecureSkipVerify`.
- Omitted `gapMs` retains the default; explicit `0` means no wait.
- `/api/lab` accepts explicit `mode` and `captureDigest` for reviewed starts.
- Excluded plan entries have `excluded: true`; consumers must not count them as
  failed or executed sessions. Whole-capture exact-once coverage is retained.
- Legacy JSON confidence fields remain for compatibility; human inspection
  reports capture quality instead of presenting that heuristic as a guarantee.

## Verification before release

Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and
`node --test scripts/dashboard.test.cjs`. The JavaScript checks exercise the
shipped state transitions; they do not replace visual browser QA.

Version 1 publication requires the CI, reproducibility, security and
software-lab qualification gates, including two-hour protocol matrices for
both commands. Windows/Linux physical NIC and DUT checks, browser visual and
keyboard checks, and the uncoached pilot remain part of the separate physical
qualification profile. Automated results do not assert that those checks passed.
