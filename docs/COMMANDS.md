# Command reference

Every Livewire command, its options, and what its output means. The everyday
workflow is in the [README](../README.md); install steps are in [SETUP.md](SETUP.md).

This reference describes the 1.1.0 command contract. When using a 1.0.1 binary,
use its
[version-pinned command reference](https://github.com/kvmukilan/livewire/blob/v1.0.1/docs/COMMANDS.md)
with that binary. In 1.0.1, `reproduce` invokes application replay; in 1.1 it is
stateless packet replay.

Run `livewire help <command>` for the same information at the terminal, and
`livewire <command> -all-flags` for the complete option list of one command.

## Primary

### `live`

Replay a recorded exchange against your device and report, in plain language,
whether it behaved the same. This is the command to hand to someone else. It
inspects selected sessions before it opens an interface or connection and uses
fresh application sessions by default. No `-mode` flag or mode-selection prompt
is needed. Use `reproduce` for stateless captured-packet transmission.

```sh
livewire live issue.pcap -t 192.168.1.50
```

For ordinary TCP, UDP, and ICMP supply the device IP; the destination port comes
from the capture. Packet drivers also require a network connection. Plain HTTP
and other socket-based application adapters do not require a packet interface. For TLS, FTPS, and SSH it opens a fresh application session
through the OS socket stack, so `-t` may be `host:port` and no packet interface is
needed. In non-interactive use, a missing requirement is an error that names the
exact flag to add.

| Capture contains | Automatic route |
|---|---|
| HTTP/1, DNS, MQTT 3.1.1/5, Modbus, DNP3, FTP, or a rule-pack protocol | semantic adapter and response comparison |
| UDP or ICMP | live datagram/echo driver with reply checking |
| ordinary TCP without an adapter | blocked by default; advanced `-mode auto` or `-exact-tcp` retains the packet driver |
| TLS with matching embedded PCAPNG secrets or `-keylog` | decrypt captured records, detect the inner protocol, then open fresh certificate-verified TLS |
| TLS without secrets | fresh verified handshake from captured ClientHello metadata; application replay remains incomplete and unverified |
| explicit or implicit FTPS with matching embedded secrets or `-keylog` | FTP control/data coordinator with fresh verified TLS |
| SSH | fresh SSH using explicit credentials, commands, and a required pinned host key |
| DNP3 Secure Authentication, MQTT enhanced authentication, or unsupported security | blocked with the reason; no false success |
| unknown opaque/encrypted traffic | blocked; never silently replayed as ordinary TCP or wire traffic |

Embedded PCAPNG TLS secrets are used automatically; an explicit `-keylog` takes
priority. Malformed embedded secrets fail closed. An adjacent key log or
`SSLKEYLOGFILE` value is never read without explicit selection. Captured
TLS/SSH ciphertext is never sent by automatic mode. Use `reproduce` for raw
frame injection. Advanced `live -wire` and `live -profile wire` remain available
for compatibility and also make no response-equivalence claim.

| Option | Meaning |
|---|---|
| `-mode <intent>` | advanced compatibility override: application (default), transport, wire, or auto |
| `-session <id>` | select an exchange from `check -details`; repeatable |
| `-dry-run` | inspect selection, requirements, target, and output paths without sending |
| `-in <file>` | recognized TLS or explicit secure inputs select fresh sessions; other captures retain historical TCP dry-run/packet controls; use a positional capture for the normal application workflow |
| `-t <ip>` | your device's address |
| `-i <name>` | network connection to replay on |
| `-n <count>` | replay this many times and report how often it matched — see [below](#when-the-problem-only-happens-sometimes) |
| `-under-load` | reproduce a timing or load issue: replay at the recorded speed |
| `-exact-tcp` | use stateful transport replay for a low-level TCP issue |
| `-wire` | explicitly inject captured frames as-is; requires `-i` and does not claim session adaptation or reply equivalence |
| `-keylog <file>` | matching NSS key log for TLS or FTPS |
| `-server-name <name>` / `-ca <file>` | TLS identity and optional private CA; verification is on by default; handshake-only TLS defaults to captured SNI, then target hostname |
| `-user`, `-pass`/`-key`, `-host-key`, `-cmd` | SSH requirements; repeat `-cmd` and optionally pair each with `-expect` |
| `-details` | also print the capture assessment, the replay plan, and every session's verdict |
| `-strict-exit` | exit nonzero unless every selected exchange completes with positive matching response evidence |
| `-run-timeout <duration>` | bound the whole run, including repeated attempts and waits |
| `-response-timeout <duration>` | bound one framed TCP/TLS application or UDP/ICMP response; 0 preserves protocol defaults; at most 10m; not available for the raw TCP engine, FTP/FTPS, SSH, or wire mode |
| `-expect-fault reset\|timeout` | require that fault during an expected TCP/TLS application response read after a request was sent; recorded separately from response equivalence; conflicts with `-strict-exit` and `-stop-when-different` |
| `-concurrency <count>` | maximum workers for concurrent profiles (default 32); functional replay stays sequential |
| `-state-dir <new-dir>` / `-resume <dir>` | save durable progress or resume with the same capture and replay options |
| `-scenario <json>` | declare HTTP setup, response bindings, dependencies, and comparison policies |

Packet-level routes need Administrator (Windows) or `sudo` (Linux). Generic
replay writes `<capture>.report.json` and, when evidence is available,
`<capture>.actual.pcap`. Secure routes write a redacted protocol report. With
`-n`, each secure attempt opens a fresh connection and receives its own report.
Default output names never replace a previous run; Livewire selects a numbered
name. Explicit output paths must not already exist.

Response verification distinguishes these outcomes:

- **MATCHED THE CHECKED RESPONSES** — the compared responses matched under the
  selected policy. Device logs and fault-specific evidence are still needed to
  establish whether a crash, timeout, or other original issue recurred.
- **DIFFERENT FROM THE RECORDING** — the exchange completed but the device
  answered differently; the differences are listed.
- **THE EXCHANGE DID NOT COMPLETE** — it stopped early, with the reason.
- **EXCHANGE COMPLETED; EQUIVALENCE NOT CHECKED** — verification was off or no
  positive response comparison was available. Explicit wire replay has its own
  wire-only outcome and never claims response equivalence.

Run `livewire help reliability` for TCP mode selection and repeatable workflows.
Durable resume cannot restore a socket or the target's application state. See
[RELIABILITY_IMPLEMENTATION.md](RELIABILITY_IMPLEMENTATION.md) for recovery limits.

To reproduce an expected timeout rather than require matching responses:

```sh
livewire live issue.pcap -t 192.168.1.50 \
  -response-timeout 5s -expect-fault timeout
```

Every selected exchange must positively observe the requested fault. A refused
connection, handshake failure, ordinary EOF, maintenance failure, cancellation,
or failed cleanup does not satisfy it. A matching fault remains an incomplete
exchange in the response-comparison report. `-run-timeout` bounds the whole run;
`-timeout` is the separate secure-session budget where that route supports it.

Application replay opens fresh connections and adapts supported protocol state.
MQTT 3.1.1/5 supports bidirectional QoS handshakes and keepalive servicing during
captured timing gaps; MQTT 5 applies negotiated limits and rebuilds topic aliases.
DNP3 reassembles supported transport/application fragments, accepts changed live
fragmentation, and generates required confirmations. Unknown DNP3 object layouts,
unsupported link control, and secure authentication remain explicit limits. See
the [protocol details](RELIABILITY_IMPLEMENTATION.md#protocol-session-state).

`-strict`, `-profile`, `-set`, `-rules`, `-report`, `-actual-out`, and
`-no-rst-guard` are available behind `-all-flags`.

The positional `live <capture>` form uses the application orchestrator.
`live -in <file>` with explicit secure inputs such as `-keylog`, `-ca`, or SSH
credentials also uses that route. Recognized TLS always takes the fresh-session
route, including `live -in <file> -t <host:port>` without secure flags. Incompatible
legacy TCP controls are refused before traffic. Other captures retain historical
`live -in` dry-run, flow-selection, sequence-rewrite and raw-L4 controls.
See [Legacy `live -in` mode](#legacy-live--in-mode).

### `reproduce`

Send captured packets unchanged, without maintaining a live connection. Both
recorded directions are transmitted in capture order. This reproduces recorded
packet stimuli; it does not negotiate TCP/TLS, adapt requests, wait for replies,
or claim that the original application outcome occurred.

```sh
livewire reproduce issue.pcap -dry-run
livewire reproduce issue.pcap -i eth0 -report packets.json
livewire reproduce issue.pcap -i eth0 -pps 1000 -n 5
```

| Option | Meaning |
|---|---|
| `<capture>` or `-in <file>` | PCAP/PCAPNG input; flags may precede or follow a positional capture |
| `-i <name>` / `-iface <name>` | interface to inject packets on; required unless previewing |
| `-session <id>` | select recorded sessions; repeatable |
| `-n <count>` / `-loop <count>` | number of passes; `0` continues until interrupted |
| `-pps <n>` / `-mbps <n>` | packets per second or megabits per second |
| `-multiplier <n>` | multiply captured timing rate; `2` is twice as fast |
| `-topspeed` | send as fast as the sender allows |
| `-dry-run` | validate selection and schedule without opening a sender |
| `-report <file>` | write collision-safe JSON transmission evidence |

Use at most one rate option. Without a rate option, recorded timing is used.
The selected frames must have one link type compatible with the output
interface. Addresses, ports, sequence numbers and ciphertext remain unchanged;
use `rewrite` beforehand when static address changes are needed. Packet access
requires the appropriate driver and privileges. Reports always have
`verified: false`, including after all frames were sent successfully.

TLS-containing PCAPs can be transmitted as captured bytes without key material,
but those bytes cannot establish a new TLS application session. Use `live`
with matching keys for fresh secure application replay.

In 1.0.x, `reproduce` invoked the application workflow. In 1.1, migrate those
commands to `live`. Application options such as `-t`, `-keylog`, `-resume` and
`-mode application` are rejected before network access. `replay` remains a
compatibility alias for stateless `reproduce`.

## Supporting commands

### `check`

Look at a capture without touching the network: what traffic it holds, and
whether Livewire can replay it faithfully. Run it before `live` if you want
to know what you were sent.

```sh
livewire check issue.pcap              # summary + replayability
livewire check issue.pcap -details     # plus the per-session plan and checksums
livewire check -in issue.pcap -json assessment.json
```

| Option | Meaning |
|---|---|
| `-mode <intent>` | advanced compatibility override: application (default), transport, wire, or auto |
| `-session <id>` | select an exchange from `check -details`; repeatable |
| `-in <file>` | the capture, if you prefer it to a bare argument |
| `-details` | add the per-session replay plan and checksum validation |
| `-json <file>` | also write the machine-readable assessment |

Reads the file only — no interface is opened, no privileges needed. The coverage
table under `-details` names every session, its protocol, the driver and adapter
chosen, the fidelity achievable, and any warnings or blockers. A plan is invalid
if a captured frame is missing from it or represented twice.

`check` replaced the separate `info` and `analyze` commands, both of which still
work — see [older names](#older-names-that-still-work).

### `capture`

Record traffic from a network connection into a file, for replaying later.

```sh
livewire capture -i eth0 -o issue.pcap -duration 30s
```

| Option | Meaning |
|---|---|
| `-i <name>` | network connection to record from |
| `-o <file>` | where to save |
| `-n <count>` | stop after this many packets |
| `-duration <time>` | stop after this long, e.g. `30s`, `5m` |

Stops on Ctrl-C if you give neither limit. It records the whole connection, so
use an isolated adapter if you want only the traffic of interest. Needs elevation.

### `ifaces`

List your network connections, with their addresses and whether each can be used
for live replay.

```sh
livewire ifaces
```

No options. On Windows this is where you get the exact `\Device\NPF_{...}` value
to pass to `-i` — a friendly name like `Ethernet 2` will not work. It is also the
quickest check that packet access is working at all.

### `web`

Serve the browser dashboard: load captures, compile a plan, run one-sided or
two-sided replays, watch progress, and download artifacts.

```sh
livewire web
livewire web -addr 127.0.0.1:9000 -dir ./captures
```

| Option | Meaning |
|---|---|
| `-addr <host:port>` | where to serve (default `127.0.0.1:8080`) |
| `-dir <path>` | folder captures are read from and written to (default `.`) |
| `-unsafe-listen` | explicitly permit a non-loopback bind; the service remains unauthenticated |

Binds to localhost by default and the page is embedded in the binary, so it works
offline. Mutations require a per-process CSRF token and same-origin JSON requests;
files are confined to `-dir`. Live replay from the dashboard needs the same
privileges as the CLI. Never expose `-unsafe-listen` directly to an untrusted
network: it is an explicit override, not authentication.

---

## Advanced and compatibility tools

Shown by `livewire help --all`. These are power-user tools; `live` covers
the normal case.

### Legacy `live -in` mode

The stateful TCP engine that `live` wraps, with the controls exposed. Learns
the live peer's ISN and realigns sequence and acknowledgement numbers per flow.
Protocol-agnostic — only TCP headers are rewritten.

```sh
livewire live -in issue.pcap                            # dry run, no NIC
livewire live -in issue.pcap -live -i eth0 -t 192.0.2.50 -all
```

| Option | Meaning |
|---|---|
| `-in <file>` | the capture |
| `-live` | actually send on the wire instead of simulating |
| `-i <name>` | network connection (implies `-live`) |
| `-t <ip[:port]>` | target, defaulting to the captured server endpoint |
| `-n <count>` | replay this many times and report how often it matched |
| `-all` | replay every TCP flow, not just one |
| `-flow <index>` | replay a single flow |
| `-mode <m>` | dry-run mode: `rewrite`, `peer`, or `both` |
| `-o <file>` | write the rewritten capture (rewrite mode) |
| `-report <file>` | write a JSON report |
| `-v` | print the per-packet sequence-rewrite table |

Defaults to a dry run, which needs no privileges and touches no interface — good
for checking that a capture's sequence numbers are coherent before going near a
device. `-n` requires `-live`; repeating a deterministic dry run is refused.

### `lab`

Two-sided replay through a device under test — a firewall, NAT, proxy, router, or
impairment device — driving a client actor and a server actor on separate NICs and
recording both sides into one PCAPNG.

```sh
livewire lab -in issue.pcap -topology topology.json \
  -client-iface eth1 -server-iface eth2
```

| Option | Meaning |
|---|---|
| `-in <file>` | the capture |
| `-topology <file>` | topology JSON, describing both sides (required) |
| `-client-iface`, `-server-iface` | NICs, overriding the topology |
| `-scenario <file>` | deterministic fault scenario: delay, jitter, drop, duplication, reorder, rate, MTU |
| `-evidence <file>` | dual-interface PCAPNG (default `<capture>.lab.pcapng`) |
| `-report <file>` | JSON report (default `<capture>.lab.report.json`) |

Needs a hand-written topology file, so it is genuinely a power-user tool. Actors
wait for preceding traffic to cross the DUT, so a delayed or dropped request
cannot receive a prerecorded response.

### `replay`

Compatibility alias for stateless [`reproduce`](#reproduce). It uses the same
packet sender, rate validation, selection and report semantics. Use `live` when
a target must participate in a fresh stateful exchange.

```sh
livewire replay -in issue.pcap -i eth0 -pps 1000
livewire replay -in issue.pcap -dry-run
```

| Option | Meaning |
|---|---|
| `-in <file>` | the capture |
| `-i <name>` | network connection to send on |
| `-n <count>` | send the capture this many times (`0` = forever) |
| `-pps <n>` | packets per second |
| `-mbps <n>` | megabits per second |
| `-multiplier <n>` | scale the capture's own timing (`2` = twice as fast) |
| `-topspeed` | send as fast as possible |
| `-dry-run` | print the schedule without sending |

Rate options are mutually exclusive; supplying more than one is rejected.

### `rewrite`

Apply static edits to a capture without replaying it, in the style of
`tcprewrite`.

```sh
livewire rewrite -in issue.pcap -o edited.pcap \
  -pnat 10.0.0.0/8,192.168.0.0/16 -fixcsum
```

| Option | Meaning |
|---|---|
| `-in <file>`, `-o <file>` | input and output |
| `-srcmac`, `-dstmac` | rewrite link-layer addresses |
| `-pnat <match,rewrite>` | pseudo-NAT both endpoints by CIDR (repeatable) |
| `-portmap <from:to>` | remap a TCP/UDP port (repeatable) |
| `-ttl <n>` | set IPv4 TTL / IPv6 hop limit |
| `-fixcsum` | recompute all checksums even where nothing changed |

`-srcipmap`, `-dstipmap`, `-tcp-seq-shift`, and the VLAN options are behind
`-all-flags`.

### `convert`

Convert a pcapng file to classic pcap, optionally reassembling IP fragments.

```sh
livewire convert -in issue.pcapng -o issue.pcap -reassemble
```

| Option | Meaning |
|---|---|
| `-in <file>`, `-o <file>` | input and output |
| `-reassemble` | reassemble IPv4 and IPv6 fragments into whole datagrams |

Most commands read pcapng directly, so this is mainly for tools that cannot, and
for `-reassemble`. A pcapng holding mixed link types cannot be converted.

### `ftp-replay`

Compatibility alias for the FTP/FTPS driver used automatically by positional
`live`. It remains available for scripts that want the older,
protocol-specific spelling.

```sh
livewire live secure.pcap -t ftp.example:990 -keylog sslkeys.log
livewire ftp-replay -in issue.pcap -t ftp.example:21 \
  -set ftp.user=lab -set ftp.password=secret
livewire ftp-replay -in secure.pcap -t ftp.example:990 \
  -keylog sslkeys.log -server-name ftp.example
```

| Option | Meaning |
|---|---|
| `-in <file>` | capture containing one FTP/FTPS control group |
| `-t <host:port>` | live FTP target |
| `-keylog <file>` | NSS key log for explicit or implicit FTPS |
| `-server-name <name>` / `-ca <file>` | verified TLS identity and private CA |
| `-set ftp.user=...` | replace captured USER value |
| `-set ftp.password=...` | replace captured PASS value |
| `-set ftp.account=...` | replace captured ACCT value |
| `-set ftp.advertise-ip=...` | active-mode address when route inference is insufficient |
| `-verify off\|lenient\|strict` | compare reply classes or exact reply codes |
| `-report <file>` | redacted JSON report |

`PASV`, `EPSV`, `PORT`, and `EPRT` are renegotiated against the live peer.
`LIST`, `NLST`, `RETR`, `STOR`, `APPE`, and `STOU` data are verified by direction,
byte count, and SHA-256. Explicit FTPS upgrades the existing control connection
after `AUTH TLS`; implicit FTPS starts TLS immediately. Protected data channels
use fresh certificate-verified TLS and captured ciphertext is never transmitted.
Accepted `PROT C` and `PROT P` replies set protection separately for each following
transfer; a rejected request does not change it. A live rejection of required
`PROT P` stops the replay rather than downgrading that transfer. Active data
connections reverse the TCP initiator, but the FTP client remains the TLS client.
Protected capture data needs its matching key log. Ambiguous or unmatched data
sessions are blockers.

### `tls-replay`

Compatibility command for captured TLS application replay. It retains its
explicit keylog requirement; use `live` for embedded PCAPNG secrets or a
keylog-free handshake. It decrypts with the supplied key log and re-terminates a
fresh, certificate-verified connection through the detected inner adapter.

```sh
livewire live issue.pcap -keylog sslkeys.log -t device.example:443
livewire tls-replay -in issue.pcap -keylog sslkeys.log \
  -t device.example:443 -server-name device.example
```

| Option | Meaning |
|---|---|
| `-in <file>` | the capture |
| `-keylog <file>` | NSS-style SSL key log matching the capture (required) |
| `-t <host:port>` | the live target |
| `-server-name <name>` | certificate DNS name (defaults to the target host) |
| `-ca <file>` | PEM CA bundle, for a private CA |
| `-strict` | require live responses to byte-match the capture |
| `-report <file>` | JSON report (default `<capture>.tls.report.json`) |

Configure whatever produced the capture to write an `SSLKEYLOGFILE`, and treat
that file as a credential. Unified mode may suggest that environment value or an
adjacent key log but never reads it without affirmative selection. Ciphertext
alone cannot recover the application requests, and the capture must hold exactly one selected TLS
session. Certificate verification stays on unless you explicitly pass
`-insecure-skip-verify`, which is a lab-only override. Key-log contents never
reach reports or logs.

### `ssh-replay`

Compatibility alias for the SSH driver selected by positional `live`.
Captured SSH ciphertext does not reveal commands, so every operation is
supplied explicitly and runs over a fresh authenticated connection.

```sh
livewire live issue.pcap -t device.example:22 \
  -user lab -key id_ed25519 -host-key device_host_key.pub -cmd 'show version'
livewire ssh-replay -in issue.pcap -t device.example:22 \
  -user lab -key id_ed25519 -host-key device_host_key.pub \
  -cmd 'show version' -expect 'Version'
```

| Option | Meaning |
|---|---|
| `-in <file>` | the capture, used to account for the SSH lane |
| `-t <host:port>` | the live device |
| `-user <name>` | SSH username |
| `-pass <password>` / `-key <file>` | exactly one of the two |
| `-host-key <file>` | OpenSSH public host key to pin (required by unified mode) |
| `-cmd <command>` | a command to run (repeatable, at least one) |
| `-expect <text>` | required output substring, one per `-cmd` |
| `-report <file>` | JSON report (default `<capture>.ssh.report.json`) |

Prefer a dedicated lab key over a password on a shared command line. Credentials,
command text, and response bodies are excluded from reports and logs; command
output is recorded by length and SHA-256 only. Unified mode refuses to connect
without `-host-key`; the legacy alias retains its historical unpinned lab mode
for compatibility and flags that choice as a limitation.

### `bundle`

Create a support archive that is safe to share: metadata only, with packet
evidence referenced by digest rather than embedded, because captures can contain
credentials.

```sh
livewire bundle -report issue.report.json \
  -evidence issue.actual.pcap -o issue.support.zip
```

| Option | Meaning |
|---|---|
| `-report <file>` | the run report to package |
| `-o <file>` | the ZIP to write (must not already exist) |
| `-evidence <file>` | evidence to reference by digest (repeatable) |

### `rstdrop`

Hold host RST suppression open until Ctrl-C.

```sh
livewire rstdrop -t 192.0.2.50 -port 502
```

| Option | Meaning |
|---|---|
| `-t <ip>` | target address |
| `-port <n>` | target TCP port |
| `-sport <n>` | match only this source port |

**You usually do not need this.** Stateful packet routes in `live` arm and release
the same guard automatically for the duration of a replay. Use it only when an external
injector — Scapy, or a hand-rolled script — is sending the packets instead. Needs
Administrator or root.

### `version`

```sh
livewire version
```

Prints the version. No options.

---

## Older names that still work

`check` merged these two. Both keep their exact previous behaviour and output, so
existing scripts and older instructions keep working.

Compatibility commands and flags remain available throughout 1.x, including
`live -in`, `ftp-replay`, `tls-replay`, and `ssh-replay`. Deprecated `-on`, `-to`,
and `-iterations` still work with a warning; prefer `-i`, `-t`, and `-n`.
The announced removal boundary is 2.0.

| Command | What it does now |
|---|---|
| `livewire info <file>` | the capture summary half of `check` |
| `livewire analyze -in <file>` | the replayability assessment half of `check` |

---

## When the problem only happens sometimes

`live -n` replays the selected plan more than once and reports how often the device
behaved the same. An intermittent fault is named as such, rather than reported as
a single pass or failure:

```sh
livewire live issue.pcap -t 192.168.1.50 -i eth0 -n 5
```

```
Attempt 1 of 5: SAME AS THE RECORDING
Attempt 2 of 5: SAME AS THE RECORDING
Attempt 3 of 5: DIFFERENT FROM THE RECORDING — txid 0x7: exception 0x83
Attempt 4 of 5: SAME AS THE RECORDING
Attempt 5 of 5: DID NOT COMPLETE — the device reset (refused) the connection

================================
OVERALL: INTERMITTENT
  same as the recording   3 of 5
  different               1 of 5
  did not complete        1 of 5

This device did not behave the same way every time, which is itself a
finding. Send us the report file.
================================
```

Details worth knowing:

- Attempts run one after another, `-gap` apart (default 1s).
- TCP application and secure attempts open fresh connections with OS-managed
  sequence state. The stateful packet engine also resets its live flow state;
  explicit wire injection keeps its raw-frame semantics.
- Generic replay records attempts in one report, with aggregate counts and an
  `intermittent` outcome. Packet routes can also publish an evidence capture.
  Secure routes write one redacted report per attempt, named
  `<report-base>.attempt-N.json`; they do not fabricate a wire capture.
- `-stop-when-different` ends the run at the first attempt that diverges, when one
  failing sample is all you need. Ctrl-C stops cleanly and still writes a report
  for the attempts that ran.
- The dashboard exposes the same control as an **Attempts** field. Stateless
  `reproduce -n` and `replay -n` repeat captured packet sends without checking
  device responses.

---

