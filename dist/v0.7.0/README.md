# Livewire

Livewire v0.7.0 is a protocol-adaptive PCAP replay platform for reproducing
network and application failures against a live endpoint or through a device
under test (DUT). Every captured frame receives an explicit replay lane:
semantic, stateful transport, wire, or blocked. Livewire never silently drops a
protocol and never reports more fidelity than it delivered.

The project is licensed under the [MIT License](LICENSE).

**New here?** [SETUP.md](SETUP.md) has copy-paste install instructions for
Windows and Linux. Come back here for what the commands do.

---

## Contents

- [The five everyday commands](#the-five-everyday-commands)
- [One set of option names](#one-set-of-option-names)
- [Command reference](#command-reference) — every command, explained
- [When the problem only happens sometimes](#when-the-problem-only-happens-sometimes)
- [What v0.7.0 adds](#what-v070-adds)
- [Where things are documented](#where-things-are-documented)

---

## The five everyday commands

`livewire` with no arguments shows these. Everything else is a power-user tool,
listed by `livewire help --all`.

| Command | What it does |
|---|---|
| [`reproduce`](#reproduce) | replay a capture against your device and say what happened |
| [`check`](#check) | look at a capture: what's in it, and whether it can be replayed |
| [`capture`](#capture) | record traffic from a network connection into a file |
| [`ifaces`](#ifaces) | list your network connections |
| [`web`](#web) | open the browser dashboard |

`livewire help <command>` shows one command's options.

## One set of option names

The same idea keeps the same name on every command that has it:

| Option | Means |
|---|---|
| `-in` | the capture file (`reproduce` and `check` also take it as a bare argument) |
| `-i` | which network connection to use |
| `-t` | the device to talk to |
| `-n` | how many — attempts for a replay, packets for `capture` |
| `-o` | where to write |
| `-live` | on `live`, actually send on the wire instead of simulating |
| `-details` | show the expert tables instead of the plain-language summary |

Older spellings (`--to`, `--on`, `-iface`, `-target`, `-out`, `-loop`, `-count`,
`-ip`) still work everywhere they used to, so existing scripts keep running. Each
command shows only its common options; add **`-all-flags`** to any command to see
every option it accepts, with the compatibility aliases marked.

---

# Command reference

## Everyday

### `reproduce`

Replay a recorded exchange against your device and report, in plain language,
whether it behaved the same. This is the command to hand to someone else.

```sh
livewire reproduce issue.pcap -t 192.168.1.50
```

It asks two questions — your device's address and which network connection to use
— and pre-selects the right connection. Answer them up front with `-t` and `-i` to
run unattended. The port always comes from the capture, so a recording of TCP 502
contacts port 502 on your device.

| Option | Meaning |
|---|---|
| `-in <file>` | the capture, if you prefer it to a bare argument |
| `-t <ip>` | your device's address |
| `-i <name>` | network connection to replay on |
| `-n <count>` | replay this many times and report how often it matched — see [below](#when-the-problem-only-happens-sometimes) |
| `-under-load` | reproduce a timing or load issue: replay at the recorded speed |
| `-exact-tcp` | reproduce a low-level TCP issue: send the recorded packets exactly |
| `-details` | also print the capture assessment, the replay plan, and every session's verdict |

Needs Administrator (Windows) or `sudo` (Linux). Writes two files next to the
capture: `<capture>.report.json` to send back, and `<capture>.actual.pcap` holding
the traffic that was really sent and received.

Every run ends in one of four verdicts:

- **SAME AS THE RECORDING** — the device behaved as it did when the capture was
  taken. If the recording shows the problem, the problem reproduces.
- **DIFFERENT FROM THE RECORDING** — the exchange completed but the device
  answered differently; the differences are listed.
- **THE EXCHANGE DID NOT COMPLETE** — it stopped early, with the reason.
- **EXCHANGE COMPLETED; EQUIVALENCE NOT CHECKED** — only when verification is off.

`-strict`, `-profile`, `-set`, `-rules`, `-report`, `-actual-out`, and
`-no-rst-guard` are available behind `-all-flags`.

### `check`

Look at a capture without touching the network: what traffic it holds, and
whether Livewire can replay it faithfully. Run it before `reproduce` if you want
to know what you were sent.

```sh
livewire check issue.pcap              # summary + replayability
livewire check issue.pcap -details     # plus the per-session plan and checksums
livewire check -in issue.pcap -json assessment.json
```

| Option | Meaning |
|---|---|
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

## Advanced

Shown by `livewire help --all`. These are power-user tools; `reproduce` covers
the normal case.

### `live`

The stateful TCP engine that `reproduce` wraps, with the controls exposed. Learns
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

Stateless send, in the style of `tcpreplay`: blast a capture's frames onto a
connection at a chosen rate. There is no live peer, no sequence tracking, and no
reply checking — use `reproduce` or `live` when the frames must land on something
that answers.

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

Rate options take priority in the order `-topspeed`, `-pps`, `-mbps`,
`-multiplier`.

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

Replay a captured FTP or FTPS control session together with its negotiated data
connections. Plain FTP is coordinated automatically by `reproduce`; use this
advanced command for encrypted sessions or explicit endpoint and verification
control.

```sh
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
Ambiguous or unmatched data sessions are blockers.

### `tls-replay`

Decrypt a captured TLS session with its key log and re-terminate a fresh,
certificate-verified connection, replaying the decrypted application chronology
through the detected inner adapter.

```sh
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
that file as a credential. Ciphertext alone cannot be replayed, and the capture
must hold exactly one TLS session. Certificate verification stays on unless you
explicitly pass `-insecure-skip-verify`, which is a lab-only override. Key-log
contents never reach reports or logs.

### `ssh-replay`

Re-terminate an SSH session against a live device. Captured SSH ciphertext does
not reveal the commands, so you supply them explicitly.

```sh
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
| `-host-key <file>` | OpenSSH public host key to pin (recommended) |
| `-cmd <command>` | a command to run (repeatable, at least one) |
| `-expect <text>` | required output substring, one per `-cmd` |
| `-report <file>` | JSON report (default `<capture>.ssh.report.json`) |

Prefer a dedicated lab key over a password on a shared command line. Credentials,
command text, and response bodies are excluded from reports and logs; command
output is recorded by length and SHA-256 only. Without `-host-key` the observed
key is recorded by fingerprint and the missing identity pin is flagged as a
limitation.

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

**You usually do not need this.** `reproduce` and `live` arm and release the same
guard automatically for the duration of a replay. Use it only when an external
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

| Command | What it does now |
|---|---|
| `livewire info <file>` | the capture summary half of `check` |
| `livewire analyze -in <file>` | the replayability assessment half of `check` |

---

## When the problem only happens sometimes

`-n` replays the whole capture more than once and reports how often the device
behaved the same. An intermittent fault is named as such, rather than reported as
a single pass or failure:

```sh
livewire reproduce issue.pcap -t 192.168.1.50 -i eth0 -n 5
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
- Each attempt opens a fresh connection with a new client port and ISN. Re-sending
  an identical TCP four-tuple immediately would be treated as a stale duplicate
  and reset — which would look like a failure to reproduce rather than the
  artefact it is. The substitution is recorded in the report's `transformations`.
- One report and one evidence capture cover the whole run. Each result carries an
  `attempt` number, and the report gains `attempts` plus an `outcome` object with
  the counts, whether the device was `consistent`, and an `intermittent` flag.
- A single run's report is byte-for-byte what it was before this feature existed.
- `-stop-when-different` ends the run at the first attempt that diverges, when one
  failing sample is all you need. Ctrl-C stops cleanly and still writes a report
  for the attempts that ran.
- Also available on `live -n`, and as an **Attempts** field on the dashboard.

---

## What v0.7.0 adds

- Coordinated FTP replay and verified explicit/implicit FTPS retermination,
  including active/passive IPv4 and IPv6 data connections.
- Bounded, strict PCAP/PCAPNG parsing and atomic private artifact publication.
- A rooted dashboard file boundary, CSRF and same-origin protection, request
  limits, loopback enforcement, server timeouts, and graceful job shutdown.
- Central secret redaction across CLI, dashboard, logs, reports, and bundles.
- Restricted Windows DLL loading and a hash/signature-pinned WinDivert installer.
- Reproducible Go 1.26.7 release builds, CycloneDX SBOM, SHA-256 manifests,
  immutable CI actions, vulnerability/static/race/fuzz gates, and provenance.

Carried over from v0.6.0:

- A front door showing five everyday commands instead of sixteen, with
  `livewire help --all` for the rest and `livewire help <command>` for one.
- `check`, merging `info` and `analyze` into one command.
- One option vocabulary — `-in`, `-i`, `-t`, `-n`, `-o`, `-live`, `-details` —
  meaning the same thing everywhere, with every previous spelling still accepted.
- `-n` iterations on `reproduce`, `live`, and the dashboard, reporting a
  reproduction rate and naming an intermittent device as such.
- `-details` to hide the expert tables from the default `reproduce` output, and
  `-all-flags` to see a command's full option list.

Carried over from v0.5.0: transport-neutral traces and replay plans covering TCP,
stateful UDP, ICMPv4/ICMPv6 Echo, IP fragments and explicit raw-frame lanes; four
fidelity profiles; adapters for HTTP/1.x, DNS, MQTT, Modbus/TCP and DNP3; honest
TLS and SSH retermination; JSON rule packs for proprietary framed protocols; the
two-interface `lab` runner with deterministic faults and PCAPNG evidence; and the
offline embedded dashboard with redacted support bundles.

Full history is in [CHANGELOG.md](CHANGELOG.md).

---

## Where things are documented

| Document | For |
|---|---|
| [SETUP.md](SETUP.md) | installing on a new Windows or Linux machine |
| **README.md** (this file) | what each command does |
| [DOCUMENTATION.md](DOCUMENTATION.md) | the full operator guide: walkthroughs, protocol detail, fidelity model, troubleshooting |
| [WINDOWS-QUICKSTART.md](WINDOWS-QUICKSTART.md) | advanced Windows examples |
| [SECURITY.md](SECURITY.md) | handling captures, credentials, and reports |
| [CHANGELOG.md](CHANGELOG.md) | what changed in each release |

Building from source is covered in [SETUP.md](SETUP.md#build-from-source).
