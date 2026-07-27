# Changelog

All notable changes to Livewire are documented here.

## [0.6.0] - 2026-07-27

### Highlights

- The front door now shows five everyday commands instead of sixteen. Running
  `livewire` with no arguments points a first-time user at `reproduce` rather
  than listing every power-user tool alongside it.
- `check` merges the old `info` and `analyze` into one command that answers both
  "what is in this capture" and "can it be replayed".
- One option vocabulary across the whole CLI: `-in`, `-i`, `-t`, `-n`, `-o`,
  `-live`, `-details` mean the same thing on every command that has them.
- `-n` replays a capture several times and reports how often the device behaved
  the same, so an intermittent fault is reported as a rate instead of a single
  pass or failure.
- Every previous command name and option spelling still works.

### Added

- `livewire check` — capture summary plus replayability assessment in one
  offline command, with `-details` for the per-session plan and checksums and
  `-json` for the machine-readable assessment.
- `-n` iterations on `reproduce` and `live`, and an **Attempts** field on the
  dashboard's one-sided run form. Reports gain an `attempts` count and an
  `outcome` object holding the per-attempt verdict counts, whether the device was
  `consistent`, and an `intermittent` flag; each result carries its `attempt`
  number. `-gap` spaces the attempts and `-stop-when-different` ends the run at
  the first divergence.
- `-details` on `reproduce` and `check`, and `-all-flags` on every command, which
  lists the complete option set and marks the compatibility aliases.
- `livewire help --all` and `livewire help <command>`.
- `livereplay.Config.LocalPort`, so a repeated replay can present a different
  client port to the device.

### Changed

- `reproduce` prints the capture assessment and coverage table only under
  `-details`. Blockers are still always shown, in plain language, because they
  change what a result means.
- `rstdrop` moved off the everyday surface and its help now explains that
  `reproduce` and `live` arm the same guard automatically.
- `ssh-replay` is registered in the main command table rather than through an
  `init()`, so the whole surface is readable in one place.
- `capture` now stops on SIGTERM as well as Ctrl-C; a supervised capture
  previously lost its buffered tail on shutdown.
- Dashboard artifact filenames use millisecond timestamps, so two attempts
  finishing within the same second no longer collide.
- `SETUP.md` is now a copy-paste path from a bare machine to a first replay on
  Windows and Linux; `README.md` documents every command.

### Fixed

- The TCP tuple rewriter ignored a configured local port and always stamped the
  captured one, so a per-attempt port change would not have reached the wire.
- Removed the unused `compileCoverage` helper.

### Compatibility

- `info` and `analyze` remain available and behave exactly as they did in 0.5.0.
- Every superseded option spelling — `--to`, `--on`, `-iface`, `-target`, `-out`,
  `-loop`, `-count`, `-ip`, `-dry-run`, `-times`, `-iterations` — is still
  accepted wherever it previously worked. They are omitted from the default help
  to keep the visible surface small; `-all-flags` shows them.
- A single-run report is byte-for-byte identical to 0.5.0. The new fields appear
  only when a run actually repeats.

## [0.5.0] - 2026-07-23

### Highlights

- Replays every captured frame through an explicit semantic, stateful, wire, or
  blocked lane instead of silently dropping unsupported traffic.
- Adds stateful TCP, UDP, ICMP Echo, HTTP, DNS, MQTT, Modbus, and DNP3 replay
  with functional, timing, transport, and wire fidelity profiles.
- Adds `lab` for deterministic two-sided replay through firewalls, NATs,
  proxies, routers, and other devices under test.
- Adds honest TLS and SSH retermination: TLS requires a matching key log; SSH
  requires credentials and explicit commands.
- Produces structured reports, actual-traffic PCAP/PCAPNG evidence, and redacted
  support bundles.
- Ships a Windows ZIP with `livewire.exe`, a driver setup helper, and a concise
  copy-paste quick-start.

### Added

- Transport-neutral traces, sessions, events, replay plans, and explicit raw
  lanes with full capture-frame accounting.
- Functional, timing, transport, and wire fidelity profiles with explicit
  selected and achieved fidelity.
- Stateful UDP and ICMPv4/ICMPv6 Echo replay, IPv6 fragment reassembly, active
  NDP resolution on Linux and Windows, and protocol-aware receive filters.
- Cancellable one-sided replay with deterministic cleanup of guards and packet
  interfaces.
- `livewire lab` two-interface DUT harness, topology mapping, deterministic
  fault scenarios, NAT/PAT learning, and multi-interface PCAPNG evidence.
- Built-in HTTP/1, DNS, MQTT, Modbus/TCP, and DNP3 semantic adapters.
- TLS 1.2/1.3 AEAD key-log decryption and fresh verified TLS retermination.
- SSHv2 retermination with explicit credentials and command scripts in default
  builds.
- Capture-bound TLS/SSH coverage plans and redacted retermination reports;
  SSH command expectations and optional public-host-key pinning.
- Safe declarative JSON rule packs for proprietary framed TCP/UDP protocols.
- Concrete per-lane driver identities, configurable UDP idle boundaries, and
  identifier/sequence-accurate ICMP verification.
- DUT-crossing-gated two-sided actors, gateway MAC resolution, topology MTU
  enforcement, TCP proxy-clock ACK/SACK adaptation, per-session lab verdicts,
  and firewall-timeout evidence.
- Sequence-aware TCP application-stream reconstruction with retransmission,
  overlap, out-of-order, SYN-data, and 32-bit wrap handling; ambiguous gaps and
  conflicting overlaps are explicit adaptive blockers while wire mode remains
  available.
- Capture-timeline-aware TLS plaintext ordering, strict TLS record/handshake
  framing, and grouped pipelined application-response reads.
- MQTT broker packet-identifier learning and acknowledgement rewriting across
  server-originated QoS 1/2 flows.
- Fragment-safe incremental tuple/checksum rewriting, per-session lab latency,
  loss/duplicate/reorder evidence, and topology-aware raw-lane side inference.
- Redacted metadata-only support ZIPs with digest references instead of packet
  payload inclusion.
- Typed `-set name=value` runtime variables, live-value learning, and
  secret-aware report redaction.
- Plan/run/lab/validation/artifact web APIs and a redesigned offline embedded
  dashboard.
- In-memory DUT simulations and unit, malformed-input, fuzz-seed,
  cancellation, redaction, API, and end-to-end tests.
- A Windows quick-start guide and setup helper that detects Npcap, optionally
  launches its interactive installer, downloads the official WinDivert binary
  archive, and copies the required 64-bit files beside `livewire.exe`.
- A self-contained Windows release ZIP containing `livewire.exe`, setup helper,
  quick-start, changelog, license, and security guidance.

### Changed

- `reproduce` now compiles and executes protocol-adaptive plans instead of
  assuming every useful capture is TCP.
- `analyze` now emits a per-session protocol coverage matrix.
- Stateful failures no longer fall back silently to raw transmission.
- Reports include capture digest, replay plan, adapter versions,
  transformations, redacted variables, evidence, and limitations.
- Verification-off runs now report completion without ever claiming that live
  responses matched the recording; receive-only one-sided UDP is an explicit
  wire lane rather than an impossible request/response run.
- Minimum supported Go version is 1.25.
- Windows operator documentation now starts from an existing EXE and separates
  dependency checks, normal `reproduce`/`live -all` use, and manual `rstdrop`.

### Security

- TLS certificate verification is enabled unless explicitly disabled for a lab.
- Passwords, secrets, credentials, authorization values, key logs, and MQTT
  credentials are excluded from logs/reports and scrubbed from error text.
- Web artifact downloads reject traversal and unsupported file types.

### Known boundaries

- HTTP/2, HTTP/3, distributed agents, and high-scale traffic generation are
  outside this release.
- TLS needs a matching key log and supported AEAD suite; SSH needs credentials
  and explicit commands. Encrypted payloads are never guessed.
