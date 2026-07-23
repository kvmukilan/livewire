# Changelog

All notable changes to Livewire are documented here.

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
