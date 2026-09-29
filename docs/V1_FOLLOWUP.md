# Version 1 follow-up

## Release disposition

v1.0.0 was published on 2026-09-29 after its source-bound software qualification
and publication checks completed. Later requests to simplify the command front
door and revisit TLS compatibility remained outstanding when usage was exhausted.
The published release, tag, artifacts, and historical evidence remain unchanged.

The follow-up audit found patch-level improvements, not evidence invalidating
the completed v1.0.0 qualification. TLS replay already recovered captured
plaintext and opened fresh verified sessions. Its software labs exercised the
supported secure protocols. The audit did find an HTTP/1 TLS interoperability
gap with peers requiring ALPN, validation/reporting gaps in stateless replay,
and cross-session ordering in the advanced wire route.
These are being qualified as v1.0.1; no different binaries will reuse v1.0.0.

## Command contract

- `live <capture>` plays supported application exchanges through fresh live
  connections. OS TCP maintains connection state, and adapters maintain supported
  application state from live responses.
- `reproduce <capture>` retains the guided application reproduction workflow and
  shares the fresh-session default. Neither command requires `-mode`.
- `replay -in <capture> -i <interface>` retains stateless packet injection:
  captured bytes, both recorded directions, record order, and selected pacing.
  It cannot establish a valid new TLS session or verify application equivalence.
- Advanced explicit mode/profile flags remain compatible. Scripts needing the
  former automatic packet-TCP selection can use `-mode auto`. Resuming a v1.0.0
  run also requires its original intent and matching configuration.
- `live -in` with explicit secure inputs such as `-keylog` uses the fresh-session
  route too. Mixing secure inputs and legacy-only controls fails before sending.
  Without secure inputs, historical `live -in` keeps its TCP simulation/packet
  controls and dry-run default. Previously valid dry-run commands stay dry runs.

## Follow-up changes and release gates

The patch adds the simplified defaults/help, HTTP/1.1 ALPN on fresh TLS sessions,
TLS cross-version/identity/no-send regression tests, checked stateless pacing,
pre-send link-type validation, accurate partial-send accounting, and global
capture order for advanced wire replay. The secure `live -in` form is covered
alongside the positional commands without changing historical dry-run behavior.
Dashboard evidence publication failures now invalidate completion and matching
claims while retaining observed counts and private partial evidence.

Application soaks now invoke the public defaults, without `-mode application`.
DNS/UDP, generic UDP and ICMP packet cases also exercise defaults; explicit TCP
transport/wire compatibility cases remain. A seventh required two-hour run
checks the separate stateless `replay` command against an independent capture,
comparing mixed-protocol frame bytes, order, count and unverified report status.
The advanced wire fixture also checks 40 interleaved sessions and tied timestamps.

The changed binaries require fresh Windows/Linux checks and complete two-hour
case spans. Historical v1.0.0 results cannot qualify v1.0.1. Publication remains
gated by the current manifest, matching executable hashes, CI, reproducible
artifacts, attestations, and independent published-download verification.

## TLS inputs and limits

Matching capture key material is required to recover encrypted requests. New
handshake keys do not decrypt a previous session. TLS identity verification is
enabled by default; private CAs and an explicit server name are supported.
HTTP/1 replay negotiates only `http/1.1`; HTTP/2, HTTP/3 and TLS client-certificate
authentication are outside the current CLI's supported application scope.
SSH uses explicit commands and credentials with a pinned host key.

Physical NIC/device, native Linux arm64 runtime, Windows physical Npcap faults,
uncoached operator and visual-browser qualification remain separate from the
software-lab release evidence. A matched response does not prove a device crash
or other field fault without independent target-side evidence.
