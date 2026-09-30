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
These changes form the v1.0.1 patch; no different binaries will reuse v1.0.0.
The [v1.0.0 evidence index](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/README.md)
remains the historical record for that release.

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

The frozen v1.0.1 Windows and Linux automated gates have passed under Go 1.26.7,
including build, vet, tests, dashboard checks, static/vulnerability analysis,
race, shuffle, fuzz, coverage, corpus, protocol-fault and recovery/cleanup checks.
Aggregate statement coverage is 68.1% on Windows and 67.8% on Linux; all package
floors passed. [RELEASE_AUDIT.md](RELEASE_AUDIT.md) records the frozen source
identity, complete coverage table and retained gate evidence.

The scans found zero called vulnerabilities and zero vulnerabilities in imported
packages. GO-2026-5932 concerns only the unimported OpenPGP packages within the
required `golang.org/x/crypto` module; the dependency audit and advisory scope
are retained in the [security review](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/security-review/README.md).

All seven two-hour runs completed with zero failures: 79 case combinations,
17,015 CLI processes and 51,045 replay iterations. Every required case exceeded
two hours, and independent audits verified cleanup. The fresh
[v1.0.1 evidence index](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/README.md),
[application audit](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/final-audits/application/README.md)
and [packet/stateless audit](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/final-audits/packet/README.md)
retain the completed results. Historical v1.0.0 evidence was not reused to
qualify these changed binaries.

Frozen-source CI passed in [PR run 36627049037](https://github.com/kvmukilan/livewire/actions/runs/36627049037)
and [push run 36627037090](https://github.com/kvmukilan/livewire/actions/runs/36627037090).
Publication still requires final manifest validation, final release-commit CI,
matching executable hashes, reproducible artifacts, attestations, and
independent published-download verification. The
[Release workflow](https://github.com/kvmukilan/livewire/actions/workflows/release.yml)
and [v1.0.1 release page](https://github.com/kvmukilan/livewire/releases/tag/v1.0.1)
record actual publication status; these documents do not predeclare its success.

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
