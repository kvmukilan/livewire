# Reliability implementation validation — 2026-09-25

Historical snapshot before the version 1 revamp. See [version 1 qualification](../docs/V1_QUALIFICATION.md) for the current scope and release evidence.

Disposition at the time: development implementation. The full requested plan is not complete
and this build is not physically qualified or declared stable. Existing checkout
changes were preserved; nothing was committed, tagged, or published.

Implementation and usage: [reliability notes](../docs/RELIABILITY_IMPLEMENTATION.md).

Source digest (qualification tool, including tests and tooling):
`9eb9cc4fd7f085f2bac8ea0ba69218cafb112fa87670b48056ae2c99887f7f4b`.

Development Windows executable:
`coverage/reliability-validation-20260925/livewire.exe`.
SHA256: `434efbcefce41a816e52ef1071c2c0a4d58afbfba0ee392a5bb9748bcd6bc5a8`.

## Passed

- Windows Go 1.27.0: `go run ./scripts/task all` completed successfully. Build,
  vet, full unit suite, dashboard tests, govulncheck, staticcheck, high-confidence
  gosec, race tests, three shuffled full-suite passes, twenty shuffled dashboard
  package passes, seven fuzz targets at 200,000 iterations each, coverage, and
  the existing maintained corpus passed.
- Coverage: aggregate 65.7% (floor 60), pcapio 85.6% (85), webui 64.1% (60),
  CLI 46.7% (30), Windows backend 32.6% (20). Aggregate coverage now instruments
  all project packages with `-coverpkg=./...`, counting runtime execution through
  adapter/TLS/CLI integration tests. Isolated package floors are unchanged.
- Linux amd64 Go 1.26.4 under Kali WSL: `go test -race ./...` passed. This is
  Linux userspace evidence, not a physical Linux NIC/device qualification.
- Release comparison against checksum-verified published 0.7.0 and 0.8.0 builds
  passed. Current gzip replay, selected preview/replay, and mixed-capture behavior
  met the existing harness expectations.
- New regressions cover live MQTT identifiers and HTTP cookies, TLS cookie
  propagation with verification on/off, explicit token bindings, HTTP body
  differences, partial following frames, reordered Modbus replies, unsolicited
  MQTT acknowledgements, HTTP informational replies, bounded workers, strict
  exits, durable resume/preview, changed targets, journal corruption, exclusive
  locks, and real process termination at operation boundaries. Recovery probes
  cannot claim captured-response equivalence or silently repeat an uncertain write.

Security scan reported zero reachable/imported-package vulnerabilities and one
unused module-level advisory. The local evidence directory is
`coverage/reliability-validation-20260925`; release comparison artifacts are in
`coverage/reliability-release-comparison-final-20260925`.

## Still open

- Automatic MQTT keepalive during long captured timing gaps and remaining
  negotiated MQTT 5 behavior; DNP3 application reassembly across changed target
  fragmentation; arbitrary response-dependent pipelining. See implementation
  notes for current conservative boundaries.
- Windows/Linux physical interfaces, real target packet/report evidence, three
  consecutive passes per required field scenario, and two-hour soaks for both
  command paths. No protocol/version/device combination was physically qualified.
- The generated `qualification-pending.json` intentionally remains unqualified.
  The existing validator rejected it for missing evidence; the blocker output is
  saved alongside the automated logs. An automated pass does not override this gate.
