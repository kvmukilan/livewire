# Livewire v1.3.0 software-lab evidence

Five completed [hosted qualification jobs](https://github.com/kvmukilan/livewire/actions/runs/39494894674) cover **43 platform/suite/command/case combinations**, **14,874 CLI processes** and **44,622 repetitions**. Each case spans at least two hours, with zero recorded failures and verified owned-resource cleanup.

| Platform | Suite / command | Cases | CLI processes | Repetitions | Minimum case span (s) | Report |
|---|---|---:|---:|---:|---:|---|
| windows-amd64 | application / `live` | 17 | 3,672 | 11,016 | 7231.676102000 | [windows-live/report.json](windows-live/report.json) |
| linux-amd64 | application / `live` | 17 | 3,723 | 11,169 | 7209.340444000 | [linux-live/report.json](linux-live/report.json) |
| linux-amd64 | packet / `live` | 7 | 5,222 | 15,666 | 7206.920567000 | [linux-packet/live.run.json](linux-packet/live.run.json) |
| linux-amd64 | stateless / `reproduce` | 1 | 1,127 | 3,381 | 7204.115316000 | [linux-stateless-reproduce/reproduce.run.json](linux-stateless-reproduce/reproduce.run.json) |
| linux-amd64 | stateless / `replay` | 1 | 1,130 | 3,390 | 7203.346696000 | [linux-stateless-replay/replay.run.json](linux-stateless-replay/replay.run.json) |

## Replay scope

`live` creates fresh stateful application sessions. `reproduce` sends the captured frames statelessly, and `replay` remains its compatibility alias. Each Windows/Linux application matrix contains 16 application comparison cases and one separately checked TLS handshake case. The handshake case sends zero application bytes and must remain application-incomplete, unverified and unmatched. Stateless and explicit wire cases establish frame transmission, not an application response match or reproduction of a device fault.

The two-hour matrices repeatedly start CLI processes, each with three repetitions; they do not claim one connection remained open for two hours. Continuity checks limit an execution to 120 seconds, suite idle gaps to 60 seconds, and case idle gaps to 300 seconds. Failed, interrupted, suspended or superseded-source runs are excluded.

## IEC 60870-5-104 and multi-session TLS

Version 1.3.0 adds the `iec104` adapter and replay of every selected TLS session in one run. These are covered by the native regression gates (dissector and adapter unit tests, a controlled plain-TCP target, a loopback TLS outstation that validates sequence numbers and varies its spontaneous data) and by operator replay of a field capture with its key log against that outstation. They are not an additional two-hour matrix case; the matrices above exercise the unchanged built-in cases on the 1.3.0 executables.

## Evidence identities

The [stable manifest](../stable.json) binds all five reports and both native check manifests. Each run includes `provenance.json`, `validation.json` and `SHA256SUMS`. Private fixtures and secrets are omitted.

- Frozen candidate: `fd0202e5d1d1ae3bc83f4fc0b850fa0b4c5b8ef9`.
- Executable source digest: `0f5645de5168c07e698244f63155755e3aff0512cff7a975a88c024833d7a4c1`.
- Release toolchain: Go 1.26.9.

- linux-amd64: `31eedb1975a7b4b35bd805578393caec3b7b484f3d5f59e12347c3f97222f90d`
- linux-arm64: `f07a801da33c4516663b5b2e6e0b405505fe26e63a645e75a1b246b60242049c`
- windows-amd64: `4b6e84229621a9968dde8cfdfbe1d18767652708f4f5678d3c5d179c178fac7d`

- `windows-live/report.json`: `83222daac87c868d501f22ddc30861543451e46c151fb99f63242a5e1d40c331`; UTC 2026-10-20T20:49:22.1996901Z to 2026-10-20T22:50:22.6523459Z.
- `linux-live/report.json`: `00af0dea91a8e012ba89384ed22301753ab0c7804b92c39712fc603e06284bb5`; UTC 2026-10-20T20:47:40.016549724Z to 2026-10-20T22:48:17.498712046Z.
- `linux-packet/live.run.json`: `e6e7c0037d028d0341b064bcaaced8b75dd9021be4c232b81551e0d384cee377`; UTC 2026-10-20T20:47:46.296367Z to 2026-10-20T22:48:03.453875Z.
- `linux-stateless-reproduce/reproduce.run.json`: `f06dd90d8b90b6917a462cd2a1dd262a77105990723733a522cc3e203ea90f44`; UTC 2026-10-20T20:47:43.112591Z to 2026-10-20T22:47:48.212293Z.
- `linux-stateless-replay/replay.run.json`: `bf85903dae3932c9ec31df84904593c6ec9835236f8b46acc548b84d9016a8ef`; UTC 2026-10-20T20:47:48.388922Z to 2026-10-20T22:47:53.009387Z.

## Native and CI checks

Native Windows and Linux gates passed build, vet, tests, dashboard, Python tests, lint/security, race, shuffle, fuzz, coverage, corpus, protocol-fault, recovery/cleanup and the loader benchmark cases; Windows also passed the published-version comparison. Bound records are in [Windows checks](windows-checks/checks.json) and [Linux checks](linux-checks/checks.json).

## Publication and history

Before publication, the final manifest must pass the Go validator against the final assets, a clean checkout must rebuild all 23 assets byte-for-byte while preserving the three frozen binary hashes, and the tag-triggered Release workflow must independently rebuild, verify the committed checksums and SBOM, and publish the assets with provenance attestations. The previous stable manifest is archived as [v1.2.0.json](../v1.2.0.json).
