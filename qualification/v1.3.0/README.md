# Livewire v1.3.0 software-lab evidence

Five completed [hosted qualification jobs](https://github.com/kvmukilan/livewire/actions/runs/39543811481) cover **43 platform/suite/command/case combinations**, **14,837 CLI processes** and **44,511 repetitions**. Each case spans at least two hours, with zero recorded failures and verified owned-resource cleanup.

| Platform | Suite / command | Cases | CLI processes | Repetitions | Minimum case span (s) | Report |
|---|---|---:|---:|---:|---:|---|
| windows-amd64 | application / `live` | 17 | 3,638 | 10,914 | 7211.863250000 | [windows-live/report.json](windows-live/report.json) |
| linux-amd64 | application / `live` | 17 | 3,723 | 11,169 | 7222.514233000 | [linux-live/report.json](linux-live/report.json) |
| linux-amd64 | packet / `live` | 7 | 5,215 | 15,645 | 7201.721614000 | [linux-packet/live.run.json](linux-packet/live.run.json) |
| linux-amd64 | stateless / `reproduce` | 1 | 1,131 | 3,393 | 7203.289366000 | [linux-stateless-reproduce/reproduce.run.json](linux-stateless-reproduce/reproduce.run.json) |
| linux-amd64 | stateless / `replay` | 1 | 1,130 | 3,390 | 7202.269709000 | [linux-stateless-replay/replay.run.json](linux-stateless-replay/replay.run.json) |

## Replay scope

`live` creates fresh stateful application sessions. `reproduce` sends the captured frames statelessly, and `replay` remains its compatibility alias. Each Windows/Linux application matrix contains 16 application comparison cases and one separately checked TLS handshake case. The handshake case sends zero application bytes and must remain application-incomplete, unverified and unmatched. Stateless and explicit wire cases establish frame transmission, not an application response match or reproduction of a device fault.

The two-hour matrices repeatedly start CLI processes, each with three repetitions; they do not claim one connection remained open for two hours. Continuity checks limit an execution to 120 seconds, suite idle gaps to 60 seconds, and case idle gaps to 300 seconds. Failed, interrupted, suspended or superseded-source runs are excluded.

## IEC 60870-5-104 and multi-session TLS

Version 1.3.0 adds the `iec104` adapter and replay of every selected TLS session in one run. These are covered by the native regression gates (dissector and adapter unit tests, a controlled plain-TCP target, a loopback TLS outstation that validates sequence numbers and varies its spontaneous data) and by operator replay of a field capture with its key log against that outstation. They are not an additional two-hour matrix case; the matrices above exercise the unchanged built-in cases on the 1.3.0 executables.

## Evidence identities

The [stable manifest](../stable.json) binds all five reports and both native check manifests. Each run includes `provenance.json`, `validation.json` and `SHA256SUMS`. Private fixtures and secrets are omitted.

- Frozen candidate: `1694e5a5110386f73fb5592d6d46d6ebe9ac55f5`.
- Executable source digest: `a5b66f960b3194308d71ed509a2965410ba915b97ff5e3d305a369cf78b2d718`.
- Release toolchain: Go 1.26.10.

- linux-amd64: `3e8b51e6b2c96b12a99e437b92346f5eb4819e388f25c34e37b5b2e08d4f6d9e`
- linux-arm64: `e2d46a1106e661fee7e4f8682197e4d099f8773ffc2f16fa4e3ea350862db3cd`
- windows-amd64: `82be21d8d8940a4f3321c7874621a85a21b4313bb3032cf4ef2c9b3c722df6b1`

- `windows-live/report.json`: `92e072dd7b5ed98ccf1ff9fe692953db479172d4100ebf0e725732d5b64e9b52`; UTC 2026-10-21T04:26:12.1463998Z to 2026-10-21T06:26:53.7819482Z.
- `linux-live/report.json`: `5610c44be4ec3542053090ad52b4181311957d47a407117ba3e8b54d8500ba22`; UTC 2026-10-21T04:24:46.754810725Z to 2026-10-21T06:25:37.404290078Z.
- `linux-packet/live.run.json`: `83c7b92bdb71ea53432ef3a41f21c9910f038e95d24c423dcf810161415a0043`; UTC 2026-10-21T04:24:37.861343Z to 2026-10-21T06:24:49.274393Z.
- `linux-stateless-reproduce/reproduce.run.json`: `f50b347c61bf39fb8ed5d0db8bc376c7a513ee7cf599192b64a2cd3385a3a906`; UTC 2026-10-21T04:24:38.249128Z to 2026-10-21T06:24:42.164900Z.
- `linux-stateless-replay/replay.run.json`: `fd39d2f3c2b437c332edeb8ce965733a9b761faf6d2c2c219b5db7f26e1c8089`; UTC 2026-10-21T04:24:47.986864Z to 2026-10-21T06:24:51.066839Z.

## Native and CI checks

Native Windows and Linux gates passed build, vet, tests, dashboard, Python tests, lint/security, race, shuffle, fuzz, coverage, corpus, protocol-fault, recovery/cleanup and the loader benchmark cases; Windows also passed the published-version comparison. Bound records are in [Windows checks](windows-checks/checks.json) and [Linux checks](linux-checks/checks.json).

## Publication and history

Before publication, the final manifest must pass the Go validator against the final assets, a clean checkout must rebuild all 23 assets byte-for-byte while preserving the three frozen binary hashes, and the tag-triggered Release workflow must independently rebuild, verify the committed checksums and SBOM, and publish the assets with provenance attestations. The previous stable manifest is archived as [v1.2.0.json](../v1.2.0.json).
