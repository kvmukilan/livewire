# Livewire v1.2.0 software-lab evidence

Five completed [hosted qualification jobs](https://github.com/kvmukilan/livewire/actions/runs/36826225622) cover **43 platform/suite/command/case combinations**, **14,817 CLI processes** and **44,451 repetitions**. Each case spans at least two hours, with zero recorded failures and verified owned-resource cleanup. The summary was recomputed from the hash-bound packaged reports; its SHA-256 is `463db98099f81285d403dd34bbeefb51c3d1596361f1e8fbd24dbcfe5ba85cae`.

| Platform | Suite / command | Cases | CLI processes | Repetitions | Minimum case span (s) | Report |
|---|---|---:|---:|---:|---:|---|
| windows-amd64 | application / `live` | 17 | 3,638 | 10,914 | 7216.675281500 | [windows-live/report.json](windows-live/report.json) |
| linux-amd64 | application / `live` | 17 | 3,723 | 11,169 | 7223.174983071 | [linux-live/report.json](linux-live/report.json) |
| linux-amd64 | packet / `live` | 7 | 5,201 | 15,603 | 7200.212578000 | [linux-packet/live.run.json](linux-packet/live.run.json) |
| linux-amd64 | stateless / `reproduce` | 1 | 1,128 | 3,384 | 7203.443513000 | [linux-stateless-reproduce/reproduce.run.json](linux-stateless-reproduce/reproduce.run.json) |
| linux-amd64 | stateless / `replay` | 1 | 1,127 | 3,381 | 7203.611169000 | [linux-stateless-replay/replay.run.json](linux-stateless-replay/replay.run.json) |

The runs include 1,299 separately observed TLS handshakes and 148,830 stateless frames. Neither counter is an application-match count.

## Replay scope

`live` creates fresh stateful application sessions. `reproduce` sends the captured frames statelessly, and `replay` remains its compatibility alias. Each Windows/Linux application matrix contains 16 application comparison cases and one separately checked TLS handshake case. The handshake case sends zero application bytes and must remain application-incomplete, unverified and unmatched. Stateless and explicit wire cases establish frame transmission, not an application response match or reproduction of a device fault.

The two-hour matrices repeatedly start CLI processes, each with three repetitions; they do not claim one connection remained open for two hours. Continuity checks limit an execution to 120 seconds, suite idle gaps to 60 seconds, and case idle gaps to 300 seconds. Failed, interrupted, suspended or superseded-source runs are excluded.

Matching embedded or explicitly supplied secrets allow supported captured plaintext to run on fresh verified TLS sessions. Soak fixtures cover captured TLS 1.2 with fresh TLS 1.3; the separate recording checks cover captures under TLS 1.2 and 1.3. HTTP/2/3, TLS client-certificate authentication, arbitrary key-exporting applications, and full Modbus Security are outside this qualification. Physical NIC/DUT behavior, Windows Npcap fault injection, native Linux arm64 runtime and uncoached human pilots are not claimed. Independent device evidence is still needed to establish a field fault.

## Automatic TLS recording

The new `capture -tls -- <application>` path passed **40 short end-to-end recording checks** on Linux AF_PACKET and Windows Npcap loopback. Twenty-four cover HTTP/1, Modbus, DNS/TCP, MQTT 3.1.1, MQTT 5 and DNP3 under captured TLS 1.2 and 1.3. Sixteen more cover explicit FTPS active/passive uploads/downloads under both TLS versions, including protected control/data connections and reversed TCP initiation. Each records an independent Python TLS client, embeds matching secrets in the capture, and verifies a fresh application exchange using that PCAPNG without an external key-log file. Mixed captures use an explicit session selection. See the [recording evidence](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.2.0/tls-recording/README.md).

The client must support session-key export; this feature cannot recover an older encrypted-only PCAP that lacks matching secrets. Private CA trust or fresh credentials may still be required. Recording checks are separate from the two-hour replay matrices. Secret-bearing captures, key logs, private keys and credentials are excluded from public evidence.

## Evidence identities

The [stable manifest](../stable.json) binds all five reports and both native check manifests. Each run includes `provenance.json`, `validation.json` and `SHA256SUMS`; these 15 hosted proof files identify the candidate, reviewed workflow revision, native toolchain and independently executed transcript check. Report references bind per-attempt reports, peer transcripts and permitted synthetic packet captures. Private fixtures and secrets are omitted.

- Frozen candidate: `c5dfe7fea386414c16883d7a049a4961c89ab2e8`.
- Executable source digest: `3a1102ebe8db6e159c216ead76248995d187c35933fa20b3bfb7a67d8ed09a82`.
- Release toolchain: Go 1.26.7.

- linux-amd64: `0fbf245bced65b99009270a69a8aa7718d99b934e0cc1de1debc9b012c77cc48`
- linux-arm64: `2a08a49de98dc97c767ab95a588b0e442a16f30e95f50061bcb9d4395abaadbf`
- windows-amd64: `52f9b662e8c4607148e54c436607615efab08e93b8cce27225668646f2b62448`

- `windows-live/report.json`: `63bf7f6fb2794f730214a8265a8651757bbfca7129695685ce1b3d9f1824f662`; UTC 2026-10-01T06:44:37.8314544Z to 2026-10-01T08:45:23.3979077Z.
- `linux-live/report.json`: `77fd8a66583294ee7e7fbff0f8737d8d65a6d981be27473599ef64cae8972eb7`; UTC 2026-10-01T06:43:23.134676468Z to 2026-10-01T08:44:14.497987074Z.
- `linux-packet/live.run.json`: `a0a8208cb62b2c3d86366aad749f29e03f485235611adfa3527b6bd31af9e9a5`; UTC 2026-10-01T06:43:16.451470Z to 2026-10-01T08:43:26.025465Z.
- `linux-stateless-reproduce/reproduce.run.json`: `a1ce3addd5851a178a64d922a37defd7a688f0e8e776dfddeb53402f4a310dd3`; UTC 2026-10-01T06:43:13.589809Z to 2026-10-01T08:43:17.691489Z.
- `linux-stateless-replay/replay.run.json`: `9ae6db856345b6505e1b260a1f961fae57aaff45e3101769c48fe58bb3a5be3a`; UTC 2026-10-01T06:43:18.620582Z to 2026-10-01T08:43:23.525888Z.

## Native and CI checks

Native Windows and Linux gates passed build, vet, tests, dashboard, Python tests, lint/security, race, shuffle, fuzz, coverage, corpus, protocol-fault, recovery/cleanup and six benchmark cases. Windows also passed the published-version comparison. Each native corpus run checked 35 maintained cases. Aggregate coverage was Windows 69.4% and Linux 69.5%. Actual process exits and source identities were independently audited; the private audit SHA-256 is `b8ccd4512a7fc315cf6ab73b351904ad7d6c88828189c160564e2e8a54a02eec`. Bound public-safe records are in [Windows checks](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.2.0/windows-checks/checks.json) and [Linux checks](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.2.0/linux-checks/checks.json).

Candidate CI passed all eight jobs in both [push 36826110837](https://github.com/kvmukilan/livewire/actions/runs/36826110837) and [PR 36826114023](https://github.com/kvmukilan/livewire/actions/runs/36826114023), including the mandatory Linux native recording gate. These results do not substitute for CI on the final evidence/docs commit. Dashboard automated tests were rerun; no new manual dashboard visual test is claimed. Website publication and browser verification are separate from replay qualification.

## Publication and history

Before publication, the final manifest must pass the official Go validator against the final assets. A fresh clean checkout must rebuild all 23 assets byte-for-byte, including exactly 19 flat Windows ZIP members, while preserving the three frozen binary hashes. The final evidence/docs commit must pass its own CI before merge and tag. The tag-triggered [Release workflow](https://github.com/kvmukilan/livewire/actions/workflows/release.yml) must independently rebuild with `release.ps1`, verify the committed checksums and SBOM, and publish the assets and provenance attestations. Downloaded assets and all six attested subjects must then be verified against the tagged commit.

These are required publication gates, not a claim in this prepublication record that later steps have already completed. See the [v1.2.0 release](https://github.com/kvmukilan/livewire/releases/tag/v1.2.0) and its workflow for publication status. Existing release tags, assets and evidence remain unchanged; the previous stable manifest is archived as [v1.1.0.json](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.1.0.json).
