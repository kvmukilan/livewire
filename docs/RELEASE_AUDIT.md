# Livewire v1.3.0 release audit

Qualification record prepared 2026-10-21 for candidate `fd0202e5d1d1ae3bc83f4fc0b850fa0b4c5b8ef9` and executable source digest `0f5645de5168c07e698244f63155755e3aff0512cff7a975a88c024833d7a4c1`.

Five completed [hosted qualification jobs](https://github.com/kvmukilan/livewire/actions/runs/39494894674) cover **43 platform/suite/command/case combinations**, **14,874 CLI processes** and **44,622 repetitions**. Each case spans at least two hours, with zero recorded failures and verified owned-resource cleanup.

The [complete evidence index](https://github.com/kvmukilan/livewire/blob/v1.3.0/qualification/v1.3.0/README.md) contains exact times, case spans, counters and binary/report hashes.

## IEC 60870-5-104 and multi-session TLS replay

Version 1.3.0 adds the `iec104` adapter for IEC 60870-5-104 controlling-station sessions, plain or inside TLS (IEC 62351-3), and lets one `live` run execute every selected TLS session of a capture in capture order. These paths are covered by the native regression gates on both platforms: dissector and adapter unit tests, a controlled plain-TCP target, a loopback TLS outstation that validates send/receive sequence numbers and sends a different number of spontaneous bursts than the capture, multi-session aggregation, route detection and port selection. They were also exercised by operator replay of a field Achilles capture with its key log against that outstation, where four application sessions were compared, three handshake-only probes ran as fresh handshakes and ten alert-only sessions were reported as skipped.

These checks are regression and loopback evidence. The two-hour matrices exercise the unchanged built-in cases on the 1.3.0 executables; no additional two-hour IEC 104 matrix case is claimed, and no physical IEC 104 outstation was qualified.

## Replay and verification boundary

`live` creates fresh stateful application sessions. `reproduce` sends the captured frames statelessly, and `replay` remains its compatibility alias. Each Windows/Linux application matrix contains 16 application comparison cases and one separately checked TLS handshake case. The handshake case sends zero application bytes and must remain application-incomplete, unverified and unmatched. Stateless and explicit wire cases establish frame transmission, not an application response match or reproduction of a device fault.

The two-hour matrices repeatedly start CLI processes, each with three repetitions; they do not claim one connection remained open for two hours. Continuity checks limit an execution to 120 seconds, suite idle gaps to 60 seconds, and case idle gaps to 300 seconds. Failed, interrupted, suspended or superseded-source runs are excluded.

Matching embedded or explicitly supplied secrets allow supported captured plaintext to run on fresh verified TLS sessions. A capture with several TLS sessions to one server replays them in capture order, matching each session's secrets by its own client random; sessions without a server handshake run as a fresh handshake only, and sessions that cannot be prepared are reported as skipped. HTTP/2/3, TLS client-certificate authentication, arbitrary key-exporting applications, and full Modbus Security are outside this qualification. Physical NIC/DUT behavior, Windows Npcap fault injection, native Linux arm64 runtime and uncoached human pilots are not claimed. Independent device evidence is still needed to establish a field fault.

## Native and CI checks

Native Windows and Linux gates passed build, vet, tests, dashboard, Python tests, lint/security, race, shuffle, fuzz, coverage, corpus, protocol-fault, recovery/cleanup and the loader benchmark cases. Windows also passed the published-version comparison. Each native corpus run checked 35 maintained cases. Aggregate coverage was Windows 69.7% and Linux 69.8%. Bound public-safe records are in [Windows checks](https://github.com/kvmukilan/livewire/blob/v1.3.0/qualification/v1.3.0/windows-checks/checks.json) and [Linux checks](https://github.com/kvmukilan/livewire/blob/v1.3.0/qualification/v1.3.0/linux-checks/checks.json). The Linux checks ran on a native Linux kernel under WSL2 with the same Go 1.26.10 toolchain.

Release candidates 1.3.0-rc.1 and 1.3.0-rc.2 were published from the same adapter and routing source and passed the tag-triggered release workflow, including its compatibility, security, race, fuzz and coverage gates. These results do not substitute for CI on the final evidence/docs commit. Dashboard automated tests were rerun; no new manual dashboard visual test is claimed. Website publication and browser verification are separate from replay qualification.

## Publication gates

Before publication, the final manifest must pass the official Go validator against the final assets. A fresh clean checkout must rebuild all 23 assets byte-for-byte, including exactly 19 flat Windows ZIP members, while preserving the three frozen binary hashes. The final evidence/docs commit must pass its own CI before merge and tag. The tag-triggered [Release workflow](https://github.com/kvmukilan/livewire/actions/workflows/release.yml) must independently rebuild with `release.ps1`, verify the committed checksums and SBOM, and publish the assets and provenance attestations. Downloaded assets and all six attested subjects must then be verified against the tagged commit.

These are required publication gates, not a claim in this prepublication record that later steps have already completed. See the [v1.3.0 release](https://github.com/kvmukilan/livewire/releases/tag/v1.3.0) and its workflow for publication status. Existing release tags, assets and evidence remain unchanged; the previous stable manifest is archived as [v1.2.0.json](https://github.com/kvmukilan/livewire/blob/v1.3.0/qualification/v1.2.0.json).
