# Livewire v1.2.0 release audit

Qualification record prepared 2026-10-01 for candidate `c5dfe7fea386414c16883d7a049a4961c89ab2e8` and executable source digest `3a1102ebe8db6e159c216ead76248995d187c35933fa20b3bfb7a67d8ed09a82`.

Five completed [hosted qualification jobs](https://github.com/kvmukilan/livewire/actions/runs/36826225622) cover **43 platform/suite/command/case combinations**, **14,817 CLI processes** and **44,451 repetitions**. Each case spans at least two hours, with zero recorded failures and verified owned-resource cleanup. The summary was recomputed from the hash-bound packaged reports; its SHA-256 is `463db98099f81285d403dd34bbeefb51c3d1596361f1e8fbd24dbcfe5ba85cae`.

The [complete evidence index](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.2.0/README.md) contains exact times, case spans, counters and binary/report hashes.

## Automatic TLS recording

The new `capture -tls -- <application>` path passed **40 short end-to-end recording checks** on Linux AF_PACKET and Windows Npcap loopback. Twenty-four cover HTTP/1, Modbus, DNS/TCP, MQTT 3.1.1, MQTT 5 and DNP3 under captured TLS 1.2 and 1.3. Sixteen more cover explicit FTPS active/passive uploads/downloads under both TLS versions, including protected control/data connections and reversed TCP initiation. Each records an independent Python TLS client, embeds matching secrets in the capture, and verifies a fresh application exchange using that PCAPNG without an external key-log file. Mixed captures use an explicit session selection. See the [recording evidence](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.2.0/tls-recording/README.md).

The client must support session-key export; this feature cannot recover an older encrypted-only PCAP that lacks matching secrets. Private CA trust or fresh credentials may still be required. Recording checks are separate from the two-hour replay matrices. Secret-bearing captures, key logs, private keys and credentials are excluded from public evidence.

## Replay and verification boundary

`live` creates fresh stateful application sessions. `reproduce` sends the captured frames statelessly, and `replay` remains its compatibility alias. Each Windows/Linux application matrix contains 16 application comparison cases and one separately checked TLS handshake case. The handshake case sends zero application bytes and must remain application-incomplete, unverified and unmatched. Stateless and explicit wire cases establish frame transmission, not an application response match or reproduction of a device fault.

The two-hour matrices repeatedly start CLI processes, each with three repetitions; they do not claim one connection remained open for two hours. Continuity checks limit an execution to 120 seconds, suite idle gaps to 60 seconds, and case idle gaps to 300 seconds. Failed, interrupted, suspended or superseded-source runs are excluded.

Matching embedded or explicitly supplied secrets allow supported captured plaintext to run on fresh verified TLS sessions. Soak fixtures cover captured TLS 1.2 with fresh TLS 1.3; the separate recording checks cover captures under TLS 1.2 and 1.3. HTTP/2/3, TLS client-certificate authentication, arbitrary key-exporting applications, and full Modbus Security are outside this qualification. Physical NIC/DUT behavior, Windows Npcap fault injection, native Linux arm64 runtime and uncoached human pilots are not claimed. Independent device evidence is still needed to establish a field fault.

## Native and CI checks

Native Windows and Linux gates passed build, vet, tests, dashboard, Python tests, lint/security, race, shuffle, fuzz, coverage, corpus, protocol-fault, recovery/cleanup and six benchmark cases. Windows also passed the published-version comparison. Each native corpus run checked 35 maintained cases. Aggregate coverage was Windows 69.4% and Linux 69.5%. Actual process exits and source identities were independently audited; the private audit SHA-256 is `b8ccd4512a7fc315cf6ab73b351904ad7d6c88828189c160564e2e8a54a02eec`. Bound public-safe records are in [Windows checks](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.2.0/windows-checks/checks.json) and [Linux checks](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.2.0/linux-checks/checks.json).

Candidate CI passed all eight jobs in both [push 36826110837](https://github.com/kvmukilan/livewire/actions/runs/36826110837) and [PR 36826114023](https://github.com/kvmukilan/livewire/actions/runs/36826114023), including the mandatory Linux native recording gate. These results do not substitute for CI on the final evidence/docs commit. Dashboard automated tests were rerun; no new manual dashboard visual test is claimed. Website publication and browser verification are separate from replay qualification.

## Publication gates

Before publication, the final manifest must pass the official Go validator against the final assets. A fresh clean checkout must rebuild all 23 assets byte-for-byte, including exactly 19 flat Windows ZIP members, while preserving the three frozen binary hashes. The final evidence/docs commit must pass its own CI before merge and tag. The tag-triggered [Release workflow](https://github.com/kvmukilan/livewire/actions/workflows/release.yml) must independently rebuild with `release.ps1`, verify the committed checksums and SBOM, and publish the assets and provenance attestations. Downloaded assets and all six attested subjects must then be verified against the tagged commit.

These are required publication gates, not a claim in this prepublication record that later steps have already completed. See the [v1.2.0 release](https://github.com/kvmukilan/livewire/releases/tag/v1.2.0) and its workflow for publication status. Existing release tags, assets and evidence remain unchanged; the previous stable manifest is archived as [v1.1.0.json](https://github.com/kvmukilan/livewire/blob/v1.2.0/qualification/v1.1.0.json).
