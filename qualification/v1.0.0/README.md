# Livewire v1.0.0 software-lab evidence

All six required runs completed with **zero failures**, no interruption, and verified cleanup. Every one of the **78 platform/suite/command/case combinations** has successful executions spanning more than two hours. The runs exercised **16,600 CLI processes and 49,800 replay iterations**, using three iterations inside each process. These are repeated-process protocol soaks; they do not claim that a single CLI process stayed alive for two hours.

| Platform | Suite | Command and report | Cases | CLI processes | Replay iterations | Minimum case span (seconds) |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| windows-amd64 | application | [live](windows-live/report.json) | 16 | 3,440 | 10,320 | 7227.206 |
| windows-amd64 | application | [reproduce](windows-reproduce/report.json) | 16 | 3,440 | 10,320 | 7227.225 |
| linux-amd64 | application | [live](linux-live/report.json) | 16 | 3,376 | 10,128 | 7229.365 |
| linux-amd64 | application | [reproduce](linux-reproduce/report.json) | 16 | 3,376 | 10,128 | 7229.437 |
| linux-amd64 | packet | [live](linux-packet/live.run.json) | 7 | 1,484 | 4,452 | 7225.549 |
| linux-amd64 | packet | [reproduce](linux-packet/reproduce.run.json) | 7 | 1,484 | 4,452 | 7223.395 |

The [machine-readable summary](summary.json) retains exact spans and report hashes. The six reports and their deduplicated required evidence contain 62,132 files totaling 163,052,018 bytes before Git compression. These figures exclude automated-check bundles, diagnostics, and additional audits. Both packet reports reference the same packet evidence directory.

The [stable manifest](../stable.json) binds the evidence to executable source digest `f01dd0fd79190f0e3754fdc535fe187a75ade0341e482eb24d8fa1809c7f7122` and these tested binaries:

| Binary | SHA256 |
| --- | --- |
| Windows amd64 | `cd49568186a36f26f4a48d9fd12568bbd9d6ee62a745d116d8b1291f4b19ba91` |
| Linux amd64 | `640faff8b4c37474cc92f87b52e6a519cc08ea4040abfda32d12f0bbe4c8f7b3` |

Application cases cover HTTP/1, DNS/TCP, Modbus/TCP, MQTT 3.1.1/5, DNP3, their supported TLS routes, FTP, explicit/implicit FTPS, and SSH. Packet cases cover DNS/UDP, generic UDP, ICMPv4/v6, adaptive TCP, captured TCP, and wire injection. The [scope and repeat-test commands](../../docs/V1_QUALIFICATION.md) describe the exact combinations, independent peer checks, and Linux packet loss/delay/reordering setup. Captured transport and wire observations retain their distinct verification limits; a received packet is not a verified application exchange or proof of a device crash.

Additional evidence:

- [Windows automated checks](windows-checks/README.md) and [Linux automated checks](linux-checks/README.md): build, static/security analysis, tests, race, shuffle, fuzz, coverage, corpus, loader limits, and published-release comparison as applicable.
- [Application final audit](final-audits/application/README.md) and [packet final audit](final-audits/packet/README.md): independent retained-file checks and post-run process/listener/network cleanup observations. Unrelated host inventories are omitted with explicit provenance.
- [Long-process HTTP checks](long-process-http/README.md): four additional single-process runs of about 70 minutes, each with 4,200 fresh connections and 8,400 independently validated requests and compared responses. Resource observations are not a general memory-leak guarantee.
- [Excluded MQTT/TLS pacing diagnostic](diagnostics/mqtt-pacing-round33/README.md): the actual failure on an earlier binary, its absolute-deadline correction, and before/after probes. That failed run is not part of successful qualification.
- [CI records](ci/): successful source checks, with commit identities retained so earlier runs remain distinguishable.

The application bundle excludes fixture captures, TLS key logs, private keys, and credential material. Packet captures are synthetic traffic from the owned virtual-network lab. The audit sources document historical private paths and inputs; repeat the public lab harnesses to generate new evidence.

Qualification covers Windows loopback peers and Linux software networking under WSL2. Physical NICs/DUTs, Windows physical Npcap driver behavior, native Linux arm64 runtime, human-pilot usability, and visual/keyboard browser QA are not qualified. Dashboard API and JavaScript state tests passed; Linux arm64 is cross-built. The separate physical qualification profile remains available.

Validate a release checkout with the checksum-verified artifacts present:

```sh
go run ./scripts/qualify validate -version 1.0.0 -artifacts dist/v1.0.0 qualification/stable.json
```
