# Livewire v1.0.1 software-lab evidence

All seven required runs completed with **zero failures**, no interruption and verified cleanup. Every one of the **79 platform/suite/command/case combinations** has successful executions spanning at least two hours. The runs exercised **17,015 CLI processes and 51,045 replay iterations**, with three iterations inside each process. These are repeated-process protocol soaks; they do not claim that one CLI process stayed alive for two hours.

| Platform | Suite | Command and report | Cases | CLI processes | Replay iterations | Minimum case span (seconds) |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| windows-amd64 | application | [live](windows-live/report.json) | 16 | 3,440 | 10,320 | 7228.117 |
| windows-amd64 | application | [reproduce](windows-reproduce/report.json) | 16 | 3,440 | 10,320 | 7228.062 |
| linux-amd64 | application | [live](linux-live/report.json) | 16 | 3,360 | 10,080 | 7226.822 |
| linux-amd64 | application | [reproduce](linux-reproduce/report.json) | 16 | 3,360 | 10,080 | 7226.821 |
| linux-amd64 | packet | [live](linux-packet/live.run.json) | 7 | 1,533 | 4,599 | 7207.813 |
| linux-amd64 | packet | [reproduce](linux-packet/reproduce.run.json) | 7 | 1,533 | 4,599 | 7201.211 |
| linux-amd64 | stateless | [replay](linux-stateless/replay.run.json) | 1 | 349 | 1,047 | 7202.830 |

The [machine-readable summary](summary.json) reconciles completed reports with their hash-bound transcripts and retains exact spans and hashes. The seven reports and their deduplicated required evidence contain 64,364 files totaling 224,582,486 bytes before Git compression. These figures exclude automated-check bundles and supplemental audits. Both packet reports reference the same packet evidence directory.

The [stable manifest](../stable.json) binds this evidence to source digest `8300e2e6ea1c0a0991103e8ff7664c5afa5d677d5a9fd09da540abca0c7c5dcb`. Tested Windows and Linux amd64 binaries match the final packaged executables. Linux arm64 is reproducibly cross-built; native arm64 runtime qualification is not claimed.

| Binary | SHA256 |
| --- | --- |
| windows-amd64 | `a1e50c312d7c02cbc7001cce979b3505036fc4c7a4dd392924db215e3d4f7239` |
| linux-amd64 | `6ccae4417361d344f5ba47080106da27f8ea42a44d9518addc25df97a1ba93d1` |
| linux-arm64 | `8118bec7327e24d2e9e75ade935ec7cd886c14b0533d89ecfb0c58dc5901a1da` |

Application cases cover HTTP/1, DNS/TCP, Modbus/TCP, MQTT 3.1.1/5, DNP3, their supported TLS routes, FTP, explicit/implicit FTPS and SSH. Both `live` and `reproduce` use their public application defaults, without a mode flag. TLS soak captures use TLS 1.2 and fresh peers negotiate TLS 1.3; the opposite TLS-version direction and HTTP/1.1 ALPN have separate regression coverage.

Packet cases cover DNS/UDP, generic UDP, ICMPv4/v6, adaptive TCP, captured TCP and advanced wire injection. The datagram cases use the public defaults. The wire case independently checks 40 interleaved sessions and tied capture timestamps. Adaptive TCP runs include packet loss, delay and reordering in owned Linux virtual networks.

The separate stateless `replay` run checks a mixed-protocol fixture, including opaque TLS bytes, for exact frame bytes, order and counts against independent captures. Observation timestamps are checked against execution windows; this does not establish exact inter-packet timing fidelity. It observed 7,329 frames and explicitly retains an unverified application status. Raw injection does not establish a new TLS connection or prove application equivalence.

See the [qualification scope and repeat commands](../../docs/V1_QUALIFICATION.md) for exact combinations. Custom rule packs, IPv6 TCP/UDP, captured TLS 1.3 and active FTP handling have regression coverage rather than extra two-hour matrix combinations. TLS client-certificate authentication and HTTP/2/3 application replay are outside the supported CLI scope.

Additional evidence:

- [Windows automated checks](windows-checks/README.md) and [Linux automated checks](linux-checks/README.md): build, vet, tests, dashboard, static/security analysis, race, shuffle, fuzz, coverage, corpus, protocol faults, recovery, loader limits and published-release comparison as applicable.
- [Application final audit](final-audits/application/README.md) and [packet final audit](final-audits/packet/README.md): independent retained-file checks and owned process/listener/network cleanup observations.
- [CI records](ci/): successful checks with full commit identities.
- [Security advisory review](security-review/README.md): the required-module OpenPGP advisory and evidence that the affected packages are not imported.
- [v1.0.0 evidence](../v1.0.0/README.md): historical qualification, retained unchanged. Its prior results do not qualify the changed patch.

Application fixture captures, TLS key logs, private keys and credential files remain private. Published packet captures contain synthetic lab traffic. Excluded scratch executables and interrupted pre-freeze diagnostics are not passing qualification evidence.

This qualification covers Windows loopback peers and Linux software networking under WSL2. Physical NICs/DUTs, Windows physical Npcap faults, native Linux arm64 runtime, human-pilot usability and visual/keyboard browser QA are not qualified. Dashboard API and JavaScript state checks passed. A matched response does not prove a device crash or field fault without independent target-side evidence.

Validate this release checkout with checksum-verified artifacts present:

```sh
GOTOOLCHAIN=go1.26.7 go run ./scripts/qualify validate -version 1.0.1 -artifacts dist/v1.0.1 qualification/stable.json
```
