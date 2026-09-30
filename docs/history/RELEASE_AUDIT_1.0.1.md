# Livewire 1.0.1 release audit

The frozen Windows and Linux automated gates and all seven required two-hour
software-lab runs completed successfully. The runs cover 79 case combinations,
17,015 CLI processes and 51,045 replay iterations, with zero failures and
independently verified cleanup. Final manifest validation, final CI and
publication verification remain enforced release gates; their completion is
recorded by the linked workflows, not asserted in advance here.

The [follow-up record](V1_FOLLOWUP.md) explains the command changes, TLS fixes,
and disposition of v1.0.0. Its published tag, binaries, and historical evidence
remain unchanged. The changed patch has its own fresh qualification evidence.

## Frozen candidate

The completed gate records bind to commit
`99600ceae7c179eb758895cf6657d646ae1fe466`, Go 1.26.7, and source digest
`8300e2e6ea1c0a0991103e8ff7664c5afa5d677d5a9fd09da540abca0c7c5dcb`.
The soaks used the exact packaged Windows amd64 and Linux amd64 candidates;
final manifest validation must reconcile their hashes with the release assets.
Linux arm64 is cross-built and has no native runtime qualification.

The [v1.0.1 evidence index](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/README.md)
links source-bound Windows/Linux execution records, logs, coverage results,
corpus results, completed run reports, transcripts and artifact hashes.

## Completed automated checks

Native Windows amd64 and Linux amd64 checks passed build, vet, unit tests,
JavaScript dashboard-state checks, static and vulnerability analysis, race
tests, shuffled/repeated tests, all seven fuzz targets at 200,000 iterations
each, coverage, the maintained corpus, protocol-fault regressions, and
recovery/cleanup checks. Both completed gate records retain the frozen source
digest before and after execution. Frozen-source GitHub CI also passed for the
same full commit: [pull-request run 36627049037](https://github.com/kvmukilan/livewire/actions/runs/36627049037)
and [push run 36627037090](https://github.com/kvmukilan/livewire/actions/runs/36627037090).
These runs establish the frozen source's CI result; final release-commit CI
remains a separate gate.

| Statement coverage | Windows | Linux | Required |
|---|---:|---:|---:|
| Aggregate | 68.1% | 67.8% | 60% |
| PCAP I/O | 85.3% | 85.3% | 85% |
| Dashboard backend | 63.1% | 63.0% | 60% |
| CLI | 48.7% | 48.8% | 30% |
| Packet backend | 30.0% | 31.0% | 20% |

Loader checks at 10, 100 and 512 MiB and 1,000,000 records passed on both hosts;
513 MiB and 1,000,001-record inputs were rejected at the documented limits.
Windows comparison with checksum-verified published 0.7.0 and 0.8.0 executables
passed its gzip HTTP, selected-exchange and mixed-capture expectations.

`govulncheck` reported zero called vulnerabilities and zero vulnerabilities in
imported packages on both platforms. It also reported the required-module
advisory [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), which affects only
the unmaintained `golang.org/x/crypto/openpgp` package family. The frozen-source
Linux dependency audit found none of those packages in Livewire's dependency
closure; the module's other cryptographic and SSH packages are imported.
This is an assessed unused-package advisory, not a claim that the dependency
module has no advisories. The [security review](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/security-review/README.md)
retains the scan, dependency analysis and primary advisory evidence.

No connected browser was available. Dashboard API and JavaScript state tests
passed; visual and keyboard QA are not claimed.

## Completed soaks and publication gates

The `software-lab` profile and case boundaries are documented in
[V1_QUALIFICATION.md](V1_QUALIFICATION.md). Every required case has successful
executions spanning at least two hours. All seven final reports record zero
failures, no interruption and verified cleanup.

| Completed run | Case combinations | CLI processes | Replay iterations |
|---|---:|---:|---:|
| Windows application `live` | 16 | 3,440 | 10,320 |
| Windows application `reproduce` | 16 | 3,440 | 10,320 |
| Linux application `live` | 16 | 3,360 | 10,080 |
| Linux application `reproduce` | 16 | 3,360 | 10,080 |
| Linux packet `live` | 7 | 1,533 | 4,599 |
| Linux packet `reproduce` | 7 | 1,533 | 4,599 |
| Linux stateless `replay` | 1 | 349 | 1,047 |
| **Total** | **79** | **17,015** | **51,045** |

The [machine-readable summary](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/summary.json)
retains exact spans, counts and hashes. The independent
[application audit](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/final-audits/application/README.md)
and [packet/stateless audit](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/final-audits/packet/README.md)
retain additional checks of actual exits and task-owned resource cleanup.

The application runs exercised the public defaults without `-mode application`.
Each CLI process ran three repetitions; these matrix results do not claim that
one CLI process stayed alive for two hours. The stateless run checked independent
frame bytes, order and counts and retained an unverified application outcome.
Packet and application results carry different verification claims.

Publication requires successful validation of the completed current-source
manifest, matching tested and packaged executable hashes, final CI,
reproducible artifacts and SBOM, Windows ZIP validation, attestations, and
verification of the actual published downloads. The
[Release workflow](https://github.com/kvmukilan/livewire/actions/workflows/release.yml)
and [v1.0.1 release page](https://github.com/kvmukilan/livewire/releases/tag/v1.0.1)
provide the actual publication status. This audit records completed tests and
the enforced publication gates; it does not claim future workflow or download
checks have already succeeded.

## Qualification limits and history

Physical NICs and DUTs were unavailable. This software profile does not assert
physical-device, human-pilot, native Linux arm64, Windows physical Npcap fault,
or visual-browser qualification. The separate physical profile retains its
applicable field requirements. Windows artifacts are not Authenticode-signed.
A matched application response alone does not establish a device crash or
other field fault.

The immutable [v1.0.0 audit](https://github.com/kvmukilan/livewire/blob/v1.0.0/docs/RELEASE_AUDIT.md)
and [evidence index](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/README.md)
retain that release's completed six-run qualification, including the diagnosed
MQTT pacing failure and fresh successful runs of its correction. Its additional
[long-process HTTP checks](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/long-process-http/README.md)
remain historical evidence and do not qualify the changed v1.0.1 candidate.
For earlier results, see the
[0.9.0-rc.2 audit](https://github.com/kvmukilan/livewire/blob/v1.0.0/docs/history/RELEASE_AUDIT_0.9.0-rc.2.md).
