# Livewire 1.0.0 release audit

Version 1 addresses stateful PCAP replay and makes observed outcomes explicit.
Application replay creates fresh TCP/TLS connections, learns supported live
protocol state, and compares checked responses. Captured transport and wire
replay retain their distinct fidelity and verification limits.

## Qualification scope

The release uses the `software-lab` profile documented in
[V1_QUALIFICATION.md](V1_QUALIFICATION.md). It requires two-hour runs for every
supported application case on Windows and Linux, and every packet case on
Linux, through both `live` and `reproduce`. Independent peers and packet captures
check actual CLI executions; the release gate reconciles run summaries with
hashed execution transcripts and retained artifacts. Tested executable hashes
must match the packaged binaries and all records bind to the release source.

Physical NICs and DUTs were unavailable. The software profile does not assert
physical, human-pilot, native Linux arm64, or visual-browser qualification.
The separate physical profile retains those applicable field requirements.

## Repairs and regression evidence

- The packet TCP sender tracks outstanding sequence ranges, cumulative ACKs,
  live MSS and windows, bounded retries/probes, and FIN completion. The receiver
  handles out-of-order data, duplicate overlaps, sequence wrap and queued FIN.
- Application and TLS replay keep reading during captured pauses. MQTT 3.1.1/5
  maintains keepalives, separate identifier namespaces, aliases and negotiated
  limits. DNP3 handles changed transport/application fragmentation and live
  confirmations; unsupported authentication and object layouts stop safely.
- An initial Linux TLS MQTT soak exposed a pacing deadline race. The reader now
  preserves absolute deadlines and distinguishes pacing expiry from maintenance
  failures. The failed run and before/after probes remain diagnostic evidence;
  successful release qualification requires fresh runs of the corrected binary.
- FTP data protection follows accepted replies per transfer. Active captures
  preserve TLS roles. Refused control/data protection stops before credentials
  or uploads; encrypted capture data is decrypted before fresh retermination.
- Response faults have a separate explicit expectation and outcome. Setup,
  cancellation, journal, and cleanup failures cannot masquerade as a reproduced
  reset or timeout. Resume never restores a socket or credentials.
- Linux neighbor discovery retries within a fixed budget and respects the
  selected interface. Independent virtual-network tests exercise loss, delay,
  reordering, UDP, ICMP, stateful/captured TCP, and wire replay.

## Automated checks

Native Windows and Linux Go 1.26.7 checks passed build, vet, unit tests,
JavaScript dashboard-state checks, vulnerability/static analysis, race tests,
shuffled/repeated tests, seven fuzz targets at 200,000 iterations each, coverage,
and the maintained corpus. Source-bound logs, execution records and corpus
evidence are retained in `qualification/v1.0.0/windows-checks` and
`qualification/v1.0.0/linux-checks`. Their indexes distinguish completed checks
from excluded diagnostics and earlier runs.

| Statement coverage | Windows | Linux | Required |
|---|---:|---:|---:|
| Aggregate | 67.1% | 66.8% | 60% |
| PCAP I/O | 85.3% | 85.3% | 85% |
| Dashboard backend | 62.6% | 62.6% | 60% |
| CLI | 46.7% | 46.8% | 30% |
| Packet backend | 30.0% | 31.0% | 20% |

Loader checks at 10, 100 and 512 MiB and 1,000,000 records passed on both hosts;
513 MiB and 1,000,001-record inputs were rejected at the documented limits.
Comparison with checksum-verified published 0.7.0 and 0.8.0 executables passed
its gzip HTTP, selected-exchange and mixed-capture expectations.

Four additional HTTP checks kept one CLI process running for about 70 minutes
each: both commands on Windows and Linux. Each completed 840 attempts containing
five fresh sessions, with 8,400 independently validated and compared responses,
zero rejected exchanges, and verified process/listener cleanup. The retained
[results and reproduction instructions](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/long-process-http/README.md)
include exact durations and resource observations; they do not establish a
general memory-leak bound or replace the required two-hour protocol matrices.

No connected browser was available. Dashboard API and JavaScript state tests
passed; visual and keyboard QA are not claimed.

## Publication gates

All six required two-hour matrices completed with zero failures and verified
cleanup: 78 case combinations, 16,600 CLI processes, and 49,800 replay iterations.
The completed `qualification/stable.json` manifest and
[evidence index](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/README.md)
retain exact source/binary hashes, case spans, and independent cleanup audits.
Publication requires manifest validation and successful CI on the final source.
The release workflow tests
Go 1.26.7 and 1.27.x, rebuilds all three targets with Go 1.26.7, proves byte-identical
checksums and SBOM, validates the Windows ZIP, attests assets, and verifies
published downloads. Its actual completed status is the publication evidence.

Windows artifacts are not Authenticode-signed. Linux arm64 is cross-built.
For historical comparisons, see the
[0.9.0-rc.2 audit](https://github.com/kvmukilan/livewire/blob/v1.0.0/docs/history/RELEASE_AUDIT_0.9.0-rc.2.md).
