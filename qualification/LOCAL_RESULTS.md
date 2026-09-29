# Local implementation verification - 2026-09-09

Disposition: development build 0.9.0-dev; external qualification remains open.
No release or tag was published by this implementation work.

The CLI executable in the workspace is the packaged development executable.
Source fingerprint (code, tests, tooling, and corpus, normalized to LF):
`d81af55e29b732afc088a56196956de3359ea4687a1818c383984fb5ce82e842`.

## Verified

- Windows: complete Go 1.26.7 and Go 1.27.0 test suites; vet and module verification.
- Complete Windows race suite, followed by shuffled race tests three times for
  the changed CLI, FTP, SSH, lifecycle, secure outcome, and iteration packages.
- Linux amd64 userspace under Kali WSL2: complete Go 1.26.7 tests, complete race
  suite, and vet. The initial Linux race run exposed missing synchronization
  in the new CLI replacement fixture; after fixing its readiness handoff, the
  CLI race suite passed three times and the complete Linux race suite passed.
  The corrected fixture also passed three Windows race runs.
- Python qualification tests: 11 passed on Windows and Linux. Dashboard shipped
  JavaScript state tests: 5 passed. The 16-case regression corpus passed.
- Coverage: 60.9% aggregate (floor 60), CLI 39.9% (30), pcapio 85.3% (85),
  webui 62.5% (60), Windows backend 30.0% (20).
- govulncheck: zero reachable or imported-package vulnerabilities; one unused
  module-level advisory remains. staticcheck, actionlint, and gosec high/high
  passed. The bounded CLI snapshot loader has a documented G703 suppression:
  the operator chooses a local file and the CLI has no rooted directory boundary.
- Same valid gzip exchange: published 0.7 sends one request; published 0.8
  blocks without sending; the development executable sends and compares it.
  Selected mixed-capture replay succeeds and retains excluded-packet accounting.
- Linux amd64, Linux arm64, and Windows amd64 packages built with Go 1.26.7.
  Two fresh Windows build directories produce the same 17 checksummed assets.
  A native Linux build also matches the Windows-produced Linux amd64 binary
  byte-for-byte using the pinned release flags and toolchain.
  The Windows ZIP checksum, contents, version, doctor JSON, missing-interface
  and missing-output-directory blockers, and help exit behavior passed.
- The packaged Linux executable runs under WSL and doctor correctly identifies
  missing packet capabilities/firewall tools as warnings for general inspection.
- The builder refuses the existing rc.2 directory and preserves its manifest.
  An incomplete qualification manifest is rejected; validator tests also cover
  stale source, mismatched artifacts, tampered evidence, slow cancellation,
  failed cleanup, insufficient soaks, and pilot thresholds.
- Recorder and short soak-harness smoke tests passed. These are harness tests,
  not two-hour replay soaks or DUT qualification.

## Size and memory measurements

Each fixture is generated into a temporary capture and processed in an isolated
worker. Times include capture loading and intent planning, not live replay.
Peak RSS is the observed OS high-water mark sampled at 10ms; runtime/heap details
and host metadata are retained in the metrics JSON. WSL results are not physical
NIC measurements or a throughput guarantee. Some checks ran concurrently;
these timings are observations, not a controlled performance comparison.

| Host | Case | Load seconds | Plan seconds | Observed peak RSS MiB | Result |
|---|---|---:|---:|---:|---|
| Windows | 10MiB | 0.010 | 0.015 | 39.6 | Pass |
| Windows | 100MiB | 0.099 | 0.096 | 295.2 | Pass |
| Windows | 512MiB | 0.453 | 0.582 | 1537.0 | Pass |
| Windows | 513MiB-limit | 0.460 | 0.000 | 586.9 | Pass |
| Windows | 1000000-records | 0.164 | 0.544 | 817.4 | Pass |
| Windows | 1000001-records-limit | 0.163 | 0.000 | 181.5 | Pass |
| Linux WSL | 10MiB | 0.015 | 0.022 | 36.7 | Pass |
| Linux WSL | 100MiB | 0.102 | 0.171 | 293.1 | Pass |
| Linux WSL | 512MiB | 0.748 | 1.837 | 1525.6 | Pass |
| Linux WSL | 513MiB-limit | 0.538 | 0.000 | 584.5 | Pass |
| Linux WSL | 1000000-records | 0.260 | 1.609 | 851.5 | Pass |
| Linux WSL | 1000001-records-limit | 0.249 | 0.000 | 178.9 | Pass |

Limits refer to decoded packet bytes, not RAM. Both over-limit cases were
rejected with pcapio limit errors. A 512 MiB capture can require about 1.6 GB RAM;
protocol, session count, reassembly, and adapter complexity can increase this.

## Evidence locations

Local, uncommitted evidence is under coverage/: production-final-tests.txt,
production-go127-tests.txt, production-final-race.txt, production-linux-final.txt,
production-linux-race-cli.txt, production-final-corpus/, production-final-comparison/,
production-final-vulncheck.txt, production-final-gosec.json,
production-verified-benchmark/, production-linux-benchmark/,
production-final-package/v0.9.0-dev/, and production-final-repro/v0.9.0-dev/.

The Windows executable SHA-256 is
`2125cb85895bdb3eb9ffac5c70b04f492547682f300e5d7f1cf8533dff20fb21`.
The Linux amd64 executable SHA-256 is
`9b3e68c38a20f640c8ae2313188e000fe0851783163a3fa4eaea2d3fa241fda9`.

## Still required before stable promotion

- Controlled physical Windows/Linux NIC tests and a two-interface DUT run,
  three consecutive passes per scenario, with exact host/driver/NIC/firmware.
- Two-hour replay soaks on each qualified platform and verified host cleanup.
- Real browser visual/keyboard QA; browser discovery returned no connection.
- Five-engineer, five-task uncoached pilot with the agreed completion/time targets.
- Native arm64 execution and Windows signing remain disclosed limitations.
- New external CI/publication/attestation checks have not been run for these
  uncommitted changes. Existing release gates remain and the stable gate is added.

The lab target/interface/host details and pilot observations have not been
provided. WSL, synthetic captures, mocks, and loopback servers do not replace
those field results. Follow PRODUCTION.md and the qualification tooling.
