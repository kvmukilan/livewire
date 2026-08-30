# Livewire v0.8.0 Release Audit

Audit date: 2026-08-31

Disposition: **local release gates passed; GitHub branch and tag workflows are
mandatory publication gates.** Physical NIC/device replay, a physical
two-interface DUT, native Linux arm64 execution, and Authenticode publisher trust
are explicit unverified boundaries and are not presented as completed validation.

## Implemented release scope

| Area | Evidence |
|---|---|
| Protocol-aware front door | `reproduce <capture>` and positional `live <capture>` share one automatic router for ordinary transports, registered plaintext adapters, TLS, FTP/FTPS, SSH, and explicit raw wire replay |
| Honest fallback policy | Unknown opaque traffic, unsupported security, and DNP3 Secure Authentication are blocked automatically; `--wire` is an operator-selected escape hatch and never claims response equivalence |
| Secure retermination | Captured TLS plaintext is recovered only from an explicit key log, then replayed over fresh verified TLS; FTPS coordinates control and data sessions; unified SSH requires a pinned host key and replays fresh explicit operations |
| Complete-capture enforcement | TLS, FTPS, and SSH honor `--require-complete-capture`; unified mode refuses to replay one selected secure lane while silently omitting another captured lane |
| Repeatable diagnosis | Secure and ordinary attempts share outcome classification, early-stop rules, and summaries; completed-but-uncompared, wire-only, different, and incomplete results remain distinct |
| Shared execution | CLI and dashboard call `internal/planexec` for blocked, semantic, coordinated FTP, UDP/ICMP, stateful TCP, and stateless dispatch instead of maintaining divergent execution trees |
| Evidence and artifact safety | Reports are redacted, explicit output collisions fail before network activity, defaults use numbered unused names, final publication is no-replace on Windows and Unix, and wire replay emits metadata-only evidence |
| Operator help | The no-argument task hub, `help protocols`, `help diagnose`, route/readiness output, typo suggestions, and support-bundle workflow expose a short path from capture to reproducible issue report |
| Release supply chain | Go 1.26.7 builder, three-version compatibility, pinned actions/tools, deterministic multi-platform builds and ZIP, CycloneDX SBOM, checksums, byte comparison, and GitHub build provenance |

### Protocol policy

- Registered plaintext protocols use their semantic adapters when possible;
  ordinary TCP, UDP, and ICMP use the planner's supported transport drivers.
- TLS and FTPS require captured key material and establish a new verified live
  secure connection. SSH establishes a new pinned connection and performs the
  requested command or upload/download operation.
- Opaque or unsupported encrypted traffic is never presented as semantic replay.
  The operator may explicitly choose raw `--wire`, whose report states that
  replies were not compared.
- HTTP/2 and HTTP/3 semantic replay remain deliberately deferred.

## Automated acceptance gates

The branch and tag workflows require:

- module verification, complete tests, and `go vet` on Go 1.25.14, 1.26.7, and
  1.27.x;
- Linux race detection, shuffled/repeated tests, and all seven short fuzz
  targets;
- `govulncheck` with no reachable findings, `staticcheck`, and high-confidence
  high-severity `gosec`;
- aggregate and package coverage floors;
- Linux amd64, Linux arm64, and Windows amd64 builds;
- deterministic artifact regeneration and byte comparison;
- binary version/module inspection, CycloneDX structure validation, Windows ZIP
  extraction/version smoke, SHA-256 verification, and GitHub attestations;
- release-asset download, name comparison, and checksum verification after
  publication.

## Local verification results

The completed v0.8.0 source tree passed these gates on 2026-08-31:

| Gate | Result |
|---|---|
| Toolchains | Complete Windows test suite passed on Go 1.25.14, 1.26.7, and 1.27.0 |
| Modules and compiler checks | `go mod verify`, `go mod tidy`, `go vet ./...`, and Linux amd64, Linux arm64, and Windows amd64 cross-builds passed |
| Static and vulnerability analysis | `staticcheck` v0.7.0, high/high `gosec` v2.28.0, and `actionlint` v1.7.12 reported zero findings; `govulncheck` v1.7.0 reported zero reachable vulnerabilities |
| Stress and concurrency | Windows race detector passed; all packages passed shuffle count 3; `internal/webui` passed shuffle count 20 |
| Fuzz smoke | All seven configured fuzz targets passed five-second smoke runs |
| Coverage | aggregate 62.2%, `pcapio` 85.3%, `webui` 61.5%, `cmd/livewire` 45.0%, backend 30.1% |
| Integration | The suite includes loopback end-to-end TLS retermination and repeated secure outcome/report tests in addition to protocol simulators and parser fixtures |

The release artifacts are regenerated only after this audit is finalized. Their
`SHA256SUMS` file is the authoritative hash record. Commit, tag, attestation,
release URL, asset-name parity, and downloaded checksum evidence are recorded by
GitHub and the tag workflow rather than embedded here; doing so inside a release
input would make byte-reproducible artifact hashes circular.

## Windows trust notice

The Windows amd64 executable and ZIP are not Authenticode-signed. They include
`WINDOWS-UNSIGNED.txt`; users must verify `SHA256SUMS` and the GitHub provenance
attestation before accepting an unknown-publisher warning. The WinDivert setup
helper independently pins the official v2.2.2 archive to
`63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`
and rejects a mismatched download or invalid available signature.

## Verification boundaries

These are disclosed limitations, not inferred passes:

- no elevated replay against a controlled physical Windows or Linux NIC/device;
- no deliberately wired physical two-interface DUT replay;
- no native execution of the Linux arm64 binary on arm64 hardware;
- no Authenticode publisher identity for the Windows application;
- no claim that raw wire replay, opaque encrypted replay, or an unverified
  completed exchange matched application behavior;
- no HTTP/2 or HTTP/3 semantic adapter.

Simulator, parser, loopback integration, Windows-runtime, cross-build, and
artifact tests do not substitute for those physical or publisher-trust checks.
