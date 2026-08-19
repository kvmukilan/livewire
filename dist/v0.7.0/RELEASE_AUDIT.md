# Livewire v0.7.0 Release Audit

Audit date: 2026-08-20

Disposition: **local release gates passed; GitHub PR and tag workflows remain
mandatory publication gates.** Physical NIC/device replay, a physical two-interface
DUT, native Linux arm64 execution, and Authenticode publisher trust are explicit
unverified boundaries and are not presented as completed validation.

## Implemented release scope

| Area | Evidence |
|---|---|
| Bounded capture parsing | Shared `pcapio.Limits`; strict classic-PCAP and PCAPNG validation before allocation; malformed, oversized, truncated, footer, snaplen, timestamp, and count fixtures |
| Artifact integrity | Mode-0600 temporary files, mode-0700 private directories, checked write/flush/close paths, and atomic final rename |
| Dashboard boundary | `os.Root` file confinement; extension and regular-file enforcement; method, JSON, 1 MiB, strict-field, same-origin, CSRF, loopback Host, and unsafe-bind controls |
| Lifecycle | Timed `http.Server`, signal handling, idempotent shutdown, active-job cancellation/join, resource closure, and aggregated RST-guard failures |
| Secret handling | One structured redactor across CLI, dashboard, errors, logs, reports, evidence metadata, and bundles, including JSON-escaped secret forms |
| Windows loading | System Npcap-only loading; absolute executable-directory WinDivert loading with restricted DLL search; pinned v2.2.2 archive hash and signature checks |
| FTP/FTPS | Command/reply adapter, multiline replies, strict/lenient comparison, coordinated active/passive IPv4/IPv6 groups, transfer digest verification, explicit/implicit TLS recovery and fresh verified live TLS |
| Exact-once planning | `ModeCoordinated` with related control/data session IDs and capture coverage validation |
| Shared execution | CLI and dashboard share bounded capture loading, planning, FTP execution, redaction, finalization, and report primitives |
| Release supply chain | Go 1.26.7 builder, pinned dependencies/actions/tools, deterministic multi-platform builds and ZIP, CycloneDX SBOM, checksums, byte comparison, and GitHub build provenance |

HTTP/2 and HTTP/3 semantic replay remain deliberately deferred.

## Automated acceptance gates

The release branch and tag workflows require:

- module verification and complete tests on Go 1.25.14, 1.26.7, and 1.27.x;
- Windows runtime tests, Linux/Windows cross-builds, `go vet`, race detection,
  shuffled/repeated tests, and all seven short fuzz targets;
- `govulncheck` with no reachable findings, `staticcheck`, and high-confidence
  high-severity `gosec`;
- aggregate/package coverage floors configured in CI;
- deterministic release regeneration and byte comparison;
- binary version/module inspection, CycloneDX structure validation, Windows ZIP
  extraction/version smoke, SHA-256 verification, and GitHub attestations;
- release-asset download, name comparison, and checksum verification after
  publication.

## Local verification results

The completed release tree passed these local gates on 2026-08-20:

| Gate | Result |
|---|---|
| Toolchains | Complete Windows test suite passed on Go 1.25.14, 1.26.7, and 1.27.0 |
| Modules and compiler checks | `go mod verify`, `go vet ./...`, and all three required cross-builds passed |
| Static and vulnerability analysis | `staticcheck` v0.7.0 and high/high `gosec` v2.28.0 reported zero findings; `govulncheck` v1.7.0 reported zero reachable vulnerabilities |
| Stress and concurrency | Linux race detector passed; all packages passed shuffle count 3; `internal/webui` passed shuffle count 20 |
| Fuzz smoke | All seven configured fuzz targets passed five-second smoke runs |
| Coverage | aggregate 61.4%, `pcapio` 85.3%, `webui` 60.5%, `cmd/livewire` 36.8%, backend 30.1% |
| Workflow validation | `actionlint` v1.7.12 passed |

The committed artifacts are regenerated only after this audit is finalized.
Their `SHA256SUMS` file is the authoritative hash record. Commit, PR, tag,
attestation, release URL, asset-name parity, and downloaded checksum evidence
are recorded by GitHub and the tag workflow rather than embedded here; doing so
inside a release input would make byte-reproducible artifact hashes circular.

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
- no HTTP/2 or HTTP/3 semantic adapter.

Simulator, parser, integration, Windows-runtime, cross-build, and artifact tests
do not substitute for those physical or publisher-trust checks.
