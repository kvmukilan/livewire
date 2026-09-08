# Livewire 0.9.0-rc.1 release audit

Date: 2026-09-08. Disposition: **release candidate for validation**, not stable.

The 0.8 audit remains available in `dist/v0.8.0/RELEASE_AUDIT.md` and the
v0.8.0 tag. Its historical test results do not qualify the current source.

## What worked in 0.7, what regressed in 0.8

This review compared the published Windows executables, tagged source, current
CLI/dashboard behavior, and synthetic loopback captures. No individual reviewer
comments or customer captures were supplied, so the findings establish concrete
regressions; they do not explain every reported bad review.

| Area | 0.7 strength / behavior | 0.8 problem | 0.9 response |
|---|---|---|---|
| Valid binary HTTP | gzip response replay completes and matches | Entropy heuristic overrides a valid HTTP adapter and blocks before sending | Decode recognized application data before treating entropy as unknown security |
| Everyday help | Capture, check, reproduce, interfaces, and dashboard are visible | Front door prioritizes two overlapping replay commands; discovery needs more steps | Restore the five everyday commands and keep advanced aliases |
| Mixed captures | Planner exposes HTTP and raw background lanes | Whole-capture secure routing can reject a useful exchange with no built-in selection | Explicit session selection; excluded packets remain in the accounting and report |
| Readiness | Adapter plan is visible | The gzip fixture simultaneously says BLOCKED, 100% replay confidence, and semantic HTTP | One shared readiness decision and capture-quality wording |
| Operator control | Existing fidelity profiles and narrow commands are available | Automatic classification decides execution before the operator can express intent clearly | Application / transport / wire modes, automatic compatibility mode, offline dry-run |
| Dashboard | Existing local dashboard | Stale build label, limited secure workflow, stale previews and repeated-start risk | Current build version, secure inputs, shared executor, invalidation and duplicate-start tests |

0.8 also improved successful help exit behavior, secure input guidance, pinned
SSH identity, artifact collision protection, redaction, and release gates.
Those protections are retained. Returning wholesale to 0.7 would lose useful work.

The design decision is **automatic inspection with explicit execution intent**.
Application mode requires an application driver. Transport mode accepts unknown
binary payloads without claiming application equivalence, while recognized TLS
and SSH require fresh secure sessions or explicit wire mode. Wire mode has no
response-equivalence claim. Script invocations omitting mode retain compatibility.

## Reproduced published-binary comparison

`scripts/compare-releases.py` generates checksummed Ethernet/IP/TCP PCAPs, starts
only localhost HTTP servers, and compares published 0.7/0.8 with the current EXE.
The mixed-capture case is inspected offline in old releases; no raw interface is
opened by the comparison. The script is now required in Windows CI and release CI.

| Case | 0.7 | 0.8 | 0.9 candidate |
|---|---|---|---|
| Same gzip HTTP exchange | exit 0, one HTTP request | exit 1, zero requests, opaque blocker | exit 0, one request |
| HTTP plus ARP, select HTTP and preview | no new session-selection workflow | no new session-selection workflow | exit 0, background explicitly excluded, no send |
| HTTP plus ARP, select HTTP and execute | not exercised on wire | not exercised on wire | exit 0, one HTTP request, excluded packet reported |
| No-argument help | five everyday commands, exit 2 | two replay entry points, exit 0 | five everyday commands, exit 0 |

Run from the repository after building `livewire.exe`:

```powershell
python scripts/compare-releases.py --output coverage/new-comparison
```

The output directory must be new. It contains captures, command transcripts,
reports, exit codes, request counts, and transcript digests.

## Additional fixes found by release review

- `golang.org/x/crypto` v0.55.0 had two reachable SSH deadlock vulnerabilities:
  [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
  [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355). Upgrade to v0.56.0 removes
  the reachable findings. Its Go minimum is 1.26; CI tests 1.26.7 and 1.27.x with
  automatic toolchain switching disabled so the compatibility labels are honest.
- Secure timing previews now reject unsupported execution before input collection.
- Truncated FTP data lanes cannot become runnable when grouped with control traffic.
- Partially specified SSH expectations and TLS with no compared responses cannot
  report an overall verified match.
- Dashboard plans and reports hash the same loaded byte stream. An integration
  test replaces a capture during HTTP replay and verifies the report still names
  the original input digest.
- Removed obsolete private planning helpers detected by staticcheck.
- The Windows package now includes `WORKFLOW.md`; release publication explicitly
  marks `-rc.N` tags as prereleases and does not promote them to Latest.

## Local verification

These are automated Windows-host results on the candidate source, not physical
hardware or visual browser qualification.

| Gate | Result |
|---|---|
| Go 1.26.7 and Go 1.27.0 | Complete tests passed; module verification and vet passed |
| Concurrency | Complete race tests passed on 1.26.7 |
| Repeatability | All packages shuffled three times; webui shuffled twenty times, passed |
| Fuzz smoke | All seven configured targets completed their five-second runs |
| Static checks | staticcheck v0.7.0 and actionlint v1.7.12 passed |
| Security | govulncheck v1.7.0: zero reachable findings; one module-level finding outside called code. gosec v2.28.0 high/high: zero issues |
| Coverage, Go 1.26.7 | Aggregate 60.8% (floor 60); pcapio 85.3% (85); webui 62.5% (60); CLI 39.6% (30); backend 30.1% (20) |
| Planner coverage | 87.9%; explicit intent, exclusions, TLS/SSH/FTPS requirements, truncation and lab capabilities |
| Dashboard state | Five shipped-JavaScript state tests passed; API and loopback integration tests passed |
| End-to-end regressions | Published-binary gzip comparison, selected exchange, TLS verified peer, FTP coordination, SSH expectation outcomes, capture replacement |

Artifact hashes and final publication evidence are intentionally outside this
input document: embedding the final hash inside the release would be circular.
The tag workflow rebuilds Linux amd64/arm64 and Windows amd64, byte-compares the
committed artifacts, validates the ZIP and SBOM, attests binaries/checksums, and
re-downloads published assets for verification. Its actual run status is the
source of truth for those publication gates.

## Stable-promotion criteria

The following remain open and prevent treating this candidate as stable:

1. Browser visual and keyboard checks at desktop and narrow widths: select a
   capture, inspect, select sessions, change intent, provide TLS/SSH inputs,
   start, stop, inspect differences, download evidence. No browser was connected
   in this environment; DOM-state tests are not visual QA.
2. Controlled Windows and Linux physical NIC tests for capture, stateful TCP,
   UDP/ICMP, raw wire mode, cancellation, and driver/interface error recovery.
3. A physical two-interface DUT run using transport/wire intent and topology.
4. A small network/QA-engineer pilot against the actual workflows that produced
   the 0.8 complaints. Record task completion, time to first successful replay,
   unnecessary blockers, mode confusion, and usefulness of the resulting report.

Native Linux arm64 execution and Windows Authenticode signing also remain
unverified/unavailable. The Windows archive includes the unsigned-build notice.
HTTP/2 and HTTP/3 semantic adapters and arbitrary mixed secure exchanges remain
outside this candidate's supported scope. Loopback, simulator, parser, and
cross-build checks do not prove those capabilities.

Promote only after these acceptance checks pass. Keep new protocol expansion
behind recovery of predictable replay, clear scope, and useful diagnostic evidence.
