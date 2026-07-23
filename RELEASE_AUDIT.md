# Livewire v0.5.0 Release Audit

Audit date: 2026-07-23

Disposition: **automated software release gates pass. Physical hardware,
arm64 execution, Wireshark, and rendered-browser qualification remain pending
and are documented below rather than being implied by the release.**

## Requirement coverage

| Area | Status | Evidence |
|---|---|---|
| Every captured frame is represented exactly once | Pass | Transport-neutral `Trace`, `Session`, `Event`, explicit raw lanes, `ReplayPlan.ValidateCoverage`, unit/fuzz coverage in `internal/replay` |
| Explicit functional/timing/transport/wire selection | Pass | Concrete drivers and requested/achieved fidelity in analyze, reports, one-sided runs, and per-session lab verdicts |
| TCP adaptive replay | Pass | Existing live client state machine plus sequence-aware application reconstruction; gaps/conflicting overlaps block adaptive modes while explicit wire remains available |
| Stateful UDP | Pass | Bidirectional tuple grouping, configurable idle boundary, turn replay, adapter correlation, unsolicited/multicast wire grading |
| ICMPv4/ICMPv6 Echo | Pass | Identifier/sequence matching, address/checksum rewriting, response verification; non-Echo control traffic remains an explicit raw/wire lane |
| IPv6 foundations | Pass | IPv4/IPv6 fragment reassembly, overlap rejection, IPv6-aware filters, Linux/Windows NDP, IPv6 RST suppression |
| Cancellation and cleanup | Pass | Context-aware receive/pacing/concurrency, prompt TLS/SSH connection cancellation, and tests proving backend/RST-guard release on success, error, cancellation, and panic |
| Two-sided DUT lab | Pass in simulation | One scheduler, client/server actors, NAT/PAT tuple learning, TCP peer-clock ACK/SACK adaptation, UDP/ICMP actors, topology gateway/MAC/VLAN/MTU handling |
| Deterministic faults | Pass | Seeded delay/jitter/drop/duplicate/reorder/rate/MTU rules with direction/session/time/packet matching and parser fuzzing |
| Dual-interface evidence | Pass in automated tests | PCAPNG writer with two interface blocks; NAT, TCP clock, latency, loss, duplication, reorder, reset, timeout, and per-session verdict reporting; raw-lane side inference uses captured topology addresses and reports ambiguity |
| Adapter contract and JSON rules | Pass | Compiled adapter API plus bounded declarative framing, correlation, volatile ranges, and copy-from-live substitutions; no arbitrary scripting |
| HTTP/1.0 and HTTP/1.1 | Pass | Pipelining, request-aware HEAD/CONNECT responses, Content-Length validation, chunked and close framing, substitutions with length repair |
| TLS 1.2/1.3 | Pass for documented suites | Matching NSS key-log decryption, strict record/handshake reassembly, capture-timeline plaintext ordering, grouped pipelined turns, fresh verified TLS connection, inner-adapter replay, and a redacted capture-coverage report; missing/unsupported secrets fail explicitly |
| SSHv2 | Pass with supplied inputs | Capture-bound fresh SSH connection using explicit credentials and command/expect script, optional host-key pinning, digest-only output evidence, and a redacted coverage report; ciphertext-only captures are blockers |
| DNS UDP/TCP | Pass | TCP framing, transaction-ID plus question correlation, run-name substitution, lenient ID/TTL comparison |
| MQTT 3.1.1/5.0 | Pass | Remaining-length framing, client/credential substitutions, and QoS 0/1/2 flow handling including learning broker-selected packet IDs and rewriting later client acknowledgements |
| Modbus/TCP and DNP3 | Pass | Semantic framing/comparison and transaction/application sequence handling; DNP3 Secure Authentication remains an honest blocker |
| Variables and secret handling | Pass | Repeated `-set`, web fields, learned values, log/report/support-bundle redaction, digest-only proprietary diffs and SSH output evidence, and secret regression tests |
| Fidelity-claim invariant | Pass | Verification-off results are explicitly unverified/unmatched; wire and blocked lanes never claim adaptation or response equivalence |
| Dashboard and APIs | Pass for source/API tests | Offline embedded graphite/navy UI; plan/run/lab/validate/status/stop/artifact/bundle APIs; responsive markup, keyboard shortcuts, focus treatment, labels, ARIA groups, and pressed state |
| Local release material | Pass | MIT `LICENSE`, changelog, security/operator guidance, Go 1.25 floor, guarded release script, checksums, three local binaries, and a self-contained Windows ZIP with setup helper and quick-start |

## Automated release gate results

All commands were run from the local dirty workspace without committing it.

| Gate | Result |
|---|---|
| `gofmt` | Pass |
| `go test -count=1 ./...` on Windows/current Go | Pass |
| `go vet ./...` | Pass |
| `go mod verify` | Pass |
| `go test -race -count=1 ./...` on Windows | Pass |
| `GOTOOLCHAIN=go1.25.0 go test -count=1 ./...` | Pass |
| Linux/amd64 WSL2 current-Go unit suite | Pass |
| Linux/amd64 WSL2 current-Go race suite | Pass |
| Adapter, rule-pack, scenario, trace, TLS framing, IPv6 fragment, and malformed-fragment fuzz targets | Pass; all seven targets executed live mutations after baseline collection (longer campaigns used for the larger rule/scenario corpora) |
| Dashboard embedded JavaScript syntax | Pass with Node parsing of the embedded script |
| `git diff --check` | Pass; only existing Git line-ending notices |
| Linux amd64, Linux arm64, Windows amd64 builds | Pass |
| Windows artifact version and module/architecture metadata smoke | Pass |
| Windows release ZIP extraction, bundled setup helper, Npcap detection, official WinDivert download/copy, and packaged EXE version smoke | Pass |
| Linux amd64 artifact version smoke under WSL2 | Pass |
| Linux arm64 artifact module/architecture metadata smoke | Pass; execution remains a hardware gate below |

## Local artifacts

Directory: `dist/v0.5.0`

| Artifact | SHA-256 |
|---|---|
| `livewire-0.5.0-linux-amd64` | `93d874b72f09a0b9629601e31691583ccc190956d374628088860d00601a8a0a` |
| `livewire-0.5.0-linux-arm64` | `dc5607095a2415012c3d2b7cce3e497d38bd2cf9d3433823bc21b05fb7c12386` |
| `livewire-0.5.0-windows-amd64.exe` | `f14c61ded3dd596a37497e42ec8ba895bc5907a61cbe99e8a5a7b10ee7cdf142` |
| `livewire-0.5.0-windows-amd64.zip` | `837e5592de8390196dc30efe9faac60f35a8f67f04a2e63f9878a852f4f98fa0` |
| `LICENSE` | `2094a839810ecd4147e3db41712e4c312e97d635fc739b1596763879ba5e20d1` |
| `README.md` | `687a1e32a30eb79b226a8c3f223f600875ec915c3283f5246c8e362296b3a496` |
| `SETUP.md` | `7dec22974b57d1e60b65a38371161cc5da2cace91223f8193f4e89c7c3077fef` |
| `WINDOWS-QUICKSTART.md` | `cee3dba62d3d117e63b49938fc0118af3539b929c79bbe4523a12f6c7ae51733` |
| `DOCUMENTATION.md` | `11bbd82baa62cfdc0d61c40c84663ed74f8fabf6f0b92fc8212db18e426d9221` |
| `setup-windows.ps1` | `e576f5f57ccdd427f83f4708820b05bf189d7592204ebe5110e9e4d4a604a16a` |
| `CHANGELOG.md` | `777bfdfce04e436bd89600a01e196c96fa178d96b267bd2b7519d5f268a15bee` |
| `SECURITY.md` | `0a587116ec74eac4562c5ec15d3887b90731fe9f53e3c8b874f20e976f6fe734` |

The hashes were independently recomputed after the release script generated
`SHA256SUMS`. All artifacts embed the expected module path and report version
`0.5.0`; the current builder was Go 1.26.1.

## Required gates still pending

These checks require capabilities not available in the current session and are
not replaced by the passing simulator/unit coverage:

- Elevated Windows one-sided injection against a controlled physical target.
  Npcap is running, but the current process is not an administrator.
- Elevated Linux one-sided injection against a controlled physical target.
  WSL2 passed unit and binary smoke tests, but is not a hardware packet smoke.
- A physical or deliberately wired virtual two-interface DUT run covering
  pass-through, NAT/PAT, proxy, firewall rejection, cancellation, and cleanup.
- Opening the produced dual-interface PCAPNG in Wireshark. Neither Wireshark,
  `tshark`, nor `dumpcap` is installed in this environment.
- Rendered visual/keyboard validation of the dashboard. The in-app browser was
  unavailable; API/DOM source tests and JavaScript syntax passed, but they are
  not a rendered-browser substitute.
- Execution on Linux arm64 hardware. The artifact cross-build and metadata
  checks pass, but this host cannot execute that architecture.

Do not describe v0.5.0 as fully released until the required pending gates have
been recorded with interface names, target/DUT topology, commands, artifact
digests, resulting reports, and PCAPNG evidence.

## Deliberate v0.5.0 boundaries

- Two-sided actors adapt transport state and preserve opaque application bytes;
  they do not claim semantic application equivalence unless a one-sided
  application adapter/retermination path is used.
- TLS needs matching session secrets and a supported cipher suite. SSH needs
  credentials and an explicit command script. Encrypted intent is never guessed.
- DNP3 Secure Authentication and proprietary fresh cryptographic state require
  a purpose-built security-aware adapter.
- HTTP/2, HTTP/3, distributed agents, high-scale traffic generation, and
  automatic encrypted-data recovery are outside v0.5.0.
