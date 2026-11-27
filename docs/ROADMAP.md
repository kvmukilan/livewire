# Livewire roadmap

This lists features under consideration after 1.5.0. Nothing here is a commitment, and an entry does not change the supported scope described in [RELIABILITY_IMPLEMENTATION.md](RELIABILITY_IMPLEMENTATION.md) until it ships and appears in the changelog.

## Direction

Livewire stays an authorized-testing replay tool: it takes one recorded exchange, replays it against one named device through fresh connections, and states whether the checked responses match. The next versions aim to reduce the number of captures that end as "completed, not compared" or "cannot decrypt", and to make the dashboard sufficient on its own for every route the CLI supports. The first goal means HTTP/2, the remaining common TLS 1.2 suites, client certificates and `Expect: 100-continue`. The second means run history, a recorded-versus-live view, an exportable finding report, and SSH/FTP/two-sided flows in the guided path. Release qualification should get cheaper per release without weakening what a stable tag asserts.

## 1.6 candidates

### 1. Wider TLS decryption coverage (M)

**Problem.** A capture with a correct key log still fails with `unsupported cipher suite 0x....` when the server chose TLS 1.2 ChaCha20-Poly1305, DHE-GCM or a CBC suite. A TLS 1.3 session that sends KeyUpdate cannot be decrypted past that point. Embedded PCAPNG secrets with a label outside the fixed list are rejected, although Wireshark and newer clients write extra labels.

**Behaviour.**
- Add 0xCCA8, 0xCCA9, 0x009E, 0x009F and the CBC-SHA/SHA256/SHA384 suites, including encrypt-then-MAC.
- Follow KeyUpdate by ratcheting the traffic secret per direction.
- Ignore unknown labels with a counted note; continue to reject malformed lines.
- `livewire check` and the dashboard readiness line name the suite and say "decryptable" or give the exact reason before a target is entered.

**Files.** `internal/tlsreplay/decrypt.go` (`cipherSuites`, `decrypt12`, `decrypt13`), `kdf.go`, `keylog.go`, `internal/pcapio` (embedded secrets), `internal/replayintent/inspect.go`, `cmd/livewire/check.go`.

**Hard parts.**
- CBC needs explicit IV handling, MAC verification and the EtM extension. This is offline decryption of the operator's own capture, but it must fail closed on a bad MAC.
- A KeyUpdate hidden inside a record that fails to decrypt must stop the session, not desynchronize it.
- Relaxing label handling touches `FuzzPCAPNGTLSSecrets` expectations.

**Tests.** Unit vectors per suite generated with `crypto/tls` and a `KeyLogWriter`; extend `FuzzTLSRecordAndHandshakeParsing`; one replaylab TLS case pinned to TLS 1.2 ChaCha20 and one that forces a KeyUpdate.

### 2. TLS 1.2 resumption fallback and client certificates (M)

**Problem.** A resumed TLS 1.2 session has no `CLIENT_RANDOM` line of its own, so the whole run stops under the 1.5.0 "partial key coverage" rule. Devices that require a client certificate cannot be replayed at all.

**Behaviour.**
- Resolve the master secret of a resumed session from the full handshake in the same capture that issued the session ID or ticket. When that handshake is absent, report "resumed session, original handshake not in capture" for that session.
- Add `-client-cert` and `-client-key` to `live`, with matching dashboard fields beside the CA field, using the existing upload path.
- The report records that a client certificate was presented and its SHA-256 fingerprint. It never records the key.

**Files.** `internal/tlsreplay/records.go` and `decrypt.go` (session ID and ticket linkage), `internal/secureexec/execute.go` and `handshake.go` (`tls.Config.Certificates`), `sessions.go`, `cmd/livewire/tls_cmd.go` and `live.go`, `internal/webui/secure_run.go`, `upload.go`, `index.html`, `SECURITY.md`.

**Hard parts.**
- Extended-master-secret and ticket resumption variants differ; support session-ID and ticket resumption only where the originating handshake is in the capture.
- The private key is a new credential type in the working folder. Reuse the owner-only file handling from `internal/securefile` and `internal/recording`, and exclude it from `bundle` and from artifact listing.

**Tests.** Unit test with a two-connection `crypto/tls` capture (full, then resumed); replaylab case `http1-mtls`; dashboard test that the key path never appears in `/api/status` output or in a report.

### 3. HTTP/2 application replay over TLS (L)

**Problem.** Most current HTTPS captures negotiate `h2`. They decrypt, then replay as opaque chunks and end as "completed, not compared". Raw replay of captured HTTP/2 frames is also wrong against a live server, because HPACK state and SETTINGS differ.

**Behaviour.**
- A new `http2` adapter decodes the captured connection into request/response pairs per stream (HEADERS, CONTINUATION, DATA, trailers).
- It replays each request through a fresh HTTP/2 connection and compares status, selected headers and body, using the HTTP/1 comparison and cookie policy.
- Server SETTINGS, WINDOW_UPDATE and PING are serviced live.
- Dashboard and `check` show "HTTP/2, N requests" instead of "opaque".
- First version: sequential replay in captured request order. Server push and captured stream concurrency are ignored and stated in the result. Cleartext h2c is out of scope.

**Files.** New `internal/adapters/http2.go`; `registry.go`; `internal/adapters/http_policy.go` (shared comparison); `internal/secureexec/execute.go` (ALPN-directed adapter choice, replacing the "opaque plaintext" fallback); `tls_script.go`; `internal/replayintent/inspect.go`; scenario support in `internal/replay`.

**Hard parts.**
- The adapter interface is framed-message oriented. HTTP/2 needs a connection-level driver, so decide early whether to wrap `golang.org/x/net/http2` (`Framer` plus `hpack` for decoding, `Transport` for sending) or to extend the adapter contract.
- A capture that starts mid-connection has an unknown HPACK dynamic table. Detect and refuse it.
- Pseudo-header and header-order fidelity is not preserved by a standard client. Document this as a semantic replay.
- gRPC bodies will compare as bytes only.

**Tests.** Decoder unit tests on recorded frame fixtures; a fuzz target for the frame/HPACK decode path; replaylab case `http2-tls` with a login cookie and an authenticated follow-up, mirroring `http1-tls`; dashboard test for the readiness text.

### 4. HTTP/1 `Expect: 100-continue` and WebSocket upgrade (M)

**Problem.** Uploads using `Expect: 100-continue` are rejected up front (`internal/adapters/http.go`). A capture that upgrades to WebSocket stops being comparable at the 101 response.

**Behaviour.**
- For Expect, send the headers, wait a bounded time for `100 Continue` or a final status, then send the body. Report which occurred.
- For WebSocket, complete the upgrade with a fresh `Sec-WebSocket-Key`, validate the live `Sec-WebSocket-Accept`, re-mask client frames, answer ping/pong, and compare text and binary message payloads in order.

**Files.** `internal/adapters/http.go`, `incremental.go`, `live_events.go`, new `internal/adapters/websocket.go`, `internal/tlsreplay/reterminate.go` (interim-response wait over TLS).

**Hard parts.**
- The interim wait must fit both the plain TCP and the reterminated TLS exchange loops.
- `permessage-deflate` needs either context-takeover handling or refusal. Refuse first.
- WebSocket traffic is often server-driven with no request/response pairing. Compare by ordered server messages, with volatile fields declared through scenario JSON.

**Tests.** Extend `http_framing_test.go`; a replaylab peer that answers 100 on one request and 417 on another; a WebSocket echo-plus-push peer, plaintext and TLS.

### 5. Dashboard: run history and recorded-versus-live view (M)

**Problem.** The result panel holds only the last run. It lists differing values but not the surrounding request and response. Artifacts are only reachable as links for the current job.

**Behaviour.**
- A "History" section lists earlier runs from the working folder (capture, target, time, verdict). Selecting one reloads its result panel.
- Each compared exchange expands to a two-column recorded/live view (decoded fields, plus hex for byte protocols) with differences highlighted.
- CLI equivalent: `livewire compare` already takes a capture and its `.actual.pcap`; add `-html out.html` to emit the same view as a self-contained file.

**Files.** `internal/webui/webui.go` (new `/api/runs`, `/api/run/{id}`), `runs.go`, `secure_run.go`, `run_evidence.go`, `index.html`, `internal/compare/compare.go`, `cmd/livewire/compare.go`.

**Hard parts.**
- Reports hold `Difference{Field, Expected, Actual}`, not full payloads. The view needs payload excerpts, which may contain credentials. Apply the existing `job.protectVariables` scrubbing and size caps, and keep decrypted TLS payloads out of persisted reports unless the operator opts in.
- History must be an index built from report files confined to the working root. It must not become a new store.

**Tests.** `platform_test.go`-style handler tests for path confinement and redaction; `scripts/dashboard.test.cjs` for rendering and for escaping untrusted payload text (device-controlled bytes reach the DOM).

### 6. Dashboard: guided SSH, FTP and two-sided flows, plus a rule-pack helper (M)

**Problem.** The guided path covers single-target application replay. SSH, FTP/FTPS and two-sided (`lab`) runs require opening Advanced options and, for lab, editing JSON. Proprietary protocols need a hand-written rule pack pasted into a textarea.

**Behaviour.**
- After inspection, step 2 switches its fields by detected route. SSH shows user, key, pinned host key and commands. FTP shows credentials and transfer checks. Two-sided shows two interfaces and a generated default topology.
- A "Describe this protocol" panel proposes a rule pack from the selected session: framing guess (length-field, delimiter or fixed) and candidate volatile ranges from bytes that differ between repeated exchanges. The operator edits and saves it as a file.
- CLI: `livewire check capture.pcap -suggest-rules tcp-0`.

**Files.** `internal/webui/index.html`, `flows.go`, `ssh_on.go`, `ftp.go`, `runs.go` (`handleLab`), `internal/replayintent/route.go`, `internal/adapters/rules.go` (new suggestion function), `cmd/livewire/check.go`.

**Hard parts.**
- `index.html` is one file with inline script. Split the script into embedded files before adding more states.
- Rule suggestions are heuristics and must be labelled as proposals. A wrong framing guess must still fail in `CompileRulePackJSON` or at replay, never produce a false match.

**Tests.** `intent_test.go` for route-to-form mapping; `FuzzRulePackCompiler` extended with generated suggestions (every suggestion must compile); dashboard tests per route.

### 7. Finding report export (S)

**Problem.** Replay results feed assessment reports and retest evidence, but the output is JSON plus a pcap. Operators rewrite it by hand.

**Behaviour.**
- `livewire live ... -report-format md|html` and a dashboard "Export report" button.
- Contents: capture digest, target, tool and adapter versions, per-exchange verdict, differences, TLS parameters, and the exact command line to repeat the run.
- A stable, versioned JSON schema document for `*.report.json`, so external analysis tooling can consume it. An optional `-finding-id` label is carried into the report.

**Files.** `cmd/livewire/report.go`, `verdict.go`, `retermination_report.go`, `internal/webui/runs.go`, new `docs/REPORT_SCHEMA.md`.

**Hard parts.** One renderer must serve the generic, TLS, FTP and SSH report shapes, which differ today. The export must reuse redaction and must not introduce a new path for secrets.

**Tests.** Golden-file tests in `report_test.go`; a schema validation test over every replaylab case report.

### 8. Qualification cost (M)

**Problem.** Every stable tag needs full soak matrices on two platforms plus native check bundles, even when a patch release does not touch the replay path. From 1.5.0 the soak is thirty minutes per case and the matrix includes the IEC 104 cases, but the native check bundles are still produced by hand on two machines.

**Behaviour.**
- Add each case introduced above to `ApplicationLabCasesForVersion` in the release that first claims support. Leave historical lists unchanged.
- Define a "patch" profile. A release whose diff does not touch replay-path packages reuses the previous full soak and runs a shortened continuity soak plus the full native checks. The manifest records the profile and both source digests.
- Produce the native Windows and Linux check bundles from a hosted workflow, as the lab matrices already are, so a release no longer depends on two prepared machines.
- Run the application and packet suites concurrently where their peers do not share ports.

**Files.** `internal/qualification/lab.go`, `lab_contract.go`, `qualification.go`, `scripts/qualify`, `scripts/replaylab`, `.github/workflows/qualification.yml`, `docs/V1_QUALIFICATION.md`, `docs/RELEASE_AUDIT.md`.

**Hard parts.** The package-diff rule must be mechanical and conservative, and the validator must reject a patch profile when a listed package changed. Any weakening has to be visible in the published manifest.

**Tests.** `lab_contract_test.go` and `qualification_test.go` cases for accepted and rejected profile claims.

## Later

- **HTTP/3 / QUIC replay.** Needs QUIC key-log labels, QUIC packet decryption and an HTTP/3 client. Reuses the HTTP/2 request model. Large, and adds a significant dependency.
- **TLS 1.3 0-RTT.** Decrypt captured early data with `CLIENT_EARLY_TRAFFIC_SECRET` and replay it as ordinary post-handshake requests, noting the change in the result.
- **ECH.** Decrypt only when the operator supplies the ECH key material. Otherwise report the outer SNI and stop.
- **IEC 104 timers and mid-session captures.** Implement t2/t3 (S-frame acknowledgement timeout, TESTFR on idle) for recorded-timing replays. Warn in `check` when a capture has no STARTDT and sequence numbers start above zero.
- **Negative assertions.** Record "the device did not answer" as an expectation and assert silence for a bounded window, extending `-expect-fault`. Give the raw-socket UDP client a bound source port, and add a real UDP DNS replaylab peer instead of the stub.
- **Concurrent TLS sessions with recorded gaps.** Schedule sessions on the capture timeline instead of serially under `-under-load`, using the existing `-concurrency` bound.
- **Multiple dashboard jobs.** A job queue with per-job status, replacing the single `job` slot in `internal/webui/jobs.go`. Raw-interface jobs stay exclusive.
- **Dashboard login for non-loopback use.** Today the Host check refuses non-loopback access. A remote mode would need a one-time token or client certificate. Not worth doing before a concrete need exists.
- **Native packaging.** A signed Windows installer and tray launcher, and a certificate trusted for the current user only, to remove the first-use browser warning. Requires validating the double-click launch on real Windows hardware first.
- **MQTT enhanced authentication and DNP3 Secure Authentication.** Only with operator-supplied credentials or update keys. Each needs a design note before code.
- **Batch retest.** Run a directory of captures against one target and produce one summary report, building on the finding report export.

## Explicitly not planned

- **Target fuzzing or request mutation campaigns.** `examples/README.md` mentions `livewire fuzz`, but no such command exists. That sentence should be removed. The Go fuzz targets in `scripts/task` test Livewire's own parsers and stay. `-set` variables and scenario bindings remain the only way to change replayed content.
- **Multiple targets, target lists, address ranges or discovery.** One run addresses one named device.
- **Rate amplification or load generation beyond recorded pacing.** `-n`, `-concurrency` and `-under-load` exist to reproduce intermittent faults, not to exhaust a device.
- **Evasion of monitoring or inspection.** No fragmentation tricks, TLS fingerprint imitation, timing jitter or source spoofing added for the purpose of avoiding detection. Replays should be attributable to the operator's host.
- **Obtaining keys or credentials.** No interception proxy, no downgrade, no key extraction from processes other than the client the operator launches through `capture -tls`, no credential guessing. Decryption requires secrets the operator already holds.
- **Reusing captured TLS ciphertext or session tickets as a live session.** Cryptographically meaningless and already documented as such.
- **Bypassing unsupported authentication.** MQTT enhanced auth and DNP3 Secure Authentication stay blocked until implemented with operator-supplied credentials.
- **A hosted or multi-user service.** Captures and key logs stay on the operator's machine.

## Suggested order

1. **Item 1**: self-contained in `internal/tlsreplay`. Unblocks the most captures and is a prerequisite for meaningful HTTP/2 fixtures recorded from ordinary clients.
2. **Item 2**: shares the `secureexec` configuration work. Do the resumption fallback before client certificates.
3. **Item 4, Expect part**: small, and it exercises the interim-response wait that the HTTP/2 and WebSocket drivers also need. WebSocket can follow item 3.
4. **Item 7**: defines the report schema that items 5 and 3 write into. Do it before the dashboard reads reports back.
5. **Item 5**: depends on the schema from item 7. Split `index.html` scripts as its first step.
6. **Item 6**: depends on the script split in item 5.
7. **Item 3**: the largest item. Depends on item 1 for fixtures and on the adapter-contract decision. It can proceed in parallel with items 5 to 7, since it touches different packages. If it is not ready, 1.6 ships without it and it leads 1.7.
8. **Item 8**: move the native check bundles to a hosted workflow before 1.6.0; land the patch profile before the first 1.6.x patch release, since 1.6.0 changes replay-path packages and needs the full soak regardless.

Each new protocol capability adds its replaylab case in the same change, and the case joins the versioned qualification list in the release that first claims support.
