# PCAP replay reliability review — 2026-09-29

This is the initial review snapshot, before the subsequent version 1 fixes and qualification. See [V1_QUALIFICATION.md](V1_QUALIFICATION.md) for the final release scope and evidence. The remaining-work table below records findings at the time of this review.
It does not qualify a release or claim validation against physical equipment.

## Choosing what to reproduce

Application replay is the best starting point for reproducing a supported
request/response problem. It opens a fresh connection, uses the operating
system's TCP implementation, and maintains the application state supported by
the selected adapter. Inspect the capture, select the exchange, and preview:

```sh
livewire check issue.pcap -details
livewire reproduce issue.pcap -mode application -session tcp-0 -dry-run
livewire reproduce issue.pcap -mode application -session tcp-0 -t 192.168.1.50 -n 5 -strict-exit -run-timeout 10m
```

Use transport mode for captured TCP packet patterns, such as client
retransmissions, segmentation, unusual flags, and ACK ordering. It establishes
fresh sequence space against the live peer, but it is not a general-purpose TCP
stack. It cannot reproduce an old socket or guarantee that a captured packet
pattern remains valid when the target responds differently. Use an independent
capture and device logs to establish whether the particular fault recurred.

See `livewire help reliability` and [WORKFLOW.md](WORKFLOW.md) for commands,
and [RELIABILITY_IMPLEMENTATION.md](RELIABILITY_IMPLEMENTATION.md) for durable
progress, scenario setup, response comparison, and recovery contracts.

## Repairs in this review

The focused regression tests cover defects missed by the previously passing
suite:

- TCP receive accounting now retains bounded out-of-order sequence ranges,
  merges retransmitted overlaps, and advances only across contiguous data,
  including wraparound and FIN sequence space.
- The handshake validates SYN acknowledgements, ignores unrelated traffic,
  accepts SYN-ACK payload, echoes live server timestamps, and retries a lost SYN
  in the transport replay path. Invalid established flags and stale reset
  sequences are ignored. Terminal conversations ignore late events.
- Ignored or continuously arriving background packets no longer cancel or
  starve the TCP retransmit deadline.
- TCP application replay translates a captured client FIN into a socket write
  half-close. A loopback regression verifies a server can wait for EOF, then
  reply while the client still reads. SYN/FIN sequence anchors now expose missing
  captured prefix/suffix bytes before replay.
- Persistent response framing retains extra messages returned by an incremental
  decoder. Expected-message normalization errors remain actionable errors.
- MQTT server-assigned publish identifiers no longer overwrite the independent
  client transaction namespace. A bidirectional QoS 2 exchange with overlapping
  captured identifiers verifies the acknowledgement sequence.
- DNP3 continuation payload is no longer interpreted as an application header;
  transport fragment state and unsolicited confirmation mappings are scoped to
  link addresses. The preexisting conservative group-120 security blocker is
  preserved independently of header parsing, with a CLI regression proving the
  guarded pattern stops before replay. Changed fragment boundaries and complete
  fragmented authentication inspection remain unsupported.
- HTTP framing handles an empty substituted chunked body correctly and avoids
  integer overflow from an oversized `Content-Length`.
- Replay plans expose TCP fidelity limits. `help reliability`, the workflow guide,
  and verdict text distinguish checked response matches from fault reproduction.

## Validation performed

- Windows amd64, Go 1.27.0: `go run ./scripts/task all` passed build, vet,
  uncached unit tests, dashboard state tests, security/static analysis, race,
  three shuffled suite passes, twenty shuffled dashboard-package passes,
  seven fuzz targets at 200,000 iterations each, coverage, and the maintained
  regression corpus. Aggregate coverage was 65.9%; every required floor passed.
- Windows amd64, Go 1.27.0: `go test -race -count=1 ./...` passed.
- Linux amd64 under Kali WSL, Go 1.26.4: `go test -race -count=1 ./...` passed.
- The final engine flag/timer changes were followed by another race run of
  `./internal/engine ./internal/livereplay ./internal/lab` on both platforms.
- The final DNP3 guard change was followed by race tests of
  `./internal/dissect ./internal/adapters ./internal/replayintent ./cmd/livewire`
  on both platforms, vet on the changed Windows packages, and a passing final
  `go run ./scripts/task lint` security/static-analysis run.
- Windows: `go vet ./...`, `go build ./...`, `go mod verify`, and
  `git diff --check` passed. Engine vet was repeated after its final changes.
- Built the development executable and ran `help reliability` successfully.
  Automated CLI tests also exercise the new help route, existing commands,
  secure-session replay, and durable resume.

Local race logs and executable: `coverage/reliability-review-20260929/`.
Windows executable: `coverage/reliability-review-20260929/livewire.exe`.
SHA256: `8904fab9fd3191ef6ae99357a3c5c04abe74711100a15a30b1d68bf46ad2f3b3`.

No physical NIC/DUT, long-soak qualification, browser visual checks, or release
publication was performed. The security scan found no reachable or imported
package vulnerabilities and reported one unused module-level advisory. Existing
checkout changes were preserved; nothing was committed. The remaining work
below is still required before claiming broader TCP interoperability or field
reliability.

## Original next priorities

| Priority | Remaining work | Why it matters / acceptance evidence |
|---|---|---|
| 1 | Complete the adaptive transport sender's cumulative ACK and outstanding-segment model, generated ACKs, peer window handling, zero-window probes, loss recovery, and TCP close/challenge-ACK behavior. Keep deliberate captured-packet replay as an explicit behavior. | The current replay engine cannot promise general TCP interoperability. Exercise partial ACKs, loss, reordering, small/zero windows, delayed ACKs, simultaneous close, stale RSTs, and sequence wrap against real OS stacks. Socket application replay already delegates these responsibilities to the OS. |
| 1 | Add explicit fault expectations separate from response equivalence. | A reset, timeout, or crash may be the desired reproduction outcome. An incomplete exchange alone cannot distinguish that outcome from a broken replay. Record the expected fault, observation window, device evidence, and first divergence. |
| 1 | Complete Windows and Linux physical NIC/DUT qualification. | Use the existing qualification harness, three consecutive passes per required scenario, verified cleanup, and two-hour soaks for both `reproduce` and `live`. Record exact protocol/device/firmware combinations. Loopback tests and WSL do not satisfy this gate. |
| 2 | Service MQTT keepalive and asynchronous traffic during long captured waits; cover negotiated MQTT 5 behavior. | A session can time out while the replay scheduler waits. Validate with a broker whose keepalive is shorter than the captured pause, including QoS traffic in both directions. |
| 2 | Reassemble DNP3 application data when the target changes transport or application fragmentation. | Correct handling of continuation headers does not provide cross-fragment equivalence. Test the same logical reply under different fragmentation patterns and unsolicited responses. |
| 2 | Expose a per-exchange timeout for plain application replay. | The generic TCP semantic runner defaults to three seconds; the CLI's `-timeout` is currently reserved for fresh secure routes. `-run-timeout` bounds the entire run and does not extend that response deadline. Slow industrial responses need a separately declared budget. |
| 2 | Expand response-dependent pipelining and declare timing tolerances. | A captured request may need a fresh token from a response that has not arrived. Explicit dependencies should either schedule correctly or block before sends; report actual timing drift and resource constraints. |

Target firmware, configuration, authentication state, and starting data must be
made repeatable outside the PCAP. Durable resume records progress and uncertainty;
it cannot restore TCP/TLS sessions or make uncertain writes exactly once.

## Protocol references

TCP handshake acknowledgement validation and sequence-space handling were
checked against [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), and live
timestamp echo behavior against [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html).
MQTT identifier ownership follows the independent client/server namespaces in
the [MQTT 3.1.1 specification](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html).
The focused fixes do not constitute a claim of full RFC conformance.
