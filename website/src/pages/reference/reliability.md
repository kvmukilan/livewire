---
layout: "../../layouts/Reference.astro"
title: "Reliability reference"
description: "Replay state, supported protocols, durable progress, and verification boundaries."
sourcePath: "docs/RELIABILITY_IMPLEMENTATION.md"
sourceRef: "v1.0.1"
---


This describes the 1.0 implementation. The
[software-lab qualification profile](https://github.com/kvmukilan/livewire/blob/v1.0.1/docs/V1_QUALIFICATION.md) defines release evidence;
physical-device qualification remains separate. The
[2026-09-29 reliability review](https://github.com/kvmukilan/livewire/blob/v1.0.0/docs/RELIABILITY_REVIEW_2026-09-29.md) is an earlier
implementation snapshot; protocol behavior below includes subsequent fixes.
Positional `live capture.pcap` and `reproduce` share the fresh-session
orchestrator. `live -in` with explicit secure inputs also uses it; without
secure inputs, `live -in` retains its simulation default and transport driver. Application replay uses
operating-system TCP; transport and wire execution retain their own drivers.
Each TCP application attempt establishes fresh connection state. TLS captures are decrypted
offline with explicitly supplied key material, then replayed over new verified
TLS connections; captured TLS keys and ciphertext do not become the live session.
Compatibility commands and deprecated flag aliases remain available through 1.x.

## Run and resume

```text
livewire reproduce issue.pcap -t 192.0.2.50 -dry-run -details
livewire reproduce issue.pcap -t 192.0.2.50 -state-dir run-001 -strict-exit -run-timeout 10m
livewire live issue.pcap -t 192.0.2.50 -resume run-001 -dry-run
livewire reproduce issue.pcap -t 192.0.2.50 -resume run-001 -strict-exit -run-timeout 10m
```

Repeat the original target, replay, security, scenario, and protocol options.
The new state directory must not exist. Resume preview validates the manifest,
lock, and journal without network activity or journal mutation. Supply secrets
again through existing credential/keylog inputs. Resume never restores sockets,
TCP/TLS sequence state, authentication, cookies, or tokens.

`-concurrency` defaults to 32 for concurrent profiles and legacy `-all`;
functional replay remains sequential. `-run-timeout` includes inter-attempt
waits. Existing route timeouts still apply. `-strict-exit` requires all selected
exchanges to complete with positive matching response evidence, successful
publication, and cleanup. Otherwise existing exit conventions remain.

`-response-timeout` bounds an individual framed TCP/TLS application or UDP/ICMP
response (0 keeps protocol defaults; maximum 10 minutes). It does not replace
the whole-run budget or the raw TCP engine's bounded retransmission timers.
FTP/FTPS, SSH, transport, and wire routes reject this option. For TCP/TLS
application replay, `-expect-fault reset|timeout` requires that fault while
reading an expected response after a request was sent. All selected exchanges
must observe it and clean up successfully. Dial/handshake errors, ordinary EOF,
maintenance failures, cancellation, and journal or cleanup failures do not count.
Fault evidence never converts an incomplete exchange into a response match.
This option cannot be combined with `-strict-exit` or `-stop-when-different`.

Durable runs store a versioned manifest, hash-chained append-only journal,
immutable checkpoints, and an exclusive OS lock. Intent is flushed before sends.
Acknowledgements record progress; durable session completion resolves uncertainty.
Checkpoints contain counts and evidence references, never payloads or learned
credentials. A torn final journal line is recoverable; damaged committed records
are rejected. Required journal failures stop sends. Resume reconciles only
firewall resources carrying this run's ownership identifier.

Completed session boundaries may be skipped. Interrupted transport/wire, FTP,
SSH, MQTT, and DNP3 sessions cannot resume midway. Read-only application sessions
(HTTP GET/HEAD/OPTIONS, standard DNS TCP queries, Modbus functions 1–4) may restart
fresh. Other uncertain operations need a declared recovery contract. Resumed
timing starts a new segment and cannot claim uninterrupted timing fidelity.

## Scenario JSON

Use `-scenario scenario.json` for HTTP/1 application replay, including decrypted
TLS. Use session IDs from capture inspection and its exact `captureDigest`.
`request` is a one-based client message ordinal within the session.

```json
{
  "version": 1,
  "captureDigest": "sha256:<capture digest>",
  "steps": [
    {
      "id": "authenticate", "session": "tcp-0", "request": 1,
      "setup": true,
      "extract": [{"name": "token", "jsonPointer": "/token"}]
    },
    {
      "id": "read-state", "session": "tcp-0", "request": 2,
      "dependsOn": ["authenticate"],
      "set": {"http.header.Authorization": "Bearer ${token}"},
      "compare": {"headers": ["Content-Type"], "normalizeJSON": true,
                  "ignoreJSON": ["/generatedAt"]}
    }
  ]
}
```

`setup: true` explicitly declares a repeatable authentication/setup operation.
Do not label business writes as setup. Extract a response `header` or scalar
`jsonPointer`; bindings set existing adapter variables, including
`http.header.<name>` and `http.body`. Learned values stay in memory. Cycles,
ambiguous selectors/producers, missing requests, and missing binding producers
are rejected. Cross-session dependencies are ordered before consumers.
Same-session dependencies requiring a reply during a captured pipelined send
are currently rejected before sending.

An optional top-level `recovery` array declares read-only captured probes:

```json
"recovery": [{
  "session": "tcp-0", "request": 3,
  "field": {"header": "X-Operation-State"},
  "restartValue": "not-applied", "completeValue": "applied"
}]
```

Fresh repeatable setup runs before the probe. Probe/setup dependencies must be
within that fresh setup. The restart value must establish that the **whole
session** is safe to repeat. The completion value records unverified target-state
recovery, never a captured-response match. Unknown values or changed status stop
recovery. This operator-supplied target contract is not an exactly-once guarantee.

## Protocol session state

MQTT 3.1.1 and 5 track client-originated and broker-originated packet identifiers
independently, including QoS 1/2 acknowledgements, subscriptions, duplicate QoS
traffic, and unsolicited publishes. Keepalive PINGREQ/PINGRESP traffic is serviced
while waiting for responses and during captured timing gaps, and stops after
DISCONNECT. Runtime-generated ping replies cannot satisfy captured responses.
MQTT 5 honors Server Keep Alive, Receive Maximum, Maximum Packet Size, Maximum
QoS, and retain availability; a captured send that violates the live limits
fails explicitly. Captured topic aliases are expanded and live aliases learned
for the fresh session. Negotiated CONNACK properties may differ from the capture
and are validated as live settings. These features require captured CONNECT
context; enhanced authentication (`AUTH` or an Authentication Method) is blocked.
This is not a claim of every MQTT 5 extension or broker session-resumption mode.

DNP3 transport and application fragments are assembled separately per link,
with sequence checks and bounded buffers. Comparison uses complete logical
application messages, so the live peer may change both fragmentation layers.
Required application confirmations use the live fragment sequence and link
addresses, including unsolicited responses; captured confirmations are replaced.
Supported object layouts are parsed into indexed values. Function, indications,
object group/variation, index, count, and order remain structural checks;
lenient mode can tolerate point-value drift, while strict mode compares values.
Neither mode requires the original transport or application fragment boundaries.

DNP3 Secure Authentication functions and group 120 objects remain unsupported.
Inspection walks supported object layouts after reassembly and fails closed on
unknown qualifiers/variations, truncated objects, and incomplete fragments; it
does not certify arbitrary unknown layouts as authentication-free. The legacy
conservative byte-pattern guard can also reject a continuation that resembles
authentication. Primary data-link control requests needing a link-state adapter
are unsupported. Transport and wire modes do not add authentication support.

FTP/FTPS renegotiates passive (`PASV`/`EPSV`) and active (`PORT`/`EPRT`) data
connections and verifies transfer direction, byte count, and SHA-256. Accepted
`PROT C`/`PROT P` replies determine each transfer's protection, including switches
within one session. Rejected requests do not change protection, and a live
rejection of required `PROT P` cannot silently downgrade a transfer. Protected
capture data is decrypted offline with its matching key log and sent or compared
as plaintext over fresh verified TLS. In active mode, the FTP client remains the
TLS client even though the server initiates TCP. Unmapped or ambiguous transfers,
missing decryption material, and unsupported protection modes stop the replay.

The adaptive packet TCP engine tracks live acknowledgements, negotiated MSS and
windows, outstanding bytes, retransmissions, and FIN completion. Its bounded
flight budget is not a full congestion-control or TIME_WAIT implementation.
Captured transport and explicit wire modes preserve packet stimuli with their
own verification limits; they do not inherit application-level adaptation.

## Comparison and evidence

Plaintext and TLS requests are prepared at send time. Observation learns cookies,
MQTT identifiers, and rule-pack `copyFromLive` values even with verification off.
Comparison/correlation do not mutate state. Persistent framing retains split,
coalesced, and partial following messages. Keyed replies can arrive out of order.
Additional MQTT publishes are acknowledged while awaiting a captured response;
additional HTTP informational and DNP3 unsolicited replies are observed
separately. These extra messages are explicitly recorded as outside
captured-response comparison.

HTTP lenient comparison checks status and decoded body bytes (chunked, gzip,
deflate). Header comparison and JSON normalization/ignored fields require declared
rules. Strict comparison checks protocol content after identifier and framing
normalization, including the DNP3 and MQTT negotiation rules above.
Missing responses, capture gaps, verification off, wire execution, or failed
cleanup cannot establish a verified match. The verdict is **matched the checked
responses**. Offline `compare` uses the same adapter policies:

```text
livewire compare issue.pcap issue.actual.pcap
livewire compare issue.pcap issue.actual.pcap -strict
livewire compare issue.pcap issue.actual.pcap -scenario scenario.json
```

Packet evidence streams to a private file and is published atomically. Failed
writes/publication retain a named partial file; journals record evidence paths.
Socket replay does not fabricate wire PCAPs. Use independent capture when wire
evidence is needed. Raw packet evidence can contain credentials and is sensitive;
progress journals and shareable metadata reports exclude learned secret values.
Frames, queued replies, workers, and packet evidence have explicit bounds.

## Qualification and remaining boundaries

Use `scripts/task` for automated gates and `scripts/qualify` for evidence-bound
qualification. Tests cover process termination before/after send and after
response, uncertain-write recovery, corrupt/concurrent/changed-input resume,
state with verification off and TLS, response reset/timeout classification,
changed bodies, split/coalesced/reordered/duplicate/unsolicited/malformed traffic,
and cancellation and resource cleanup. Test code defines the scenarios; retained
passing logs establish which checks actually ran.

The 1.0 software-lab profile requires native Windows/Linux checks, independent
application peers, Linux virtual packet networking, and successful repeated
`reproduce` and `live` executions spanning two hours per required case. A smoke
run or an in-progress soak does not satisfy that gate. See
[V1_QUALIFICATION.md](https://github.com/kvmukilan/livewire/blob/v1.0.1/docs/V1_QUALIFICATION.md) for the exact scope and final evidence.
The separate physical profile retains its three-consecutive-pass, device/firmware,
physical-interface, browser, and human-pilot requirements. Unit/loopback tests,
WSL, and cross-builds do not establish physical qualification.

Remaining boundaries include arbitrary response-dependent pipelining, MQTT
enhanced authentication and unimplemented MQTT 5 extensions, unsupported DNP3
object/link-control forms and authentication, and unknown inner TLS protocols
with only limited plaintext-byte verification. HTTP/2, HTTP/3, new protocol
families, and arbitrary encrypted protocols remain outside scope. No untested
device/protocol combination is claimed qualified.
