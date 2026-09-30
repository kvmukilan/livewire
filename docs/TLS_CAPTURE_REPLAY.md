# TLS directly from a capture

```sh
livewire check issue.pcapng -details
livewire live issue.pcapng -t device.example:443
```

This creates a fresh TCP connection and a fresh TLS session. The operating
system maintains TCP state; the TLS stack negotiates new keys, validates the
server certificate and closes the owned connection when the attempt finishes.
No HTTP file, generated request or external keylog is required for a handshake.

What can run depends on what the capture contains:

| Capture input | What Livewire executes | Report boundary |
|---|---|---|
| Complete public ClientHello, no embedded or supplied TLS secrets | Fresh TLS handshake using captured SNI, ALPN and supported TLS 1.2/1.3 offers | Handshake completed; application replay incomplete, unverified and unmatched |
| PCAPNG containing matching TLSK Decryption Secrets Blocks | Recover captured application messages, then replay them through a fresh TLS session and supported adapter | Application responses are compared according to the selected verification policy |
| Capture plus explicit `-keylog session.keys` | Same application replay; explicit keylog takes priority over embedded secrets | Same application verification rules |

Embedded secrets are still secrets. They are used in memory from the immutable
capture snapshot and excluded from reports. An external file or environment
variable is never consumed merely because it exists. Malformed embedded NSS
entries, conflicting keys, missing matching session secrets and decryption
errors fail before sending; they do not silently become a handshake-only run.
The original PCAPNG may contain credentials and must be handled as sensitive.

For a private CA, add `-ca device-ca.pem`. Handshake-only replay uses captured
SNI for certificate verification; `-server-name device.example` explicitly
overrides it. Without captured SNI, the target hostname or IP is verified.
The target remains explicitly selected with `-t` in scripts. Selecting one
exchange from a mixed capture uses `-session <id>`, as shown by `check -details`.

```sh
livewire live issue.pcap -t 192.0.2.20:443 -ca device-ca.pem -n 5 -gap 1s
livewire live issue.pcap -t device.example:443 -keylog session.keys
```

For Modbus/TCP carried over TLS, a PCAPNG with matching embedded secrets needs
no separate keylog file. For example, with a TLS service listening on port 1502:

```sh
livewire live modbus-tls.pcapng -t device.example:1502
```

Livewire recovers the captured Modbus requests, opens fresh verified TCP/TLS
state, tracks live transaction identifiers and compares the checked responses.
With an encrypted-only capture and no secrets, the same command establishes
only the fresh TLS handshake; it does not recover or send Modbus function
codes, register addresses or values. Application replay remains incomplete and
unverified. Add `-ca device-ca.pem` for a private CA. TLS client-certificate
authentication and the full Modbus Security standard are not claimed here.
A peer requiring unsupported authentication can reject even the handshake.

Each attempt establishes new state. Handshake-only execution sends no captured
ciphertext or application bytes. It preserves available public SNI and ALPN,
and filters offered versions to TLS 1.2/1.3. The report records captured and
fresh public ClientHello metadata, negotiated version/cipher/ALPN, peer identity
verification and cleanup. Exact ClientHello fingerprints, cipher offers,
session resumption, PSKs, early data and captured timing are not reproduced.
Old-only TLS offers, ECH, incomplete/malformed ClientHello, TCP gaps, conflicting
retransmissions and ambiguous selected exchanges are refused before dialing.
Opening ClientHello parsing is bounded to 256 KiB; the ALPN extension to 4096 bytes.

`handshakeCompleted: true` does **not** mean the application issue reproduced.
Without secrets, `completed`, `applicationReplayCompleted`, `verified` and
`matched` remain false, with zero application request/response comparisons.
The default exit can be successful for this bounded operation; `-strict-exit`
returns failure for incomplete replay. `-strict`, response fault checks,
application variables/rules, scenarios, timing and durable resume require
application replay with matching secrets. `-timeout` and cancellation bound
the fresh connection and handshake; report publication never overwrites an
existing output.

TLS encryption intentionally prevents new session keys from recovering old
application plaintext. A fresh handshake can reproduce negotiation, trust,
ALPN and connection failures; reproducing an encrypted application exchange
requires matching captured secrets. FTPS still requires recoverable control
and data exchanges, and SSH still requires its explicit authentication and
command inputs. They do not inherit the direct TLS handshake fallback.

For stateless packet injection, `livewire reproduce issue.pcap -i <interface>`
sends the captured frames without TLS negotiation or response verification.
That remains a separate operation from a live TLS session.
