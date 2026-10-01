# TLS directly from a capture

## Record TLS applications into one file

```sh
livewire ifaces
livewire capture -i <interface> -o issue.pcapng -tls -- <application> [args...]
livewire check issue.pcapng -details
livewire live issue.pcapng -t device.example:1502
```

`capture -tls` starts recording before launching the application. It supplies
`SSLKEYLOGFILE` only to that process and its children, collects exported NSS
secrets, matches them to complete supported ClientHellos in captured TCP streams,
and embeds the matching entries as PCAPNG TLSK Decryption Secrets Blocks. A
successful recording leaves one capture, with no separate key-log file to manage.
`live` then decrypts the recorded messages and executes them through a **fresh
verified TLS connection**, including non-HTTP protocols such as Modbus, DNS/TCP,
MQTT and DNP3. `reproduce` continues to send packets statelessly.

The original application must cooperate by exporting its session keys:

| Recording application | Requirement |
|---|---|
| Python 3.8+ client using `ssl.create_default_context()` | Honors `SSLKEYLOGFILE` when key logging is supported by its SSL implementation; exercised by the native recording test |
| curl | A build with a TLS backend supporting `SSLKEYLOGFILE`; check `curl -V`. Support varies by backend/build; the Windows bundled curl must not be assumed compatible |
| Firefox / Chromium-based browser | A fresh process/profile and supported key-export configuration; an already-running browser does not inherit the new environment. HTTP/2/3 application replay is still unsupported |
| Go or another custom application | Explicitly connect its TLS key-export callback (Go: `tls.Config.KeyLogWriter`) to `SSLKEYLOGFILE`; the environment variable alone does not enable logging in every TLS library |
| Existing services, remote endpoints, or applications without key export | This launcher cannot collect their secrets automatically. Record on a cooperative endpoint or supply secrets acquired during the original exchange |

For a compatible curl build, an HTTP/1 example is:

```sh
livewire capture -i <interface> -o https.pcapng -tls -- curl --http1.1 https://device.example/health
```

For a Python Modbus-over-TLS client that uses `ssl.create_default_context()`:

```sh
livewire capture -i <interface> -o modbus.pcapng -tls -- python modbus_client.py
livewire live modbus.pcapng -t device.example:1502
```

Use an interface that sees the complete original connection, starting before
its handshake. Capture records the selected interface, so it can include
unrelated traffic from other applications. `check -details` lists the exchanges;
use `live issue.pcapng -session <id> -t <target>` to select the intended one.
Only the launched application's matching exported secrets are embedded.

The command stops after the launched application exits and a
short packet drain. It launches the supplied executable directly, without a
shell; put Livewire options before `--` and application arguments after it.
Capture needs the usual Windows/Npcap or Linux raw-packet privileges. If you
run Livewire as Administrator or with `sudo`, the launched application also
runs with that account's privileges. Prefer a short-lived client running in the
foreground; do not detach/daemonize it or delegate to an existing background
service. Finish the client normally to finalize a complete recording.

`-duration`, `-n` and Ctrl-C stop recording and terminate owned child processes.
If this interrupts the application, or capture/key collection fails, Livewire
returns nonzero and prints the path of an explicitly **partial** PCAPNG. That
file can contain useful packets and matching secrets; inspect it before replay.
It never overwrites the requested output or labels an interrupted recording
complete. TLS recording is bounded to 64 MiB of packet data, 1,000,000 packets
and a 1 MiB exported key log. Long captures must be split into shorter exchanges.
Ordinary `capture` without `-tls` keeps its original packet-only PCAP workflow.

The temporary key directory and final artifact use owner-only permissions
(protected DACLs on Windows). Unmatched secrets are omitted, the temporary log
is removed on normal/error/cancellation cleanup, and secrets are not included
in Livewire reports. The launched application's own output is inherited, so
its logging remains its responsibility. Forced machine/process termination can
leave private temporary files; these and the resulting PCAPNG remain sensitive.
Neither recording nor replay uploads the capture or secrets.

Embedding secrets is not a guarantee that every captured exchange can replay.
Use `check -details` to select the desired session. Capture gaps, unsupported
TLS suites or inner protocols, mTLS, expired application credentials, and
missing device setup retain their existing boundaries. A private CA may still
need `-ca`; fresh authentication may still need current credentials. This
feature cannot retroactively recover secrets from an old encrypted-only PCAP.

Client behavior and the file format are documented by
[Python](https://docs.python.org/3/library/ssl.html#ssl.create_default_context),
[curl](https://curl.se/docs/manpage.html#SSLKEYLOGFILE), and
[Wireshark](https://wiki.wireshark.org/TLS/#embedding-decryption-secrets-in-a-pcapng-file).

## Replay an existing capture

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
