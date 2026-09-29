# Version 1 qualification scope

Version 1 uses the `software-lab` qualification profile. The release gate binds
the reviewed evidence to the source digest and the exact Windows amd64 and Linux
amd64 executable hashes. Physical NIC/device qualification and the uncoached
human pilot remain separate work; software-lab evidence does not assert either.

The application matrix runs both `live <capture>` and `reproduce <capture>`
against independent local HTTP/1, DNS/TCP, Modbus/TCP, MQTT 3.1.1, MQTT 5, DNP3,
TLS application, FTP, explicit/implicit FTPS, and SSH peers. FTP cases exercise
uploads and downloads, with newly negotiated data connections and decrypted
capture data re-encrypted on fresh TLS sessions. MQTT peers check keepalive,
both identifier namespaces and QoS handshakes. DNP3 peers change fragmentation
and demand confirmations before sending the next fragment.

| Application cases | Independent peer checks |
|---|---|
| HTTP/1, HTTP/1 over TLS | Live login cookie, subsequent authenticated request, split replies |
| DNS/TCP, DNS over TLS | Two pipelined questions and replies returned in the opposite order |
| Modbus/TCP, Modbus over TLS | Read function/address/count and reordered transaction replies |
| MQTT 3.1.1 and MQTT 5, each plaintext and TLS | Timed keepalives, bidirectional QoS 2, packet identifiers, MQTT 5 aliases and limits |
| DNP3, DNP3 over TLS | Changed transport/application fragmentation, unsolicited traffic and confirmations |
| FTP, explicit FTPS, implicit FTPS | Fresh passive data connections, upload/download byte counts and SHA256, verified TLS identity |
| SSH | Fresh pinned host identity, explicit command outputs and exit status |

TLS soak captures use TLS 1.2 and fresh peers negotiate TLS 1.3. Captured TLS 1.3
decryption and active FTP protection/role handling have separate regression
tests; those are not additional two-hour matrix combinations.

The Linux packet matrix uses owned network namespaces and virtual Ethernet
links for DNS/UDP, generic UDP, ICMPv4/v6, adaptive TCP, captured TCP and wire
injection. Independent traffic captures and server assertions check the actual
CLI executions. Adaptive TCP executions include packet loss, delay and reordering.
These tests exercise Linux software networking, not physical devices or Windows
Npcap behavior on a physical NIC.

Each required matrix case must have successful executions spanning at least
two hours for each command. Each process repeats the exchange, checks report
evidence and server counters, and verifies released connections. Short smoke
tests cannot satisfy this gate. Reports retain the tested protocol combinations,
environment, executable hash, source digest, failures and cleanup evidence.

Additional HTTP checks exercised 840 repetitions of five captured sessions in
one CLI process for each command on each platform. Each ran for about 70 minutes
and verified 8,400 responses with fresh per-connection cookies and complete
cleanup. [Results and reproduction instructions](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/long-process-http/README.md)
retain resource observations separately from the required two-hour matrices.

The release also requires native Windows and Linux automated checks. The
existing `physical` profile retains its device, driver, browser and human-pilot
requirements. To validate the profile declared by a manifest:

```sh
go run ./scripts/qualify validate -version 1.0.0 -artifacts dist/v1.0.0 qualification/stable.json
```

All six required runs completed with zero failures and verified cleanup.
The 78 platform/suite/command/case combinations each exceeded two hours, across
16,600 CLI processes and 49,800 replay iterations. The committed
[evidence index](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/README.md)
and manifest retain exact spans, counts, hashes, and coverage limits.

## Repeat the software labs

Use the v1.0.0 source checkout and checksum-verified release binaries under
`dist/v1.0.0`. Each invocation requires a new output directory. The examples
run `live`; repeat with `-command reproduce` and a different `-out` directory
to exercise the other command. Omitting `-cases` runs the complete application
matrix. Build and run the lab executable directly so it receives cancellation.

Windows PowerShell:

```powershell
$env:GOTOOLCHAIN = 'go1.26.7'
New-Item -ItemType Directory -Path coverage -Force | Out-Null
go build -o coverage/replaylab.exe ./scripts/replaylab
if ($LASTEXITCODE -ne 0) { throw 'Replay lab build failed' }
./coverage/replaylab.exe -binary ./dist/v1.0.0/livewire-1.0.0-windows-amd64.exe -source-root . -command live -out coverage/lab-windows-live -environment 'Windows amd64 independent loopback peers' -duration 2h -interval 5s -repeat 3 -process-timeout 45s
```

Linux shell:

```sh
mkdir -p coverage
chmod +x dist/v1.0.0/livewire-1.0.0-linux-amd64
GOTOOLCHAIN=go1.26.7 go build -o coverage/replaylab ./scripts/replaylab || exit 1
./coverage/replaylab -binary "$PWD/dist/v1.0.0/livewire-1.0.0-linux-amd64" -source-root . -command live -out coverage/lab-linux-live -environment 'Linux amd64 independent loopback peers' -duration 2h -interval 5s -repeat 3 -process-timeout 45s
```

The Linux packet lab requires root, Python 3, `iproute2`, `iptables`, and
`tcpdump`, with network namespaces, virtual Ethernet, IPv6 enabled in the
namespaces, and the kernel's `netem` queue discipline available. Ensure the
Linux release binary is executable. The lab creates
its own namespaces and interfaces, removes only those resources, and runs
both commands when `--command` is omitted. For the unchanged v1.0.0 source:

```sh
sudo python3 scripts/replaylab_raw.py --binary "$PWD/dist/v1.0.0/livewire-1.0.0-linux-amd64" --output "$PWD/coverage/lab-linux-packet" --source-digest f01dd0fd79190f0e3754fdc535fe187a75ade0341e482eb24d8fa1809c7f7122 --version 1.0.0 --duration 7200 --round-gap 20 --netem
```

These commands create private captures and test key material as well as reports.
The committed qualification bundle contains only the reviewed evidence listed
by its reports; it excludes application fixtures, TLS key logs, and private keys.
Changing the source or binary requires new qualification records. The separate
[long-process HTTP instructions](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/long-process-http/README.md)
repeat the additional single-process checks.

## Replay boundaries

- Application replay uses new OS-managed TCP connections. TLS is decrypted
  offline and re-terminated with fresh keys and verified peer identity.
- The adaptive packet engine tracks live acknowledgments, negotiated MSS and
  windows, outstanding bytes and FIN completion. Its flight budget is bounded;
  it does not implement a full congestion-control algorithm or TIME_WAIT stack.
- Captured transport and wire modes deliberately preserve packet stimuli and
  have different verification limits from application replay.
- Unknown DNP3 object layouts and secure authentication are blocked when their
  safety cannot be established. Unsupported encryption requires explicit inputs
  or a safe stop. No saved socket or credential state is restored on resume.
- `-expect-fault reset|timeout` observes a response-read fault separately from
  a completed matching exchange. Device crashes or other field faults still
  require independent target-side evidence.
- Linux arm64 is cross-built. Physical NICs, actual industrial devices, Windows
  driver fault behavior, and human-pilot usability are outside this profile.
