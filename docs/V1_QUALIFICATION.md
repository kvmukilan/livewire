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

The Linux packet matrix uses owned network namespaces and virtual Ethernet
links for DNS/UDP, generic UDP, ICMPv4/v6, adaptive TCP, captured TCP and wire
injection. Independent traffic captures and server assertions check the actual
CLI executions. Packet loss, delay and reordering are separate fault checks.
These tests exercise Linux software networking, not physical devices or Windows
Npcap behavior on a physical NIC.

Each required matrix case must have successful executions spanning at least
two hours for each command. Each process repeats the exchange, checks report
evidence and server counters, and verifies released connections. Short smoke
tests cannot satisfy this gate. Reports retain the tested protocol combinations,
environment, executable hash, source digest, failures and cleanup evidence.

The release also requires native Windows and Linux automated checks. The
existing `physical` profile retains its device, driver, browser and human-pilot
requirements. To validate the profile declared by a manifest:

```sh
go run ./scripts/qualify validate -version 1.0.0 -artifacts dist/v1.0.0 qualification/stable.json
```

Qualification is pending until the committed manifest and its referenced
evidence validate. The release notes and final evidence record state the
completed checks and remaining coverage limits.

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
