# Livewire

Livewire replays a recorded network exchange against a live device and reports
whether the checked responses match the capture. It is built for reproducing
field problems on SCADA and
industrial equipment (Modbus, DNP3) and also handles HTTP/1, DNS, MQTT 3.1.1/5, FTP and
FTPS, TLS, SSH, and ordinary TCP, UDP, and ICMP.

The **1.x** line includes live TCP flow control, protocol maintenance, durable replay
progress, and explicit reset/timeout observations. Its release uses
[software-lab qualification](docs/V1_QUALIFICATION.md); physical NIC/device and
human-pilot qualification remain separate. Binaries, checksums, and provenance attestations are on the
[Releases page](https://github.com/kvmukilan/livewire/releases).

The [website and version-pinned guides](https://kvmukilan.github.io/livewire/)
cover installation, the two replay workflows and secure captures.

## Install

Copy-paste steps for a fresh Windows or Linux machine are in
[docs/SETUP.md](docs/SETUP.md). In short:

- **Windows**: download the release ZIP, verify it against `SHA256SUMS`, unzip,
  install [Npcap](https://npcap.com/), and run `setup-windows.ps1` once as
  Administrator.
- **Linux**: download the `linux-amd64` or `linux-arm64` binary, make it
  executable, and run it with `sudo` or grant it `cap_net_raw,cap_net_admin`.

Socket-based application replays (HTTP, DNS/TCP, MQTT, Modbus, DNP3, TLS, FTP,
and SSH) need no packet driver and no elevation. They create fresh connections;
captured TCP state and TLS ciphertext are not reused as a live session.

## Use

```sh
livewire check issue.pcap                      # what is in the capture, can it be replayed
livewire live issue.pcap -t 192.168.1.50       # fresh application sessions and live responses
livewire reproduce issue.pcap -i eth0          # stateless replay of the recorded packets
livewire web                                   # the same workflow in a browser
```

**`live` is stateful.** It creates fresh application connections, lets the OS
maintain TCP state, and adapts supported protocol state to live responses. It
reports checked response matches, differences, or incomplete exchanges, and
saves a shareable report next to the capture.

**`reproduce` is stateless.** It sends the recorded frames in capture order,
including both recorded directions, using captured timing or an explicit rate.
It does not establish TCP/TLS sessions or check responses. Use `-dry-run` to
preview and `-report packets.json` to retain transmission counts. `replay` is
a compatibility alias for this same packet sender. Neither primary command
requires a mode choice.

**Upgrading from 1.0.x:** application commands formerly written as
`reproduce capture.pcap -t ...` must use `live capture.pcap -t ...` in 1.1.
Application-only options on `reproduce` are rejected with migration guidance.
See the [command migration](docs/V1_FOLLOWUP.md).

For a TLS capture, use
`livewire live tls.pcap -keylog sslkeys.log -t device.example:443`.
The matching key log recovers the original requests; Livewire sends them over
a new certificate-verified TLS connection. A capture containing only encrypted
records cannot reveal those requests without matching decryption material.
Private CAs use `-ca device-ca.pem`; `-server-name` sets the verified server name
when connecting by IP. `live -in` with explicit secure inputs such as `-keylog`
also uses fresh sessions. Without secure inputs, historical `live -in` retains
its original TCP simulation/packet controls.

When you need to be precise about what is replayed:

```sh
livewire check issue.pcap -details                                        # list the sessions
livewire live issue.pcap -session tcp-0 -dry-run   # preview, send nothing
livewire live issue.pcap -session tcp-0 -t 192.168.1.50
livewire live issue.pcap -t 192.168.1.50 -n 5                        # intermittent faults
livewire compare issue.pcap issue.actual.pcap                             # where did it diverge
```

`livewire help` lists the everyday commands. `livewire help examples`,
`livewire help troubleshoot`, and `livewire help <command>` go deeper.
Use `livewire help reliability` to choose between fresh application sessions,
captured TCP behavior, repeated attempts, and durable progress. Matching checked
responses alone does not prove that the original device fault recurred.

To check a response timeout explicitly, use
`livewire live issue.pcap -t 192.168.1.50 -response-timeout 5s -expect-fault timeout`.
This applies to TCP/TLS application replay and records the fault separately from
response equivalence. MQTT keepalives and DNP3 fragment confirmations are serviced
during replay; unsupported authentication and DNP3 object layouts stop with an
explanation. See the [reliability guide](docs/RELIABILITY_IMPLEMENTATION.md) for
protocol limits and recovery rules. Historical command names and other flag
aliases remain available; application-style `reproduce` calls require the
explicit 1.1 migration described above.

## Documentation

| Read this | For |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | installing on a new Windows or Linux machine |
| [docs/COMMANDS.md](docs/COMMANDS.md) | every command and option, and what the verdicts mean |
| [docs/WORKFLOW.md](docs/WORKFLOW.md) | replay intent, session selection, and offline preview |
| [docs/RELIABILITY_IMPLEMENTATION.md](docs/RELIABILITY_IMPLEMENTATION.md) | durable runs, application state, response evidence, and current limits |
| [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md) | the full operator guide: walkthroughs, protocols, fidelity, troubleshooting |
| [docs/WINDOWS-QUICKSTART.md](docs/WINDOWS-QUICKSTART.md) | advanced Windows examples |
| [docs/PRODUCTION.md](docs/PRODUCTION.md) | diagnostics, recovery, supported platforms, and stable qualification |
| [docs/RELEASE_AUDIT.md](docs/RELEASE_AUDIT.md) | what the current release candidate has and has not been checked against |
| [SECURITY.md](SECURITY.md) | handling captures, credentials, and reports |
| [CHANGELOG.md](CHANGELOG.md) | what changed in each release |
| [CONTRIBUTING.md](https://github.com/kvmukilan/livewire/blob/v1.0.1/CONTRIBUTING.md) | building, testing, and releasing from source |

Livewire is licensed under the [MIT License](LICENSE).
