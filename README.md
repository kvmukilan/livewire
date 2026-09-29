# Livewire

Livewire replays a recorded network exchange against a live device and reports
whether the checked responses match the capture. It is built for reproducing
field problems on SCADA and
industrial equipment (Modbus, DNP3) and also handles HTTP/1, DNS, MQTT 3.1.1/5, FTP and
FTPS, TLS, SSH, and ordinary TCP, UDP, and ICMP.

The **1.0** line adds live TCP flow control, protocol maintenance, durable replay
progress, and explicit reset/timeout observations. Its release uses
[software-lab qualification](docs/V1_QUALIFICATION.md); physical NIC/device and
human-pilot qualification remain separate. Binaries, checksums, and provenance attestations are on the
[Releases page](https://github.com/kvmukilan/livewire/releases).

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
livewire reproduce issue.pcap -t 192.168.1.50  # replay it against your device
livewire web                                   # the same workflow in a browser
```

`reproduce` asks for anything it still needs, with the right answer
pre-selected, and reports matching checked responses, differences, or an
incomplete/unverified exchange. It saves a shareable report next to the capture.

`live` and `reproduce` use fresh application sessions by default; no extra mode
choice is needed. The OS maintains TCP state and supported adapters update
application state from live responses. For stateless packet injection, use
`livewire replay -in issue.pcap -i <connection>`: it sends captured bytes in
capture order without establishing TCP/TLS sessions or checking replies.

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
livewire reproduce issue.pcap -session tcp-0 -dry-run   # preview, send nothing
livewire reproduce issue.pcap -session tcp-0 -t 192.168.1.50
livewire reproduce issue.pcap -t 192.168.1.50 -n 5                        # intermittent faults
livewire compare issue.pcap issue.actual.pcap                             # where did it diverge
```

`livewire help` lists the everyday commands. `livewire help examples`,
`livewire help troubleshoot`, and `livewire help <command>` go deeper.
Use `livewire help reliability` to choose between fresh application sessions,
captured TCP behavior, repeated attempts, and durable progress. Matching checked
responses alone does not prove that the original device fault recurred.

To check a response timeout explicitly, use
`livewire reproduce issue.pcap -t 192.168.1.50 -response-timeout 5s -expect-fault timeout`.
This applies to TCP/TLS application replay and records the fault separately from
response equivalence. MQTT keepalives and DNP3 fragment confirmations are serviced
during replay; unsupported authentication and DNP3 object layouts stop with an
explanation. See the [reliability guide](docs/RELIABILITY_IMPLEMENTATION.md) for
protocol limits and recovery rules. Historical commands and flag aliases remain
available throughout 1.x.

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
