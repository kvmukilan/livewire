# Livewire

Livewire replays a recorded network exchange against a live device and tells
you, in plain language, whether the device behaved the same way it did when the
capture was taken. It is built for reproducing field problems on SCADA and
industrial equipment (Modbus, DNP3) and also handles HTTP, DNS, MQTT, FTP and
FTPS, TLS, SSH, and ordinary TCP, UDP, and ICMP.

The current line is **0.9**, a release candidate; **0.8.0** is the stable
download. Binaries, checksums, and provenance attestations are on the
[Releases page](https://github.com/kvmukilan/livewire/releases).

## Install

Copy-paste steps for a fresh Windows or Linux machine are in
[docs/SETUP.md](docs/SETUP.md). In short:

- **Windows**: download the release ZIP, verify it against `SHA256SUMS`, unzip,
  install [Npcap](https://npcap.com/), and run `setup-windows.ps1` once as
  Administrator.
- **Linux**: download the `linux-amd64` or `linux-arm64` binary, make it
  executable, and run it with `sudo` or grant it `cap_net_raw,cap_net_admin`.

Socket-based replays (HTTP, TLS, FTP, SSH) need no packet driver and no
elevation.

## Use

```sh
livewire check issue.pcap                      # what is in the capture, can it be replayed
livewire reproduce issue.pcap -t 192.168.1.50  # replay it against your device
livewire web                                   # the same workflow in a browser
```

`reproduce` asks for anything it still needs, with the right answer
pre-selected, and ends with one verdict: same as the recording, different, or
did not complete. It saves a shareable report next to the capture.

When you need to be precise about what is replayed:

```sh
livewire check issue.pcap -details                                        # list the sessions
livewire reproduce issue.pcap -mode application -session tcp-0 -dry-run   # preview, send nothing
livewire reproduce issue.pcap -mode application -session tcp-0 -t 192.168.1.50
livewire reproduce issue.pcap -t 192.168.1.50 -n 5                        # intermittent faults
livewire compare issue.pcap issue.actual.pcap                             # where did it diverge
```

`livewire help` lists the everyday commands. `livewire help examples`,
`livewire help troubleshoot`, and `livewire help <command>` go deeper.

## Documentation

| Read this | For |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | installing on a new Windows or Linux machine |
| [docs/COMMANDS.md](docs/COMMANDS.md) | every command and option, and what the verdicts mean |
| [docs/WORKFLOW.md](docs/WORKFLOW.md) | replay intent, session selection, and offline preview |
| [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md) | the full operator guide: walkthroughs, protocols, fidelity, troubleshooting |
| [docs/WINDOWS-QUICKSTART.md](docs/WINDOWS-QUICKSTART.md) | advanced Windows examples |
| [docs/PRODUCTION.md](docs/PRODUCTION.md) | diagnostics, recovery, supported platforms, and stable qualification |
| [docs/RELEASE_AUDIT.md](docs/RELEASE_AUDIT.md) | what the current release candidate has and has not been checked against |
| [SECURITY.md](SECURITY.md) | handling captures, credentials, and reports |
| [CHANGELOG.md](CHANGELOG.md) | what changed in each release |
| [CONTRIBUTING.md](CONTRIBUTING.md) | building, testing, and releasing from source |

Livewire is licensed under the [MIT License](LICENSE).
