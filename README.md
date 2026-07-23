# Livewire

Livewire v0.5.0 is a protocol-adaptive PCAP replay platform for reproducing
network and application failures against a live endpoint or through a device
under test (DUT). Every captured frame receives an explicit replay lane:
semantic, stateful transport, wire, or blocked. Livewire never silently drops a
protocol and never reports more fidelity than it delivered.

The project is licensed under the [MIT License](LICENSE).

## Start here

### Windows release

1. Download and extract `livewire-0.5.0-windows-amd64.zip`.
2. Open PowerShell with **Run as administrator** in the extracted folder.
3. Prepare Npcap and WinDivert:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\setup-windows.ps1 -ExeDirectory .
```

4. List interfaces and run a capture:

```powershell
.\livewire.exe ifaces
$Iface = '\Device\NPF_{PASTE_GUID_HERE}'
.\livewire.exe reproduce .\issue.pcap -to 192.168.1.50 -on $Iface
```

See [WINDOWS-QUICKSTART.md](WINDOWS-QUICKSTART.md) for copy-paste examples of
`live -all`, timing/transport replay, reports, and manual `rstdrop`.

### Linux release

```sh
chmod +x ./livewire
sudo ./livewire ifaces
sudo ./livewire reproduce issue.pcap --to 192.168.1.50 --on eth0
```

### Which command should I use?

| Goal | Command |
|---|---|
| Check whether a PCAP is replayable without transmitting | `livewire analyze` |
| Reproduce an issue against one real target | `livewire reproduce` |
| Debug one or all TCP flows at a low level | `livewire live` |
| Replay both sides through a firewall, proxy, NAT, or DUT | `livewire lab` |
| Replay TLS with a matching key log | `livewire tls-replay` |
| Replay explicit commands over a fresh SSH connection | `livewire ssh-replay` |
| Open the local dashboard | `livewire web` |

Start with `reproduce -profile functional`. Use `timing`, `transport`, or
`wire` only when the issue depends on that behavior.

## What v0.5.0 adds

- Transport-neutral traces and replay plans covering TCP, stateful UDP,
  ICMPv4/ICMPv6 Echo, IPv4/IPv6 fragments, and explicit raw-frame lanes.
- Four fidelity profiles: `functional`, `timing`, `transport`, and `wire`.
- Built-in application adapters for HTTP/1.0 and HTTP/1.1, DNS over UDP/TCP,
  MQTT 3.1.1/5.0, Modbus/TCP, and DNP3.
- Honest TLS and SSH retermination paths. TLS requires a matching key log; SSH
  requires credentials and an explicit command script. Ciphertext alone is a
  blocker.
- A safe JSON adapter rule-pack format for proprietary framed protocols.
- A two-interface `lab` runner with deterministic delay, jitter, drop,
  duplication, reorder, rate, and MTU scenarios plus dual-interface PCAPNG
  evidence.
- An offline embedded dashboard with plan compilation, coverage, one-sided and
  two-sided execution, structured progress, cancellation, validation, and
  artifact downloads, plus redacted metadata-only support bundles.

## Build

Go 1.25 or newer is required.

For a complete copy-paste walkthrough from installation to live traffic, use
the [Windows one-sided guide](DOCUMENTATION.md#2-windows-zero-to-one-sided-live-replay),
the [Linux one-sided guide](DOCUMENTATION.md#3-linux-zero-to-one-sided-live-replay),
or the two-sided DUT guides for
[Windows](DOCUMENTATION.md#5-windows-two-sided-replay-through-a-dut) and
[Linux](DOCUMENTATION.md#6-linux-two-sided-replay-through-a-dut).

```sh
go build -o livewire ./cmd/livewire
```

On Windows the output is `livewire.exe`. Live packet I/O needs root or
Administrator privileges; Windows additionally needs Npcap, and TCP RST
suppression needs WinDivert. See [SETUP.md](SETUP.md).

## Start with a plan

Analyze a capture without opening an interface:

```sh
livewire analyze -in trace.pcap -profile functional -json plan.json
```

The coverage matrix identifies every session or raw lane, its protocol,
selected driver, adapter, achievable fidelity, warnings, and blockers. A plan is
invalid if any captured frame is missing or represented twice.

## One-sided guided replay

Use `reproduce` when the captured client should talk to a live target:

```sh
sudo ./livewire reproduce trace.pcap --to 192.0.2.50 --on eth0
```

Common policies:

```sh
# preserve captured concurrency and timing
sudo ./livewire reproduce trace.pcap --to 192.0.2.50 --on eth0 --profile timing

# preserve transport behavior where it remains valid
sudo ./livewire reproduce trace.pcap --to 192.0.2.50 --on eth0 --profile transport

# explicit frame injection; no live adaptation claim
sudo ./livewire reproduce trace.pcap --to 192.0.2.50 --on eth0 --profile wire

# dynamic substitutions
sudo ./livewire reproduce trace.pcap --to 192.0.2.50 --on eth0 \
  -set http.host=device.example -set mqtt.client_id=replay-client

# proprietary protocol adapter
sudo ./livewire reproduce trace.pcap --to 192.0.2.50 --on eth0 \
  -rules vendor-protocol.json
```

The run writes a JSON report and actual-traffic evidence. Secret-like variables
such as passwords, tokens, authorization values, credentials, and key logs are
redacted from reports and logs.

## Two-sided DUT replay

Use `lab` when both captured endpoints must be simulated through a firewall,
NAT, proxy, or other DUT:

```sh
sudo ./livewire lab -in trace.pcap \
  -client-iface eth1 -server-iface eth2 \
  -topology topology.json -scenario faults.json
```

Minimal topology:

```json
{
  "version": 1,
  "client": {"interface": "eth1", "mtu": 1500},
  "server": {"interface": "eth2", "mtu": 1500},
  "mappings": [
    {
      "role": "client",
      "captured": {"ip": "192.0.2.10", "port": 40000},
      "live": {"ip": "10.10.0.10", "port": 40000}
    },
    {
      "role": "server",
      "captured": {"ip": "192.0.2.20", "port": 502},
      "live": {"ip": "10.20.0.20", "port": 502}
    }
  ]
}
```

Example deterministic fault scenario:

```json
{
  "version": 1,
  "seed": 42,
  "rules": [
    {
      "name": "slow server replies",
      "match": {"direction": "server-to-client", "start": "500ms"},
      "action": {"delay": "40ms", "jitter": "5ms", "drop": 0.01}
    }
  ]
}
```

Lab evidence is one PCAPNG with separate client-side and server-side interface
descriptions. The report records requested and achieved fidelity, scenario seed,
per-session drivers and verdicts, NAT/PAT and TCP sequence-clock transformations,
latency, loss, duplication, reorder, resets, and known limitations.

Functional/timing/transport lab actors wait for preceding traffic to cross the
DUT, so a delayed or dropped request cannot receive a prerecorded response.
TCP actors learn sequence translation from observed traffic and repair later ACK
and SACK state, including a sequence-translating proxy path.
Topology gateways can resolve missing MAC overrides, and topology MTUs are
enforced during injection. Wire mode keeps unconditional captured timing.

Create a safely shareable, metadata-only support archive without embedding
packet payloads:

```sh
livewire bundle -report trace.report.json \
  -evidence trace.actual.pcapng -out trace.support.zip
```

## TLS replay

TLS captures need the matching NSS-style key log. Livewire decrypts supported
TLS 1.2/1.3 AEAD records, prepares the inner protocol, and opens a fresh TLS
connection with certificate verification enabled:

```sh
livewire tls-replay -in trace.pcap -keylog sslkeys.log \
  -target device.example:443 -server-name device.example \
  -report trace.tls.report.json
```

`-insecure-skip-verify` is an explicit lab-only override. Key-log contents are
never written to reports or logs. The report includes a complete capture
coverage plan: the selected TLS lane is semantic and every unrelated lane is
an explicit blocker rather than a silent omission.

## SSH replay

SSH ciphertext does not reveal the captured commands. Bind an explicit
command/expect script to the captured SSH lane, authenticate a fresh connection,
and optionally pin the target's OpenSSH public host key:

```sh
livewire ssh-replay -in trace.pcap -target device.example:22 \
  -user lab -key id_ed25519 -host-key device_host_key.pub \
  -cmd 'show version' -expect 'Version' \
  -report trace.ssh.report.json
```

Passwords, usernames, private keys, command text, expected text, and response
bodies are excluded from reports and job/CLI logs. Command evidence is
represented by output length and SHA-256 only. Without `-host-key`, the observed
key is recorded by fingerprint and the missing identity pin is an explicit
limitation.

## Dashboard

```sh
livewire web -addr 127.0.0.1:8080 -dir ./captures
```

Open `http://127.0.0.1:8080`. The UI is embedded in the binary and has no
runtime web dependencies. Keep it bound to localhost unless an isolated lab
network and external access controls are in place.

## Commands

| Command | Purpose |
|---|---|
| `analyze` | compile the protocol coverage and fidelity plan offline |
| `reproduce` | guided protocol-adaptive replay against one live endpoint |
| `lab` | coordinated two-sided replay through a DUT |
| `bundle` | build a redacted report archive with digest-only evidence references |
| `tls-replay` | decrypt using a key log and reterminate a fresh TLS session |
| `ssh-replay` | bind a command/expect script to a captured SSH lane and reterminate it |
| `live` | advanced stateful TCP replay controls |
| `info` | inspect PCAP/PCAPNG structure and protocols |
| `ifaces` | list capture/replay interfaces and capabilities |
| `capture` | record traffic into PCAP |
| `rewrite` | static address, port, TTL, VLAN, and sequence edits |
| `replay` | explicit stateless frame injection |
| `web` | serve the embedded local dashboard |
| `convert` | convert PCAPNG to classic PCAP |

Run `livewire <command> -h` for all flags.

## Fidelity contract and limits

- `functional` selects semantic adapters when available, otherwise adaptive
  stateful transport.
- `timing` adds captured inter-session concurrency and event timing.
- `transport` preserves segmentation, flags, retransmissions, ordering, and
  transport timing where a live peer permits it.
- `wire` emits frames at captured timing and makes no adaptation or response
  equivalence claim.

When verification is off, a completed exchange is reported as unverified;
zero recorded mismatches is never converted into a “same as recording” claim.

Unknown protocols remain visible as wire lanes. Multicast and unsolicited
traffic use timing/wire replay unless an adapter can correlate a live response.
Fresh cryptographic state cannot be reconstructed from ciphertext: provide TLS
session secrets, SSH credentials and commands, or a purpose-built adapter.

High-scale traffic generation, HTTP/2 and HTTP/3, distributed replay agents,
and automatic recovery of encrypted application data without secrets are not
part of v0.5.0.

## Release verification

```sh
go mod verify
go test ./...
go vet ./...
go test -race ./...
```

Local release artifacts can be built with `scripts/release.ps1`; it produces
Linux amd64/arm64 and Windows amd64 binaries plus SHA-256 checksums under
`dist/v0.5.0/`. Hardware smoke testing remains required before using a release
candidate on production-adjacent networks.

Windows users should download `livewire-0.5.0-windows-amd64.zip`, extract it,
and follow [WINDOWS-QUICKSTART.md](WINDOWS-QUICKSTART.md). The ZIP includes
`livewire.exe` and `setup-windows.ps1`; the helper checks Npcap and downloads and
copies the required WinDivert files beside the executable.
