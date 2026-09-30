# Livewire Operator Guide

This guide describes the upcoming 1.1.0 command contract. Downloads still
provide 1.0.1 until release promotion; use the
[1.0.1 operator guide](https://github.com/kvmukilan/livewire/blob/v1.0.1/docs/DOCUMENTATION.md)
with that binary. Start with [Replay workflow](WORKFLOW.md)
for fresh live sessions, session selection, and offline preview.

This guide starts with commands that work. Use the Windows or Linux walkthrough
to go from a source checkout and a PCAP to a live replay. The protocol and
reference material comes afterward.

Livewire has two different live-replay topologies:

```text
One-sided:  Livewire host  ----------------------> live target
             captured client is simulated          real server/device

Two-sided:  Livewire client NIC --> DUT --> Livewire server NIC
             captured client actor       captured server actor
```

The two primary commands have different purposes: `live <capture>` plays
application requests through fresh stateful connections, while
`reproduce <capture> -i <interface>` sends the recorded packets statelessly.
Neither needs a mode flag. `replay` remains a stateless compatibility alias.
Use `lab` when the DUT must sit between two simulated endpoints.

In 1.0.x, `reproduce` also invoked the application workflow. From 1.1 onward,
replace it with `live` in application scripts. Stateless reproduction does not
adapt addresses, sequence numbers, TLS records or application identifiers and
never claims response equivalence. See [command migration](V1_FOLLOWUP.md).

## Quick navigation

| I want to... | Read |
|---|---|
| Run the downloaded Windows EXE | [Windows quick start](WINDOWS-QUICKSTART.md) |
| Install/build on Windows | [Windows one-sided guide](#2-windows-zero-to-one-sided-live-replay) |
| Install/build on Linux | [Linux one-sided guide](#3-linux-zero-to-one-sided-live-replay) |
| Replay through a DUT on Windows | [Windows DUT guide](#5-windows-two-sided-replay-through-a-dut) |
| Replay through a DUT on Linux | [Linux DUT guide](#6-linux-two-sided-replay-through-a-dut) |
| Add delay, loss, duplication, or reorder | [Deterministic faults](#7-add-deterministic-dut-faults) |
| Replay TLS or SSH | [TLS and SSH captures](#10-tls-and-ssh-captures) |
| Fix a setup/runtime error | [Troubleshooting](#14-troubleshooting) |
| Look up a command | [Command reference](#15-command-reference) |

For the common case—`livewire.exe` already downloaded, one PCAP, one real
target—use [WINDOWS-QUICKSTART.md](WINDOWS-QUICKSTART.md) instead of reading
this guide from beginning to end.

## 1. Before you transmit

- Use an isolated lab and a target you are authorized to test. A capture can
  contain destructive application operations.
- Use positional `live <capture>` for fresh application sessions or `reproduce`
  for stateless packets; neither needs a mode flag. Add `-session <id> -dry-run`
  to preview the intended exchange before execution. Application pacing can use
  the `timing` profile for supported plaintext and TLS protocols.
- Capture both directions, without snap-length truncation, and include the TCP
  handshake when possible.
- For packet-level one-sided replay, `-t` is an IP and the port comes from the
  capture. For TLS, FTPS, and SSH, `-t` may be `host:port`; Livewire opens a
  fresh OS-level secure connection and verifies peer identity by default.
- Live packet operations require an Administrator PowerShell on Windows or
  `sudo` on Linux. `check` is offline and needs no elevation.

The examples use these values. Replace them with values from your lab:

| Value | Example | Meaning |
|---|---|---|
| Capture | `issue.pcap` | Original PCAP or PCAPNG |
| Target | `192.168.1.50` | Live one-sided target IP |
| Windows interface | `\Device\NPF_{...}` | Exact Npcap device from `ifaces` |
| Linux interface | `enp3s0` | Interface that reaches the target |

## 2. Windows: zero to one-sided live replay

### Fast path: `livewire.exe` already exists

For the normal Windows workflow, use the shorter
[Windows live replay setup](SETUP.md#windows-live-replay). It provides
copy-paste commands to:

1. detect Npcap and install it only if missing;
2. detect or copy the two required WinDivert files;
3. select the exact Npcap interface;
4. inspect the capture, select sessions, and choose application or transport intent;
5. use `rstdrop` only for an external packet injector.

Stateful packet routes in `live` already manage RST suppression. A separate
`rstdrop` process is not needed alongside them. Stateless `reproduce` sends
captured frames without maintaining a peer TCP session.

Minimal example from an Administrator PowerShell:

```powershell
.\livewire.exe ifaces
$Iface = '\Device\NPF_{PASTE_GUID_HERE}'
.\livewire.exe live .\issue.pcap -i $Iface -t 192.168.1.50
```

The remaining Windows sections cover building from source, capture creation,
offline plan inspection, custom output paths, and advanced fidelity profiles.

### 2.1 Install the runtime requirements

1. Install Go 1.26.7 or newer if you are building from source. Release
   artifacts use the exact Go 1.26.7 maintenance toolchain. Use the official
   [Go installer](https://go.dev/doc/install).
2. Install [Npcap](https://npcap.com/). Select **Install Npcap in WinPcap
   API-compatible Mode**. Npcap provides capture, frame injection, ARP, and NDP.
3. Download the 64-bit binary distribution of
   [WinDivert](https://reqrypt.org/windivert.html). Livewire uses it temporarily
   to stop the Windows TCP stack from resetting a replayed connection.
4. Open PowerShell with **Run as administrator**.

Start in the Livewire source directory:

```powershell
Set-Location C:\path\to\livewire

go version
go mod verify

New-Item -ItemType Directory -Force .\bin, .\captures, .\runs, .\lab | Out-Null
go build -trimpath -o .\bin\livewire.exe .\cmd\livewire
.\bin\livewire.exe version
```

If you received a release binary, place it at `bin\livewire.exe` and skip the
Go build. Release binaries are published only on the
[Releases page](https://github.com/kvmukilan/livewire/releases); the
repository keeps just each release's checksum manifest under `dist/`.
[SETUP.md](SETUP.md) has the download and verification commands.

Copy the WinDivert files beside `livewire.exe`. This example matches the
official WinDivert 2.2.2 binary archive layout:

```powershell
$WinDivertRoot = 'C:\Tools\WinDivert-2.2.2-A'
Copy-Item "$WinDivertRoot\x64\WinDivert.dll" .\bin\
Copy-Item "$WinDivertRoot\WinDivert64.sys" .\bin\

Get-Service npcap
Get-Item .\bin\livewire.exe, .\bin\WinDivert.dll, .\bin\WinDivert64.sys
```

WinDivert loads its signed driver on demand and requires Administrator
privileges. Do not copy a 32-bit DLL beside the 64-bit Livewire executable.

### 2.2 Put the capture in the workspace

If you already have a capture:

```powershell
$Capture = Join-Path $PWD 'captures\issue.pcap'
Copy-Item 'C:\path\to\issue.pcap' $Capture
```

To create a capture with Livewire instead, first list the Npcap devices:

```powershell
.\bin\livewire.exe ifaces
```

Copy the complete `\Device\NPF_{GUID}` value for the adapter connected to the
lab. PowerShell single quotes preserve it exactly:

```powershell
$Iface = '\Device\NPF_{REPLACE_WITH_THE_GUID_FROM_IFACES}'
$Capture = Join-Path $PWD 'captures\issue.pcap'

.\bin\livewire.exe capture -i $Iface -o $Capture -duration 30s
```

Generate the application exchange from another terminal or device during those
30 seconds. `capture` records the whole interface, so use an isolated adapter to
avoid unrelated traffic.

### 2.3 Select the target and verify the route

```powershell
$TargetIP = '192.168.1.50'
.\bin\livewire.exe ifaces
Test-NetConnection -ComputerName $TargetIP -InformationLevel Detailed
```

Set `$Iface` to the exact Npcap device printed above. Do not use a friendly name
such as `Ethernet 2` in `-i`.

### 2.4 Inspect and compile the replay plan

These commands do not transmit anything:

```powershell
$Run = Join-Path $PWD 'runs\issue'

.\bin\livewire.exe check $Capture -details
.\bin\livewire.exe check -in $Capture -profile functional -json "${Run}.analysis.json"
```

Read the coverage table before continuing:

- `semantic` or `stateful` lanes are suitable for an adaptive live run.
- `wire` lanes can be sent, but do not claim live response equivalence.
- `blocked` lanes need a key log, credentials, a rule pack, or a different
  fidelity choice. Do not treat a blocked lane as a successful replay.

### 2.5 Run the first live replay

```powershell
.\bin\livewire.exe live $Capture `
  -t $TargetIP `
  -i $Iface `
  -profile functional `
  -report "${Run}.report.json"
```

`Ctrl-C` cancels the run and releases any owned interface and RST guard. Socket
application routes do not use either. Inspect the result without additional tools:

```powershell
$Report = Get-Content "${Run}.report.json" -Raw | ConvertFrom-Json
$Report.sessions | Format-Table sessionId, protocol, driver, fidelity, completed, verified, matched
$Report.limitations
Get-Item "${Run}.report.json"
```

The run is successful only when the relevant session completed and its
verification result matches the fidelity you requested. A wire-only or
unverified completion is not application equivalence.
Packet routes can also publish `-actual-out` evidence. Socket replay does not
fabricate a PCAP; capture its traffic independently when needed.

### 2.6 Re-run for a timing or TCP problem

`-profile timing` and `-profile transport` are what this guide uses because it
names the fidelity model directly. `live` also accepts `-under-load` and
`-exact-tcp` for exactly the same two profiles; the peer-facing docs use those
names. Either spelling is fine.

If the problem is intermittent rather than dependent on timing, add `-n 5`
instead: it replays the same plan five times and reports how often the device
behaved the same. See [§15](#15-command-reference).

```powershell
# Preserve captured timing and concurrent flow starts.
.\bin\livewire.exe live $Capture -t $TargetIP -i $Iface `
  -profile timing -report "${Run}.timing.report.json"

# Preserve segmentation, flags, retransmissions, ordering, and timing where valid.
.\bin\livewire.exe live $Capture -t $TargetIP -i $Iface `
  -profile transport -report "${Run}.transport.report.json" `
  -actual-out "${Run}.transport.actual.pcap"

# Stop the affected session at its first structural difference.
.\bin\livewire.exe live $Capture -t $TargetIP -i $Iface `
  -profile functional -strict -report "${Run}.strict.report.json"
```

`-under-load` is a guided alias for timing behavior. `-exact-tcp` selects the
transport behavior unless wire mode was explicitly requested.

## 3. Linux: zero to one-sided live replay

### 3.1 Install and build

Livewire uses Linux AF_PACKET directly; libpcap is not required for the live
backend. On Debian or Ubuntu, install the supporting commands:

```bash
sudo apt-get update
sudo apt-get install -y git iproute2 iptables ca-certificates
```

Install Go 1.26.7 or newer from the official [Go installation
guide](https://go.dev/doc/install), then start in the Livewire source directory:

```bash
cd /path/to/livewire

go version
go mod verify

mkdir -p bin captures runs lab
CGO_ENABLED=0 go build -trimpath -o ./bin/livewire ./cmd/livewire
./bin/livewire version
```

If you received a release binary, install it locally and skip the Go build.
[SETUP.md](SETUP.md) has the download and verification commands; after
verifying the checksum:

```bash
install -m 0755 ./livewire-<version>-linux-amd64 ./bin/livewire
```

Verify the Linux tools used for address resolution and TCP RST suppression:

```bash
command -v ip
command -v iptables
command -v ip6tables
```

### 3.2 Put the capture in the workspace

```bash
CAPTURE="$PWD/captures/issue.pcap"
cp /path/to/issue.pcap "$CAPTURE"
```

To record the capture with Livewire instead:

```bash
sudo ./bin/livewire ifaces

IFACE=enp3s0
CAPTURE="$PWD/captures/issue.pcap"
sudo ./bin/livewire capture -i "$IFACE" -o "$CAPTURE" -duration 30s
```

Generate the application exchange during the capture interval. Capture on an
isolated interface because this command does not apply a BPF filter.

### 3.3 Select the interface and verify the route

```bash
TARGET_IP=192.168.1.50
IFACE=enp3s0

sudo ./bin/livewire ifaces
ip -br address show dev "$IFACE"
ip route get "$TARGET_IP"
```

For IPv6, use an IPv6 target and verify it with `ip -6 route get "$TARGET_IP"`.
The selected interface must have an address from the same IP family as the
target.

### 3.4 Inspect and compile the replay plan

```bash
RUN="$PWD/runs/issue"

./bin/livewire check "$CAPTURE" -details
./bin/livewire check -in "$CAPTURE" -profile functional -json "${RUN}.analysis.json"
```

Resolve blockers before transmission. `live` routes TLS and SSH captures through
fresh secure sessions when their required inputs are supplied; see
[secure captures](#10-ftp-tls-and-ssh-captures). Malformed or truncated data
cannot be recovered by replay.

### 3.5 Run the first live replay

```bash
sudo ./bin/livewire live "$CAPTURE" \
  -t "$TARGET_IP" \
  -i "$IFACE" \
  -profile functional \
  -report "${RUN}.report.json"
```

Packet routes need privileges: AF_PACKET needs `CAP_NET_RAW`, and a stateful TCP
route's temporary `iptables` or `ip6tables` RST rule needs `CAP_NET_ADMIN`.
Socket-based application routes need neither capability and can omit `sudo` and
`-i`. After an elevated run, return artifact ownership to the current user if needed:

```bash
sudo chown "$(id -u):$(id -g)" "${RUN}.report.json"

sed -n '1,220p' "${RUN}.report.json"
ls -lh "${RUN}.report.json"
```

`Ctrl-C` cancels the run. Livewire removes any owned RST rule and closes the
interface on success, error, or cancellation. Packet routes can also publish
`-actual-out` evidence; socket replay needs an independent capture for wire bytes.

### 3.6 Re-run with other fidelity profiles

```bash
sudo ./bin/livewire live "$CAPTURE" -t "$TARGET_IP" -i "$IFACE" \
  -profile timing -report "${RUN}.timing.report.json"

sudo ./bin/livewire live "$CAPTURE" -t "$TARGET_IP" -i "$IFACE" \
  -profile transport -report "${RUN}.transport.report.json" \
  -actual-out "${RUN}.transport.actual.pcap"

sudo ./bin/livewire live "$CAPTURE" -t "$TARGET_IP" -i "$IFACE" \
  -profile functional -strict -report "${RUN}.strict.report.json"
```

## 4. When the live port differs from the capture

For plaintext and packet routes, `live -t` changes the target IP, not its ports.
Secure TLS/FTPS/SSH routes accept `host:port` directly. For other routes, rewrite the capture first
when the live service uses a different port. This example changes port 502 to
1502 in both directions and repairs checksums:

Windows:

```powershell
$MappedCapture = Join-Path $PWD 'captures\issue-port-1502.pcap'
.\bin\livewire.exe rewrite -in $Capture -out $MappedCapture -portmap 502:1502 -fixcsum
$Capture = $MappedCapture
```

Linux:

```bash
MAPPED_CAPTURE="$PWD/captures/issue-port-1502.pcap"
./bin/livewire rewrite -in "$CAPTURE" -out "$MAPPED_CAPTURE" -portmap 502:1502 -fixcsum
CAPTURE="$MAPPED_CAPTURE"
```

A one-sided run sends all stateful sessions to one target IP. Use a two-sided
topology when different captured endpoints need different live address maps.

## 5. Windows: two-sided replay through a DUT

### 5.1 Cable and select two adapters

```text
Windows client-facing NIC  ---- DUT client port
Windows server-facing NIC  ---- DUT server port
```

Do not use the same NIC twice. Do not enable Windows Internet Connection
Sharing or a Network Bridge between the two test NICs.

```powershell
.\bin\livewire.exe ifaces

$ClientIface = '\Device\NPF_{CLIENT_SIDE_GUID}'
$ServerIface = '\Device\NPF_{SERVER_SIDE_GUID}'
```

### 5.2 Create the topology

Replace the captured IPs with the two endpoint addresses in the PCAP. Replace
the live IPs with the addresses the DUT should see on each side. Port `0` maps
all ports for that captured IP and retains their captured port numbers.

```powershell
$TopologyPath = Join-Path $PWD 'lab\topology.windows.json'

$Topology = [ordered]@{
  version = 1
  client = [ordered]@{ interface = 'client-placeholder'; mtu = 1500 }
  server = [ordered]@{ interface = 'server-placeholder'; mtu = 1500 }
  mappings = @(
    [ordered]@{
      role = 'client'
      captured = [ordered]@{ ip = '192.0.2.10'; port = 0 }
      live = [ordered]@{ ip = '10.10.0.10'; port = 0 }
    },
    [ordered]@{
      role = 'server'
      captured = [ordered]@{ ip = '192.0.2.20'; port = 0 }
      live = [ordered]@{ ip = '10.20.0.20'; port = 0 }
    }
  )
}

[IO.File]::WriteAllText($TopologyPath, ($Topology | ConvertTo-Json -Depth 8))
Get-Content $TopologyPath
```

The placeholder interface values must be non-empty and different because the
file is validated before the command-line overrides are applied.

This minimal example preserves the capture's Ethernet addresses, which is
appropriate only when the DUT is transparent to those addresses. For a routed,
NAT, or firewall DUT, add `gateway` to each side so Livewire resolves the local
source and DUT next-hop MAC automatically. The corresponding NIC must have an
address from that gateway's IP family. Alternatively, set both `sourceMac` and
`nextHopMac` explicitly from the Livewire NIC and DUT port:

```json
"client": {
  "interface": "client-placeholder",
  "gateway": "10.10.0.1",
  "mtu": 1500
}
```

### 5.3 Run a no-fault baseline

```powershell
$LabRun = Join-Path $PWD 'runs\issue-baseline'

.\bin\livewire.exe lab `
  -in $Capture `
  -client-iface $ClientIface `
  -server-iface $ServerIface `
  -topology $TopologyPath `
  -profile timing `
  -evidence "${LabRun}.pcapng" `
  -report "${LabRun}.report.json"
```

The result should create one PCAPNG containing separate client-side and
server-side interface descriptions plus a JSON report containing per-session
crossing, loss, latency, reset, timeout, NAT/PAT, and fidelity evidence.

## 6. Linux: two-sided replay through a DUT

### 6.1 Cable and verify two adapters

```text
Linux client-facing NIC  ---- DUT client port
Linux server-facing NIC  ---- DUT server port
```

```bash
sudo ./bin/livewire ifaces

CLIENT_IFACE=enp3s0
SERVER_IFACE=enp4s0

ip -br link show dev "$CLIENT_IFACE"
ip -br link show dev "$SERVER_IFACE"
bridge link show
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
```

The interfaces must differ. Ensure they are not accidentally bridged or routed
around the DUT. The final two commands are checks; they do not change host
configuration.

### 6.2 Create the topology

```bash
CAPTURED_CLIENT_IP=192.0.2.10
CAPTURED_SERVER_IP=192.0.2.20
LIVE_CLIENT_IP=10.10.0.10
LIVE_SERVER_IP=10.20.0.20
TOPOLOGY="$PWD/lab/topology.linux.json"

tee "$TOPOLOGY" >/dev/null <<JSON
{
  "version": 1,
  "client": {"interface": "client-placeholder", "mtu": 1500},
  "server": {"interface": "server-placeholder", "mtu": 1500},
  "mappings": [
    {
      "role": "client",
      "captured": {"ip": "$CAPTURED_CLIENT_IP", "port": 0},
      "live": {"ip": "$LIVE_CLIENT_IP", "port": 0}
    },
    {
      "role": "server",
      "captured": {"ip": "$CAPTURED_SERVER_IP", "port": 0},
      "live": {"ip": "$LIVE_SERVER_IP", "port": 0}
    }
  ]
}
JSON

sed -n '1,160p' "$TOPOLOGY"
```

Add more mappings when the capture contains more endpoint IPs. Every TCP, UDP,
or ICMP session endpoint must have a matching role and captured address.
The minimal file preserves captured Ethernet addresses. For a routed, NAT, or
firewall DUT, add a `gateway` such as `"gateway": "10.10.0.1"` to each side and
give the corresponding Linux NIC an address of the same family, or provide both
`sourceMac` and `nextHopMac` explicitly.

### 6.3 Run a no-fault baseline

```bash
LAB_RUN="$PWD/runs/issue-baseline"

sudo ./bin/livewire lab \
  -in "$CAPTURE" \
  -client-iface "$CLIENT_IFACE" \
  -server-iface "$SERVER_IFACE" \
  -topology "$TOPOLOGY" \
  -profile timing \
  -evidence "${LAB_RUN}.pcapng" \
  -report "${LAB_RUN}.report.json"

sudo chown "$(id -u):$(id -g)" "${LAB_RUN}.pcapng" "${LAB_RUN}.report.json"
```

Open the PCAPNG in Wireshark or, when `tshark` is installed, verify it from the
terminal:

```bash
tshark -r "${LAB_RUN}.pcapng" -q -z io,stat,1
```

## 7. Add deterministic DUT faults

Always get a no-fault baseline working first. Then create a scenario. Rules can
match direction, session, capture-relative time, or packet index. Random choices
are repeatable because the seed is recorded.

```json
{
  "version": 1,
  "seed": 42,
  "rules": [
    {
      "name": "slow and lossy server replies",
      "match": {
        "direction": "server-to-client",
        "session": "tcp-0",
        "start": "250ms",
        "end": "3s"
      },
      "action": {
        "delay": "40ms",
        "jitter": "5ms",
        "drop": 0.01,
        "duplicate": 0,
        "reorder": 4,
        "rateBps": 1000000,
        "mtu": 1200
      }
    }
  ]
}
```

Save it as `lab/faults.json`, then append the scenario to either OS's lab
command:

```text
-scenario lab/faults.json
```

Valid directions are `client-to-server` and `server-to-client`. `drop` is a
probability from 0 through 1. `duplicate` is 0 through 16, `reorder` is 0 through
1024, and a non-zero MTU must be at least 576.

Functional, timing, and transport actors wait for the preceding opposite-side
frame to cross the DUT. A dropped request therefore produces a timeout instead
of an impossible prerecorded response. `-actor-timeout` changes the default
two-second wait. Wire mode deliberately does not apply that gate.

## 8. Fidelity and verification choices

| Profile | Use it for | What it claims |
|---|---|---|
| `functional` | First run; application behavior | Supported semantic adapters or fresh secure sessions; no implicit fallback for unknown TCP in default `live` |
| `timing` | Races, bursts, overlap, timeout problems | Functional behavior plus captured timing and concurrency |
| `transport` | Retransmission, flag, ordering, segmentation problems | Captured transport behavior where a live peer permits it |
| `wire` | Exact frame stimulus for a transparent DUT | Captured frame timing only; no live adaptation or response equivalence |

One-sided verification is lenient by default. Add `-strict` to stop a session at
the first structural mismatch. An unverified run may claim that transport
completed, but never that the response matched the recording.

There is no silent stateful-to-wire fallback. The plan and report identify the
driver and achieved fidelity for every session or raw lane.
Advanced `live -mode auto` retains compatibility routing to adaptive transport
for unrecognized TCP. Stateless `reproduce` has its own captured-timing and rate
options; it does not accept these profiles or perform response verification.

## 9. Runtime substitutions and proprietary protocols

Pass `-set name=value` repeatedly. On PowerShell, quote values containing JSON
or spaces:

```powershell
.\bin\livewire.exe live $Capture -t $TargetIP -i $Iface `
  -set http.host=device.example `
  -set 'http.header.X-Lab-Run=run-42' `
  -set 'http.body={"mode":"diagnostic"}' `
  -set mqtt.client_id=livewire-42 `
  -set mqtt.username=test-user `
  -set mqtt.password=secret
```

Linux:

```bash
sudo ./bin/livewire live "$CAPTURE" -t "$TARGET_IP" -i "$IFACE" \
  -set http.host=device.example \
  -set http.header.X-Lab-Run=run-42 \
  -set 'http.body={"mode":"diagnostic"}' \
  -set mqtt.client_id=livewire-42 \
  -set mqtt.username=test-user \
  -set mqtt.password=secret
```

Secret-like names and values are redacted from reports and error text. Command
lines may still be visible to other local users, so prefer short-lived lab
credentials.

Safe JSON rule packs can describe TCP/UDP matching, ports, prefixes, framing,
correlation fields, volatile ranges, and copy-from-live substitutions:

```text
livewire check -in issue.pcap -rules vendor.json
livewire live issue.pcap -t 192.168.1.50 -i <interface> -rules vendor.json
```

Rule packs cannot execute scripts or invent cryptographic state. Those cases
need a compiled Go adapter.

## 10. FTP, TLS, and SSH captures

### FTP and FTPS

FTP and FTPS control/data sessions are coordinated automatically by `live`.
The planner recognizes `PASV`, `EPSV`, `PORT`, and `EPRT`, assigns each
negotiated data session by endpoint and chronology, and blocks ambiguous groups.
`ftp-replay` remains a protocol-specific compatibility alias.

```text
livewire live issue.pcap -t ftp.example:21 \
  -set ftp.user=lab -set ftp.password=secret -strict
livewire live secure.pcap -t ftp.example:990 \
  -keylog sslkeys.log -server-name ftp.example -ca lab-ca.pem
```

For passive mode, Livewire connects to the authenticated control peer at the
live negotiated port before issuing the transfer command. For active mode it
opens a fresh listener and rewrites the advertised endpoint; set
`ftp.advertise-ip` only when route inference cannot identify a usable address.
`LIST`, `NLST`, `RETR`, `STOR`, `APPE`, and `STOU` compare direction, byte count,
digest, and reply class. Explicit FTPS upgrades the existing control connection
after a successful `AUTH TLS`; implicit FTPS begins with TLS. `PBSZ` and `PROT`
are honored and every protected data socket negotiates fresh verified TLS.
This fresh-session route never transmits captured TLS ciphertext.

Captured TLS or SSH ciphertext is never sent by automatic mode. The unified
orchestrator asks for the requirements needed to construct a fresh session. In
non-interactive runs it stops before network activity and names the exact flags.

### TLS 1.2 and 1.3

Provide the matching NSS `SSLKEYLOGFILE`. Livewire decrypts supported AEAD
records, prepares the detected inner protocol, and opens a fresh verified TLS
connection. An adjacent key log or `SSLKEYLOGFILE` environment value may be
suggested, but is never consumed without affirmative operator selection.

Windows:

```powershell
.\bin\livewire.exe live $Capture `
  -keylog .\secrets\sslkeys.log `
  -t device.example:443 `
  -server-name device.example `
  -ca .\secrets\lab-ca.pem `
  -set http.host=device.example `
  -report .\runs\issue.tls.report.json
```

Linux:

```bash
./bin/livewire live "$CAPTURE" \
  -keylog ./secrets/sslkeys.log \
  -t device.example:443 \
  -server-name device.example \
  -ca ./secrets/lab-ca.pem \
  -set http.host=device.example \
  -report ./runs/issue.tls.report.json
```

Certificate verification is enabled. Use `-insecure-skip-verify` only in an
isolated lab when verification is intentionally impossible. The capture must
contain exactly one selected TLS session; isolate it first if necessary.
`tls-replay` remains available with its original flags for existing scripts.

### SSHv2

SSH replay opens a fresh connection and runs explicit commands. Captured
ciphertext is never interpreted as the original command text.

Windows:

```powershell
.\bin\livewire.exe live $Capture `
  -t device.example:22 `
  -user lab `
  -key .\secrets\id_ed25519 `
  -host-key .\secrets\device_host_key.pub `
  -cmd 'show version' `
  -expect 'Version' `
  -report .\runs\issue.ssh.report.json
```

Linux:

```bash
./bin/livewire live "$CAPTURE" \
  -t device.example:22 \
  -user lab \
  -key ./secrets/id_ed25519 \
  -host-key ./secrets/device_host_key.pub \
  -cmd 'show version' \
  -expect 'Version' \
  -report ./runs/issue.ssh.report.json
```

Provide exactly one `-expect` for every `-cmd`, or omit all expectations for a
completion-only run. Unified mode requires `-host-key` with one OpenSSH public
key and refuses an unverified peer. `ssh-replay` retains its older unpinned lab
behavior for compatibility, records the observed fingerprint, and reports the
missing identity check as a limitation.

## 11. Built-in protocol behavior

- **TCP:** fresh sequence state, acknowledgement alignment, retransmission
  tracking, checksum repair, and IPv4/IPv6 support.
- **UDP:** bidirectional tuple grouping, configurable idle boundary, turn
  replay, endpoint rewriting, and adapter or tuple/order correlation.
- **ICMPv4/ICMPv6 Echo:** address and checksum rewriting plus identifier and
  sequence verification. Other ICMP types remain explicit wire lanes.
- **HTTP/1.0 and HTTP/1.1:** pipelining, Content-Length, chunked bodies and
  trailers, connection-close framing, and request/response pairing.
- **DNS over UDP/TCP:** transaction-ID and question correlation; lenient mode
  normalizes ID and TTL drift.
- **MQTT 3.1.1/5.0:** remaining-length framing, packet identifiers, QoS flows,
  and client ID or credential substitution.
- **Modbus/TCP and DNP3:** framing and transaction/sequence comparison. DNP3
  Secure Authentication needs a security-aware adapter.
- **FTP/FTPS:** multiline control replies, pipelining, coordinated active/passive
  data connections, transfer digests, and fresh verified FTPS retermination.
- **IPv6:** extension parsing, fragment classification/reassembly, NDP,
  protocol-aware filters, and IPv6 RST suppression.

UDP tuples split into new sessions after 30 seconds of inactivity by default.
Change that consistently in planning and execution with `-udp-idle 10s`, for
example.

## 12. Dashboard

Windows Administrator PowerShell:

```powershell
.\bin\livewire.exe web -addr 127.0.0.1:8080 -dir .\captures
```

Linux:

```bash
sudo ./bin/livewire web -addr 127.0.0.1:8080 -dir ./captures
```

Open `http://127.0.0.1:8080`. The UI is embedded and has no runtime web
dependencies. Keep it on localhost: it controls privileged packet operations
and does not include user authentication. The server enforces a random CSRF
token, same-origin JSON mutations, a 1 MiB request limit, strict fields, rooted
artifact access, and HTTP timeouts. A non-loopback address is refused unless
`-unsafe-listen` is supplied, which is an explicit dangerous override rather
than authentication. `Ctrl-Enter` starts a run and `Escape` cancels the active
job.

## 13. Reports and support bundles

`live` writes a JSON report. Its packet routes can publish an `-actual-out`
PCAP; socket replay does not fabricate packet evidence, and fresh secure routes
reject `-actual-out`. Capture the live traffic independently when needed.
Stateless `reproduce` and `replay` write transmission counts to an explicit
`-report`, including preview JSON when combined with `-dry-run`; they do not
accept `-actual-out` or compare responses. Two-sided `lab` writes the explicit
`-report` JSON and `-evidence` PCAPNG.

Application/transport reports include the capture digest, replay plan, adapter
versions, transformations, redacted variables, per-session results, and
limitations. Secure routes use redacted protocol-specific reports.

Create a shareable metadata-only bundle. When packet evidence exists, reference
it by name, size, and SHA-256 without embedding its bytes. Omit `-evidence` for
a report-only run:

Windows:

```powershell
.\bin\livewire.exe bundle `
  -report .\runs\issue.report.json `
  -evidence .\runs\issue.actual.pcap `
  -out .\runs\issue.support.zip
```

Linux:

```bash
./bin/livewire bundle \
  -report ./runs/issue.report.json \
  -evidence ./runs/issue.actual.pcap \
  -out ./runs/issue.support.zip
```

PCAP payloads can still contain credentials or personal data. Treat them as
sensitive even though Livewire does not place supplied secrets in metadata. See
[SECURITY.md](../SECURITY.md).

## 14. Troubleshooting

### Windows: `wpcap.dll` cannot be loaded

- Install Npcap and select WinPcap API-compatible mode.
- Confirm `%WINDIR%\System32\Npcap\wpcap.dll` and `Packet.dll` exist.
- Re-run `livewire ifaces` from an Administrator PowerShell.

### Windows: `WinDivert.dll` cannot be loaded

- Put the 64-bit `WinDivert.dll` and `WinDivert64.sys` beside
  `livewire.exe`.
- Run PowerShell as Administrator.
- Do not rename the DLL or driver.

### Linux: permission or AF_PACKET error

- Run the live command with `sudo`.
- Confirm the interface is up with `ip -br link`.
- Confirm `iptables` and `ip6tables` are installed.

### No response from the target

1. Confirm the chosen interface and route.
2. Confirm the target uses the same IP family as that interface.
3. Confirm the live service listens on the port captured in the PCAP.
4. Check the coverage plan for a blocker or wire-only lane.
5. Check VLAN, gateway, firewall, and next-hop reachability.
6. Inspect the actual PCAP or lab PCAPNG instead of assuming frames crossed.

### Replay receives a TCP reset

- Keep the default RST guard enabled.
- On Windows, verify WinDivert files and Administrator elevation.
- On Linux, verify the temporary `iptables` rule can be installed.
- A reset observed from the DUT or target is evidence, not a host-guard failure.

### Lab topology validation fails

- Both interface strings in the JSON must be non-empty and different, even
  when command-line overrides are supplied.
- Map every captured client and server endpoint.
- Do not change address family in a mapping.
- Use port `0` to retain the captured port.
- A VLAN must be 0 through 4094 and a non-zero MTU must be at least 576.

### The capture begins mid-session

Livewire can synthesize a best-effort TCP handshake, but fidelity is lower.
Capture the original SYN and SYN-ACK when possible.

### The capture is TLS, SSH, or authenticated DNP3

- TLS opens a fresh verified handshake from the capture's ClientHello with
  `live <capture> -t <host:port>` or `live -in <capture> -t <host:port>`.
  Application replay needs matching embedded PCAPNG TLS secrets or explicit
  `-keylog <file>`; without them it remains incomplete and unverified. FTPS
  requires recoverable control/data messages. Nearby external key logs are
  never silently read. See [TLS capture replay](TLS_CAPTURE_REPLAY.md).
- SSH needs `-user`, exactly one of `-pass`/`-key`, a pinned `-host-key`, and at
  least one explicit `-cmd`. Captured SSH ciphertext is never treated as a
  command script.
- DNP3 Secure Authentication needs a purpose-built adapter.
- Unknown opaque sessions are blocked. Livewire never guesses plaintext or
  fresh cryptographic state and never falls back to wire injection automatically.
- Use `reproduce <capture> -i <interface>` for raw packet injection. Advanced
  `live -wire` and `live -profile wire` remain compatibility spellings. None
  turns captured ciphertext into a fresh secure application session.

## 15. Command reference

`livewire` and `livewire help` open the unified, task-based help hub. `livewire
help examples` shows common workflows, `livewire help troubleshoot` gives
recovery steps, `livewire help protocols` explains automatic fallbacks, and
`livewire help diagnose` gives the evidence-collection workflow. `livewire help
commands` lists the complete catalog.
`livewire help --all` remains an alias for the catalog, and `livewire help
<command>` describes one command.

### Primary

| Command | Purpose |
|---|---|
| `live` | Stateful application replay through fresh connections, secure retermination and response comparison |
| `reproduce` | Stateless captured-packet transmission without connection state or reply checking |

### Advanced

| Command | Purpose |
|---|---|
| `check` | Inspect a capture's structure and compile its coverage, fidelity, warnings, and blockers, all offline |
| `capture` | Record an interface into PCAP |
| `ifaces` | List usable interfaces and exact Windows Npcap device names |
| `web` | Serve the embedded local dashboard |
| `live -in ...` | Historical TCP controls and dry runs unless explicit secure inputs select fresh application sessions |
| `lab` | Coordinated two-sided replay through a DUT |
| `replay` | Compatibility alias for stateless `reproduce` |
| `rewrite` | Apply static MAC/IP/port/TTL/VLAN/sequence edits |
| `convert` | Convert PCAPNG to classic PCAP, optionally reassembling fragments |
| `ftp-replay` | Protocol-specific compatibility alias for the FTP/FTPS driver |
| `tls-replay` | Protocol-specific compatibility alias for the TLS driver |
| `ssh-replay` | Protocol-specific compatibility alias for the SSH driver |
| `bundle` | Create a redacted metadata-only support ZIP |
| `rstdrop` | Hold host-RST suppression open for an external injector (`live` manages it for stateful packet routes) |
| `version` | Print the version |

### Older names, still supported

| Command | Purpose |
|---|---|
| `info` | The capture summary half of `check` |
| `analyze` | The replayability assessment half of `check` |

### Shared option vocabulary

The same idea keeps the same name on every command that has it.

| Option | Means | Commands |
|---|---|---|
| `-in` | the capture file | `reproduce`, `check`, `live`, `replay`, `rewrite`, `convert`, `lab`, `ftp-replay`, `tls-replay`, `ssh-replay` |
| `-i` | which network connection to use | `reproduce`, `capture`, `live`, `replay` |
| `-t` | the live device to talk to | `live`, `ftp-replay`, `tls-replay`, `ssh-replay`, `rstdrop` |
| `-n` | fresh attempts for `live`, unchanged packet passes for `reproduce`/`replay`, packets for `capture` | `reproduce`, `live`, `replay`, `capture` |
| `-o` | where to write | `capture`, `convert`, `rewrite`, `bundle` |
| `-live` | actually send on the wire rather than simulate | legacy `live -in` |
| `-details` | show the expert tables rather than the plain-language summary | `live`, `check` |

`live`, `reproduce`, `replay` and `check` accept a positional capture, including
flags on either side. Historical `live -in ...` retains its legacy parser unless
explicit secure inputs select fresh application replay.

Superseded spellings — `-to`, `-on`, `-iface`, `-target`, `-out`, `-loop`,
`-count`, `-ip`, `-times`, `-iterations`, `-dry-run` — remain accepted wherever
they previously worked, except for the explicit 1.1 `reproduce` contract
correction: migrate application options to `live`. Aliases are omitted from the default help to keep the visible surface
small; `livewire <command> -all-flags` lists every option a command accepts and
marks the compatibility aliases.

### Repeating a replay

Stateless `reproduce -n <count>` sends the same selected frames on each pass and
reports transmission counts, without comparing responses. `-n 0` continues
until interrupted. It does not create a new connection for each pass.

`-n <count>` on `live` replays the whole plan that many times and
reports how often the device behaved the same, which is the useful measurement
for an intermittent fault. The dashboard exposes the same control as an
*Attempts* field on the one-sided run form.

- Attempts run sequentially, separated by `-gap` (default 1s).
- Stateful packet TCP attempts use a fresh client port and ISN. An identical TCP four-tuple
  re-sent immediately is a stale duplicate as far as the peer's TCP stack is
  concerned, so it would be reset and misreported as a failure to reproduce. The
  substitution is recorded in the report's `transformations`.
- For a generic plan, one report covers the whole run; packet routes can also
  publish an evidence PCAP. Socket routes do not fabricate one. Each `sessions[]`
  and `flows[]` entry carries an `attempt` number, and the document gains `attempts`
  plus an `outcome` object holding the per-attempt counts, whether the device was
  `consistent`, and an `intermittent` flag.
- TLS, FTPS, and SSH attempts each negotiate a fresh authenticated connection
  and write a separate redacted attempt report, followed by an outcome tally.
- A single-attempt report omits the repetition-only attempt fields.
- `-stop-when-different` ends the run at the first attempt that diverges, for
  when one failing sample is all you need. Ctrl-C stops cleanly and still writes
  a report covering the attempts that ran.
- Legacy `live -in ... -n` requires an on-wire replay when requesting more than
  one attempt; repeating its deterministic simulation is refused. Positional
  `live ... -dry-run` previews the plan without executing any attempts.

Run `livewire <command> -h` for the common flags, or `-all-flags` for all of them.

## 16. Deliberate 0.9 boundaries

- No distributed replay agents.
- No TRex-scale throughput target.
- No HTTP/2 or HTTP/3 semantic adapter.
- No automatic recovery of TLS or SSH plaintext without secrets.
- No arbitrary scripting in rule packs.
- Two-sided actors preserve and adapt transport state, but opaque bytes do not
  become semantic application verification unless an adapter is involved.

Automated publication does not claim physical Windows/Linux NIC injection,
native Linux arm64 execution, a deliberately wired two-NIC DUT run, or
Authenticode publisher trust. Those boundaries are disclosed in the release
notes and [RELEASE_AUDIT.md](RELEASE_AUDIT.md). Cancellation, cleanup, parser,
dashboard, artifact, and protocol behavior are automated gates.

## 17. Building and releasing

Installing a released build is covered in [SETUP.md](SETUP.md). This section is
for maintainers cutting a release.

### Cross-compilation

The build is pure Go with no cgo, so every target cross-compiles from any host:

```sh
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -o livewire-linux-amd64       ./cmd/livewire
GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -o livewire-linux-arm64       ./cmd/livewire
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o livewire-windows-amd64.exe ./cmd/livewire
```

### Cutting a release

`scripts/release.ps1` builds all three targets, stages the documents, produces the
Windows ZIP, and writes SHA-256 checksums into `dist/v<version>/`:

```powershell
$env:GOTOOLCHAIN='go1.26.7'
./scripts/release.ps1 -Version <x.y.z>
```

It refuses to build unless the toolchain is exactly Go 1.26.7 and
`go run ./cmd/livewire version` reports the requested version. Version data is
centralized in `internal/buildinfo`. Inputs are sorted, VCS metadata is disabled,
paths are trimmed, ZIP timestamps are fixed, and the script emits a deterministic
CycloneDX SBOM, unsigned-Windows notice, and `SHA256SUMS`.

Commit only `SHA256SUMS` and the SBOM from `dist/v<version>/`; the binaries and
packaged documents are ignored and live only on the Releases page. Pushing a
`v*` tag runs `.github/workflows/release.yml`, which repeats the tests, rebuilds
every artifact, proves the rebuilt `SHA256SUMS` is byte-identical to the
committed one, validates the SBOM and ZIP, attests the rebuilt artifacts,
publishes them with only that version's changelog section, then downloads every
asset and verifies it against the committed manifest.

### Pre-release gate

Offline, on every change:

```sh
go mod verify
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

On hardware, before distributing a release candidate:

1. Check a synthetic TCP/UDP/ICMP capture and confirm every frame appears in the
   plan.
2. Run one-sided replay against controlled IPv4 and IPv6 targets.
3. Run a repeated replay (`-n 3`) and confirm each attempt uses a distinct client
   port in the evidence capture.
4. Cancel during pacing and verify the interface and the RST rule are released.
5. Run `lab` through pass-through and NAT DUT configurations with two NICs.
6. Open the resulting PCAPNG in Wireshark and confirm both interfaces and
   timestamps are present.
7. Search every report for each supplied synthetic secret and confirm none
   appears.
