# Livewire setup

## Build

Livewire requires Go 1.25 or newer.

```sh
go mod verify
go build -o livewire ./cmd/livewire
```

SSH and TLS retermination are included in the default build. The only Go module
dependencies are `golang.org/x/crypto` and its platform support module.

Cross-build examples:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o livewire-linux-amd64 ./cmd/livewire
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o livewire-linux-arm64 ./cmd/livewire
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o livewire-windows-amd64.exe ./cmd/livewire
```

On Windows, `scripts/release.ps1` builds all three targets and writes SHA-256
checksums under `dist/v0.5.0/`.

## Linux live replay

AF_PACKET is built in. Run elevated:

```sh
sudo ./livewire ifaces
sudo ./livewire reproduce trace.pcap --to 192.0.2.50 --on eth0
```

Or grant only the required capabilities:

```sh
sudo setcap cap_net_raw,cap_net_admin+ep ./livewire
```

Livewire uses `iptables` and `ip6tables` for temporary TCP RST suppression.
`-no-rst-guard` disables that guard and normally should not be used.

For `lab`, connect the host's client-facing and server-facing interfaces to the
corresponding DUT ports. Disable unrelated bridging/routing on the Livewire host
unless it is intentionally part of the test topology.

## Windows live replay

This section assumes `livewire.exe` and the PCAP are already in the current
folder. Open **PowerShell as Administrator**.

The fastest setup is the helper included in the Windows release ZIP:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\setup-windows.ps1 `
  -ExeDirectory .
```

From a source checkout, use `-File .\scripts\setup-windows.ps1` instead. The
helper checks Npcap and automatically downloads and copies the official
WinDivert 2.2.2 files when they are missing. See
[WINDOWS-QUICKSTART.md](WINDOWS-QUICKSTART.md) for the shortest complete
walkthrough.

### 1. Check Npcap

```powershell
Get-Service npcap -ErrorAction SilentlyContinue
Test-Path "$env:WINDIR\System32\Npcap\wpcap.dll"
```

If the service is shown and `Test-Path` prints `True`, Npcap is installed; do
nothing. Otherwise, download the signed installer from
[npcap.com](https://npcap.com/), place it in this folder, and run:

```powershell
$NpcapInstaller = Get-ChildItem .\npcap-*.exe |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
Start-Process -FilePath $NpcapInstaller.FullName -Verb RunAs -Wait
Get-Service npcap
```

Use the normal interactive installer. WinPcap API-compatible mode is enabled by
default on current Npcap installers. The free installer does not support silent
installation; `/S` is an Npcap OEM feature.

### 2. Check WinDivert

```powershell
Test-Path .\WinDivert.dll
Test-Path .\WinDivert64.sys
```

If both commands print `True`, WinDivert is ready; do nothing. If either is
missing, download the
[official WinDivert 2.2.2 binary archive](https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip),
extract it, then copy these two files beside `livewire.exe`:

```powershell
$WinDivertRoot = 'C:\path\to\WinDivert-2.2.2-A'
Copy-Item "$WinDivertRoot\x64\WinDivert.dll" .
Copy-Item "$WinDivertRoot\WinDivert64.sys" .
Get-Item .\livewire.exe, .\WinDivert.dll, .\WinDivert64.sys
```

WinDivert has no separate installer. Livewire loads the driver when required.

### 3. Find the interface

```powershell
.\livewire.exe ifaces
```

Copy the complete `\Device\NPF_{GUID}` path for the adapter connected to the
target. Do not pass a friendly name such as `Ethernet 2`.

### 4. Run live replay

The easiest one-sided replay is:

```powershell
$Iface = '\Device\NPF_{PASTE_GUID_HERE}'
.\livewire.exe reproduce .\trace.pcap -to 192.0.2.50 -on $Iface
```

The lower-level `live` command, commonly used while developing or debugging the
replay engine, is:

```powershell
.\livewire.exe live -in .\trace.pcap -iface $Iface -target 192.0.2.50 -all
```

Useful additions:

```powershell
# Preserve captured packet and cross-flow timing.
.\livewire.exe live -in .\trace.pcap -iface $Iface -target 192.0.2.50 -all -pace

# Save the structured result.
.\livewire.exe live -in .\trace.pcap -iface $Iface -target 192.0.2.50 -all -report .\run.report.json

# Show packet-level TX/RX and sequence-number rewrites.
.\livewire.exe live -in .\trace.pcap -iface $Iface -target 192.0.2.50 -all -v
```

`live` and `reproduce` automatically enable temporary TCP RST suppression. Do
not start `rstdrop` for these commands, and normally do not use
`-no-rst-guard`.

### 5. Manual RST suppression

Use `rstdrop` only when another program, such as Scapy, injects the packets.
Keep it running in its own Administrator PowerShell:

```powershell
.\livewire.exe rstdrop -ip 192.0.2.50 -port 502
```

Optionally restrict the rule to the captured client source port:

```powershell
.\livewire.exe rstdrop -ip 192.0.2.50 -port 502 -sport 49152
```

Press `Ctrl-C` in that terminal to remove the rule. Offline commands such as
`info` and `analyze` require neither Npcap nor WinDivert.

## TLS setup

Configure the application that creates the original capture to write an
NSS-style SSL key log, then protect that file as a credential:

```sh
livewire tls-replay -in trace.pcap -keylog sslkeys.log \
  -target device.example:443 -server-name device.example
```

For a private CA, add `-ca lab-ca.pem`. Certificate verification stays enabled
unless `-insecure-skip-verify` is explicitly supplied.

## SSH setup

SSH ciphertext does not reveal the original commands. Supply credentials and an
explicit command list:

```sh
livewire ssh-replay -target device.example:22 -user lab \
  -key id_ed25519 -cmd "show version" -cmd "show interfaces"
```

Do not place credentials on a shared command line. Prefer a dedicated lab key
and restrictive file permissions.

## Smoke tests

Offline gate:

```sh
go mod verify
go test ./...
go vet ./...
go test -race ./...
```

Hardware gate:

1. Analyze a synthetic TCP/UDP/ICMP capture and confirm every frame appears in
   the plan.
2. Run one-sided replay against controlled IPv4 and IPv6 targets.
3. Cancel during pacing and verify the interface and RST rule are released.
4. Run `lab` through pass-through and NAT DUT configurations with two NICs.
5. Open the resulting PCAPNG in Wireshark and confirm both interfaces and
   timestamps are present.
6. Search reports for every supplied synthetic secret and confirm none appears.
