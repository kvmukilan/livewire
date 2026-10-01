# Livewire Windows quick start

> **Installing on a new machine?** Use [SETUP.md](SETUP.md) — it has the
> copy-paste path from a bare PC to a first replay. This page covers the advanced
> Windows commands once that is done.

This guide describes the 1.2.0 command contract. When using a 1.0.1 binary, use the
[1.0.1 Windows guide](https://github.com/kvmukilan/livewire/blob/v1.0.1/docs/WINDOWS-QUICKSTART.md)
with that binary. In 1.0.1, `reproduce` is application replay and `replay` is the
stateless command.

This guide assumes the release ZIP has been extracted and `livewire.exe` is in
the current folder. Use a lab target you are authorized to test: replaying a
capture can repeat writes or other state-changing operations.

## 1. Open Administrator PowerShell

Open PowerShell with **Run as administrator**, then enter the extracted release
folder:

```powershell
Set-Location C:\path\to\livewire
.\livewire.exe version
```

## 2. Prepare Npcap and WinDivert

Run the included helper:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\setup-windows.ps1 `
  -ExeDirectory .
```

The helper:

- checks whether the Npcap service and DLL are present;
- optionally runs an Npcap installer you supply;
- downloads the official WinDivert 2.2.2 binary archive when needed;
- copies `WinDivert.dll` and `WinDivert64.sys` beside `livewire.exe`;
- prints the next commands to run.

If Npcap is missing, download its signed interactive installer from
[npcap.com](https://npcap.com/), save it in Downloads, then run:

```powershell
$NpcapInstaller = Get-ChildItem "$HOME\Downloads\npcap-*.exe" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\setup-windows.ps1 `
  -ExeDirectory . `
  -NpcapInstaller $NpcapInstaller.FullName
```

Npcap's free installer is interactive. Silent `/S` installation is available
only with Npcap OEM.

### WinDivert-only copy-paste setup

Use this when you do not want to run the helper script:

```powershell
$Zip = Join-Path $env:TEMP 'WinDivert-2.2.2-A.zip'
$Out = Join-Path $env:TEMP 'livewire-windivert-2.2.2'

Invoke-WebRequest `
  -Uri 'https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' `
  -OutFile $Zip

if (Test-Path $Out) { Remove-Item -LiteralPath $Out -Recurse -Force }
Expand-Archive -LiteralPath $Zip -DestinationPath $Out

$Dll = Get-ChildItem $Out -Recurse -File -Filter WinDivert.dll |
  Where-Object FullName -Match '[\\/]x64[\\/]' |
  Select-Object -First 1
$Sys = Get-ChildItem $Out -Recurse -File -Filter WinDivert64.sys |
  Select-Object -First 1

Copy-Item -LiteralPath $Dll.FullName -Destination .\WinDivert.dll -Force
Copy-Item -LiteralPath $Sys.FullName -Destination .\WinDivert64.sys -Force
Get-Item .\livewire.exe, .\WinDivert.dll, .\WinDivert64.sys
```

WinDivert does not have a separate installer. Livewire loads its signed driver
on demand. Administrator privileges are required.

## 3. Find the Windows interface

```powershell
.\livewire.exe ifaces
```

Copy the complete `\Device\NPF_{GUID}` path for the adapter that reaches the
target. Do not use a friendly name such as `Ethernet 2`.

```powershell
$Iface = '\Device\NPF_{PASTE_GUID_HERE}'
$Target = '192.168.1.50'
$Capture = '.\issue.pcap'
```

## 4. Inspect without sending packets

```powershell
.\livewire.exe check $Capture -details
.\livewire.exe check -in $Capture -profile functional -json .\issue.analysis.json
```

Resolve any `blocked` lane before replay. Offline commands do not require
Npcap, WinDivert, or Administrator privileges.

## 5. Recommended guided replay

```powershell
.\livewire.exe live $Capture `
  -t $Target `
  -i $Iface `
  -profile functional `
  -report .\issue.report.json
```

The target ports come from the capture. Start with `functional`; use `timing`
or `transport` only when the issue requires that fidelity. For stateless captured
packets use `reproduce $Capture -i $Iface`, without `-t` or `-actual-out`.
`-profile timing` and `-profile transport` can also be written `-under-load` and
`-exact-tcp`, which is what the peer-facing instructions use.

Packet routes can save `-actual-out` evidence. Socket routes do not fabricate
wire PCAPs, and secure routes reject this option; capture traffic independently
when wire evidence is needed.

If the problem is intermittent rather than fidelity-dependent, replay it several
times and read the rate instead:

```powershell
.\livewire.exe live $Capture -t $Target -i $Iface -n 5
```

Each attempt opens a fresh connection, and the closing block reports how many of
the five matched the recording. A device that answers differently between
attempts is reported as `INTERMITTENT`.

## 6. Advanced `live` commands

Replay every TCP connection:

```powershell
.\livewire.exe live -in $Capture -i $Iface -t $Target -all
```

Replay one flow shown by `check`:

```powershell
.\livewire.exe live -in $Capture -i $Iface -t $Target -flow 0
```

Preserve captured timing and concurrent flow starts:

```powershell
.\livewire.exe live -in $Capture -i $Iface -t $Target -all -pace
```

Preserve captured TCP flags, retransmissions, and ACK pattern:

```powershell
.\livewire.exe live -in $Capture -i $Iface -t $Target -all -pace -raw-l4
```

Stop on the first structural reply difference and save a report:

```powershell
.\livewire.exe live -in $Capture -i $Iface -t $Target `
  -all -verify strict -report .\issue.live.report.json
```

Print packet-level rewrite and TX/RX information:

```powershell
.\livewire.exe live -in $Capture -i $Iface -t $Target -all -v
```

The legacy `live -in` form exposes the TCP engine for non-TLS captures unless
explicit secure inputs select fresh application replay. Recognized TLS always
uses fresh sessions; without embedded secrets or `-keylog`, only its handshake
runs and application replay remains incomplete. Positional `live <capture>`
is the stateful application workflow for supported TCP, UDP, ICMP, HTTP, DNS,
MQTT, Modbus, DNP3 and secure protocols. For stateless captured packets, use:

```powershell
.\livewire.exe reproduce $Capture -dry-run
.\livewire.exe reproduce $Capture -i $Iface -report .\packets.json
```

Stateless replay sends both recorded directions unchanged, without opening a
TCP/TLS session or checking responses. In 1.0.x, application replay used the
`reproduce` spelling; migrate those commands to positional `live` in 1.1.

## 7. RST suppression

Stateful packet routes in `live` automatically install and remove the temporary
RST guard. Do not run `rstdrop` alongside them, and normally do not pass
`-no-rst-guard`. Stateless `reproduce` does not manage a peer TCP session.

Use `rstdrop` only when another tool such as Scapy injects packets:

```powershell
.\livewire.exe rstdrop -t $Target -port 502
```

Optionally restrict it to a captured client source port:

```powershell
.\livewire.exe rstdrop -t $Target -port 502 -sport 49152
```

Leave that terminal running and press `Ctrl-C` to remove the rule.

## 8. Common failures

- `wpcap.dll` missing: install Npcap, then rerun `livewire.exe ifaces`.
- WinDivert load/file error: confirm the 64-bit DLL and driver are beside the
  64-bit EXE and PowerShell is elevated.
- No response: verify `$Iface`, the route, target IP family, and captured port.
- Immediate TCP reset: verify automatic RST suppression started successfully;
  a reset sent by the real device may be the issue evidence.
- Multiple TCP flows: add `-all` or select one with `-flow N`.
