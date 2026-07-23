# Livewire Windows quick start

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
.\livewire.exe info -v $Capture
.\livewire.exe analyze -in $Capture -profile functional -json .\issue.analysis.json
```

Resolve any `blocked` lane before replay. Offline commands do not require
Npcap, WinDivert, or Administrator privileges.

## 5. Recommended guided replay

```powershell
.\livewire.exe reproduce $Capture `
  -to $Target `
  -on $Iface `
  -profile functional `
  -report .\issue.report.json `
  -actual-out .\issue.actual.pcap
```

The target ports come from the capture. Start with `functional`; use `timing`,
`transport`, or `wire` only when the issue requires that fidelity.

## 6. Advanced `live` commands

Replay every TCP connection:

```powershell
.\livewire.exe live -in $Capture -iface $Iface -target $Target -all
```

Replay one flow shown by `info`:

```powershell
.\livewire.exe live -in $Capture -iface $Iface -target $Target -flow 0
```

Preserve captured timing and concurrent flow starts:

```powershell
.\livewire.exe live -in $Capture -iface $Iface -target $Target -all -pace
```

Preserve captured TCP flags, retransmissions, and ACK pattern:

```powershell
.\livewire.exe live -in $Capture -iface $Iface -target $Target -all -pace -raw-l4
```

Stop on the first structural reply difference and save a report:

```powershell
.\livewire.exe live -in $Capture -iface $Iface -target $Target `
  -all -verify strict -report .\issue.live.report.json
```

Print packet-level rewrite and TX/RX information:

```powershell
.\livewire.exe live -in $Capture -iface $Iface -target $Target -all -v
```

`live` is the advanced TCP engine. Use `reproduce` for protocol-adaptive TCP,
UDP, ICMP, HTTP, DNS, MQTT, Modbus, DNP3, and explicit wire lanes.

## 7. RST suppression

`live` and `reproduce` automatically install and remove the temporary RST
guard. Do not run `rstdrop` with them, and normally do not pass
`-no-rst-guard`.

Use `rstdrop` only when another tool such as Scapy injects packets:

```powershell
.\livewire.exe rstdrop -ip $Target -port 502
```

Optionally restrict it to a captured client source port:

```powershell
.\livewire.exe rstdrop -ip $Target -port 502 -sport 49152
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
