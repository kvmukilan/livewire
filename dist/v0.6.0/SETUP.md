# Livewire setup

Copy-paste instructions to get Livewire working on a machine that has nothing
installed. Pick your operating system, run the blocks in order, then confirm with
[Check it works](#check-it-works).

Once it runs, [README.md](README.md) explains every command.

- [Windows](#windows)
- [Linux](#linux)
- [Check it works](#check-it-works)
- [When something goes wrong](#when-something-goes-wrong)
- [Build from source](#build-from-source)

---

## Windows

Livewire needs two drivers on Windows: **Npcap** to send and receive packets, and
**WinDivert** to stop Windows resetting the connection it is replaying.

### 1. Download it

Open **PowerShell** (a normal one is fine for this step) and paste:

```powershell
New-Item -ItemType Directory -Force C:\livewire | Out-Null
Set-Location C:\livewire
Invoke-WebRequest -UseBasicParsing `
  -Uri https://github.com/kvmukilan/livewire/releases/download/v0.6.0/livewire-0.6.0-windows-amd64.zip `
  -OutFile livewire.zip
Expand-Archive -Path livewire.zip -DestinationPath . -Force
Remove-Item livewire.zip
Get-ChildItem
```

You should see `livewire.exe` and `setup-windows.ps1`.

### 2. Install Npcap

Npcap has an interactive installer, so this is the one step you cannot fully
paste. Download it from **<https://npcap.com/>**, save it into `C:\livewire`, then
run:

```powershell
Get-ChildItem .\npcap-*.exe |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1 |
  ForEach-Object { Start-Process -FilePath $_.FullName -Verb RunAs -Wait }
```

Click through the installer and accept the defaults. Leave **WinPcap API-compatible
mode** ticked — it is on by default.

Already installed? This prints `True` if so, and you can skip to step 3:

```powershell
(Get-Service npcap -ErrorAction SilentlyContinue) -ne $null -and
  (Test-Path "$env:WINDIR\System32\Npcap\wpcap.dll")
```

### 3. Install WinDivert

Close PowerShell and reopen it with **Run as administrator**, then:

```powershell
Set-Location C:\livewire
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\setup-windows.ps1 -ExeDirectory .
```

That downloads the official WinDivert files and puts them beside `livewire.exe`.
It also re-checks Npcap and tells you if it is still missing.

Everything from here on needs that **Administrator** PowerShell — sending raw
packets is a privileged operation.

### 4. Replay a capture

```powershell
Set-Location C:\livewire
.\livewire.exe reproduce .\issue.pcap -t 192.168.1.50
```

Replace `192.168.1.50` with your device's address and `issue.pcap` with the file
you were sent. Livewire asks which network connection to use and pre-selects the
right one — press Enter to accept it.

To skip that question, pass the connection with `-i`. Run `.\livewire.exe ifaces`
to list them, and paste the whole `\Device\NPF_{...}` value:

```powershell
.\livewire.exe reproduce .\issue.pcap -t 192.168.1.50 -i '\Device\NPF_{PASTE_GUID_HERE}'
```

---

## Linux

### 1. Download it

```bash
curl -fsSLO https://github.com/kvmukilan/livewire/releases/download/v0.6.0/livewire-0.6.0-linux-amd64
chmod +x livewire-0.6.0-linux-amd64
sudo mv livewire-0.6.0-linux-amd64 /usr/local/bin/livewire
livewire version
```

On a 64-bit ARM machine (Raspberry Pi 4/5, AWS Graviton) use
`livewire-0.6.0-linux-arm64` instead.

There are no drivers to install. Packet access is built in, and RST suppression
uses `iptables`/`ip6tables`, which your distribution already has.

### 2. Replay a capture

```bash
sudo livewire reproduce issue.pcap -t 192.168.1.50
```

Replace `192.168.1.50` with your device's address. Livewire asks which network
connection to use and pre-selects the right one — press Enter to accept it. To
skip the question, list them with `livewire ifaces` and pass one:

```bash
sudo livewire reproduce issue.pcap -t 192.168.1.50 -i eth0
```

### Running without sudo

Grant just the two capabilities Livewire needs, instead of full root:

```bash
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/livewire
livewire reproduce issue.pcap -t 192.168.1.50 -i eth0
```

Re-run `setcap` after replacing the binary — an upgrade clears it.

---

## Check it works

Two commands, on either platform. Neither sends a packet, so they are safe to run
anywhere.

```bash
livewire version    # prints: livewire 0.6.0
livewire ifaces     # lists your network connections
```

```powershell
.\livewire.exe version
.\livewire.exe ifaces
```

`version` proves the binary runs. `ifaces` proves packet access works — on
Windows it is what confirms Npcap is installed correctly.

Then look at a capture without touching the network:

```bash
livewire check issue.pcap
```

If that prints a packet summary and a replay assessment, you are ready.

---

## When something goes wrong

| What you see | What to do |
|---|---|
| `wpcap.dll` not found *(Windows)* | Npcap is missing or was installed without WinPcap-compatible mode. Reinstall from <https://npcap.com/>. |
| `WinDivert.dll could not be loaded` *(Windows)* | Re-run step 3. `WinDivert.dll` and `WinDivert64.sys` must sit in the same folder as `livewire.exe`. |
| `Access is denied` / nothing is sent *(Windows)* | Use an **Administrator** PowerShell. |
| `operation not permitted` *(Linux)* | Put `sudo` in front, or apply the `setcap` line above. |
| The connection resets immediately | RST suppression did not arm. On Windows check WinDivert and that you are elevated; on Linux check `iptables` is present. A reset from the *device* may be the real finding. |
| `couldn't find a usable network connection` | Run `livewire ifaces` and pass one with `-i`. On Windows use the full `\Device\NPF_{...}` value, not a friendly name like `Ethernet 2`. |
| `more than one network connection is possible` | Same fix — name one with `-i`. |
| Windows blocks the download or the exe | The release is unsigned. Verify it against the `SHA256SUMS` file published with the release, then allow it. |

Still stuck? Run the command with `-details` and send us the output along with the
report file.

---

## Build from source

Only needed if you are changing Livewire. Requires **Go 1.25 or newer**.

```bash
git clone https://github.com/kvmukilan/livewire.git
cd livewire
go build -o livewire ./cmd/livewire
./livewire version
```

```powershell
git clone https://github.com/kvmukilan/livewire.git
Set-Location livewire
go build -o livewire.exe .\cmd\livewire
.\livewire.exe version
```

On Windows you still need the drivers from steps 2 and 3 above; point the setup
script at your build directory with `-ExeDirectory`.

TLS and SSH retermination are included in the default build. The only module
dependency is `golang.org/x/crypto` and its platform support modules, and the
build is pure Go — no cgo, no C toolchain.

Before sending changes:

```bash
go mod verify
go build ./...
go vet ./...
go test ./...
```

Cross-compilation and release procedures are in
[DOCUMENTATION.md](DOCUMENTATION.md#17-building-and-releasing).
