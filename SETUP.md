# Setup

## Build

Go 1.21+ only. No cgo, no external modules.

```
go build -o livewire ./cmd/livewire

# cross-compile
GOOS=linux   go build -o livewire     ./cmd/livewire
GOOS=windows go build -o livewire.exe ./cmd/livewire
```

`go build -tags ssh` adds the `ssh-replay` command (pulls golang.org/x/crypto/ssh).
The race detector needs a C compiler: `CGO_ENABLED=1 go test -race ./...`.

## Linux live replay

AF_PACKET is built in — no drivers. Needs privilege:

```
sudo ./livewire ifaces
sudo ./livewire live -in cap.pcap -iface eth0 -target 192.168.1.50:502
```

Or grant caps instead of sudo:

```
sudo setcap cap_net_raw,cap_net_admin+ep ./livewire
```

`iptables`/`ip6tables` is used for RST suppression; `-no-rst-guard` skips it.

## Windows live replay

Two user-installed drivers:

1. **Npcap** (https://npcap.com) for send/receive. livewire loads its `wpcap.dll`
   at runtime, including a default install (no WinPcap-compat mode needed).
2. **WinDivert** for RST suppression — put `WinDivert.dll` and `WinDivert64.sys`
   next to `livewire.exe`:

   ```
   Invoke-WebRequest https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip -OutFile wd.zip
   Expand-Archive wd.zip -DestinationPath wd -Force
   Copy-Item wd\*\x64\WinDivert.dll,wd\*\x64\WinDivert64.sys . -Force
   ```

Run from an elevated shell:

```
livewire ifaces                          # copy the \Device\NPF_ name
livewire live -in cap.pcap -iface "\Device\NPF_{...}" -target 192.168.1.50:502
```

Offline commands and `live` dry-run work without any of this.

## Loopback smoke test (single machine)

Npcap ships a loopback adapter (`\Device\NPF_Loopback`, 127.0.0.1). Run a TCP
listener, capture a session against it, then replay:

```
# terminal 1: a listener on 127.0.0.1:9502 (any echo server)
# terminal 2:
livewire capture -iface "\Device\NPF_Loopback" -out cap.pcap -duration 10s
#   ... make a connection to 127.0.0.1:9502 while it captures ...
livewire live -in cap.pcap -iface "\Device\NPF_Loopback" -target 127.0.0.1:9502 -flow <N> -v
```

Elevated, with WinDivert present, it completes handshake-through-close.
