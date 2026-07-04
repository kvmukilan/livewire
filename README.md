# livewire

Stateful TCP replay. It replays a captured session against a live host and keeps
the TCP connection coherent — learns the server's real ISN from its SYN-ACK and
rewrites seq/ack/timestamps/SACK per flow so the exchange actually completes.

`tcpreplay` can't do this (it's stateless and Unix-only); `tcpliveplay` only
handles one IPv4 flow and tracks by packet count, which desyncs when the server
re-segments. livewire is cross-platform (Linux + Windows), pure Go, no cgo, no
external dependencies.

## Build

```
go build -o livewire ./cmd/livewire      # livewire.exe on Windows
```

Needs Go 1.21+. First build pulls the toolchain version pinned in go.mod.

## Commands

| Command | What it does |
|---|---|
| `info` | inspect a pcap/pcapng — flows, protocols, handshakes, checksums, fragments |
| `ifaces` | list interfaces (and Npcap devices on Windows) with capabilities |
| `capture` | record frames from an interface to a pcap |
| `rewrite` | static edits: MAC / IP pseudo-NAT / ports / TTL / VLAN / seq, fix checksums |
| `prep` | classify packets client/server and write a cache |
| `replay` | stateless send of a capture at a chosen rate |
| `live` | stateful replay: hold the seq/ack in sync against a live host |
| `web` | browser dashboard for the above |
| `convert` | pcapng → classic pcap; `-reassemble` stitches IPv4 fragments |

## Live replay

```
# Linux (root)
sudo ./livewire live -in cap.pcap -iface eth0 -target 192.168.1.50:502

# Windows (Administrator; needs Npcap + WinDivert)
livewire live -in cap.pcap -iface "\Device\NPF_{...}" -target 192.168.1.50:502
```

It sends the SYN, waits for the real SYN-ACK, learns the live ISN, then sends the
rest with corrected sequence numbers. `-v` prints a per-packet trace, `-tui` shows
a live dashboard, `-flow N` picks one connection out of a multi-flow capture.

The host kernel will RST the spoofed connection unless suppressed — livewire does
that automatically (iptables on Linux, WinDivert on Windows). `-no-rst-guard`
turns it off.

Only TCP headers are touched; the payload (Modbus, DNP3, HTTP, whatever) is sent
byte-for-byte as captured.

## Notes

- Live replay needs root/Administrator (raw sockets + the RST rule).
- Windows live needs Npcap installed and WinDivert next to the binary. See SETUP.md.
- SSH re-termination lives behind a build tag: `go build -tags ssh`.
- Captures without a SYN can't be replayed statefully (no ISN to anchor).
