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
a live dashboard, `-flow N` picks one connection out of a multi-flow capture,
`-all` replays every flow in the capture (concurrently; add `-pace` to reproduce
the capture's original timing, `-sequential` to run them one at a time).

## Response verification

Because it holds the connection in sync, livewire waits for each server reply the
capture expected before sending the next request. `-verify` decides how closely
that reply must match:

| `-verify` | behaviour |
|---|---|
| `off` | send/receive at the TCP layer only; don't inspect reply content |
| `lenient` *(default)* | reassemble the server's reply stream and compare it to the capture; report divergences but keep going; tolerate value drift (a live PLC's register values may legitimately differ from capture time) |
| `strict` | abort the flow the moment a reply structurally diverges from the capture |

The comparison is protocol-agnostic (byte-for-byte against the captured server
stream) with a **Modbus-aware** layer on port 502: it pairs each reply ADU with
the captured one and reports meaningful diagnostics — e.g. *"txid 0x0007:
expected function 0x03 (read-holding-registers), got exception 0x83 code 0x02
(illegal-data-address)"*, a transaction-id echo failure, or a register value
drift. Structural problems (an exception, wrong function code, bad id echo) fail
the check; value drift is reported but tolerated in `lenient`.

### Adaptive clock (`-adaptive`)

By default the replay assumes the live server returns the *same number of bytes*
as the capture — it tracks progress by byte count in the server's sequence space.
That's faithful, but a device that answers differently (a shorter Modbus
exception, an extra register, a re-length HTTP body) stalls the clock: it waits
for bytes that never come and eventually times out.

`-adaptive` makes livewire behave like a real TCP endpoint instead: client ACKs
acknowledge the server's **actual** delivery high-water mark, and a request/response
turn completes once the server goes quiescent — even if it answered with fewer
bytes than the capture. The connection stays coherent and runs handshake-through-close
against a device whose replies don't byte-match the recording. Pair it with
`-verify` to *complete* the flow and *report* exactly where the live device
diverged. It suits request/response traffic (Modbus, DNP3, most SCADA); leave it
off for byte-exact fidelity against a server you expect to replay identically.

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
