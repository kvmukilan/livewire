# livewire — User Guide

livewire replays a captured TCP session against a **live** host and keeps the
connection coherent: it learns the real server's sequence numbers on the fly and
rewrites the exchange so the session actually completes — including protocols
like **Modbus** and **DNP3**, whose payload bytes are sent exactly as captured.

Use it to reproduce, against real equipment, an exchange you recorded in a pcap.

- One self-contained binary. No runtime dependencies, no Python, no cgo.
- Runs on **Linux** and **Windows**.
- Three ways to drive it: the **command line**, a **terminal dashboard (TUI)**,
  and a **browser dashboard (the GUI/web mode)**.

---

## 1. Install

### Option A — use a prebuilt binary (easiest)

Copy the right file to the machine and run it. Nothing else to install for the
offline commands.

| Platform | File |
|---|---|
| Linux    | `livewire` |
| Windows  | `livewire.exe` |

```
# Linux: make it executable and check it runs
chmod +x ./livewire
./livewire version
```

```powershell
# Windows (PowerShell)
.\livewire.exe version
```

### Option B — build from source

Needs [Go](https://go.dev/dl/) 1.21 or newer. One command:

```
go build -o livewire ./cmd/livewire        # produces livewire.exe on Windows
```

Cross-compile for the other OS from either machine:

```
GOOS=linux   go build -o livewire     ./cmd/livewire
GOOS=windows go build -o livewire.exe ./cmd/livewire
```

### One-time setup for **live replay** (only)

Everything except live replay works with no setup. To put packets on the wire
against a real device you need privileges and, on Windows, two drivers.

**Linux** — run with `sudo`, or grant the binary the capabilities once:

```
sudo setcap cap_net_raw,cap_net_admin+ep ./livewire
```

**Windows** — install two drivers, then run from an **Administrator** terminal:

1. **[Npcap](https://npcap.com)** — the packet driver (a normal installer).
2. **WinDivert** — used to stop Windows from resetting the replayed connection.
   Put `WinDivert.dll` and `WinDivert64.sys` next to `livewire.exe`:

   ```powershell
   Invoke-WebRequest https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip -OutFile wd.zip
   Expand-Archive wd.zip -DestinationPath wd -Force
   Copy-Item wd\*\x64\WinDivert.dll,wd\*\x64\WinDivert64.sys . -Force
   ```

---

## 2. Quick start (the one command)

> **Handing a capture to someone who just needs to reproduce it?** Use the
> guided `reproduce` command instead of `live` — it prompts for the device IP and
> network connection and prints a plain same/different verdict, no flags. See
> [§4e](#4e-guided-reproduction-reproduce).


```
# Linux
sudo ./livewire live -in capture.pcap -iface eth0 -target 192.168.1.50:502

# Windows (Administrator)
livewire live -in capture.pcap -iface "\Device\NPF_{...}" -target 192.168.1.50:502
```

That's it. With no extra flags livewire will:

1. open the connection to the target and learn its real sequence numbers,
2. replay your captured request bytes exactly,
3. **wait for each reply** the capture expected, **check it** against the
   recording, and
4. keep going even if the device answers a bit differently, then close cleanly.

Don't know the interface name? List them:

```
livewire ifaces
```

---

## 3. What "verify" and "adaptive" mean

These are **on by default** — you normally don't touch them. This section just
explains what livewire is doing for you.

### Verify — does the live reply match the pcap?

livewire reassembles what the device sends back and compares it to the captured
reply. For Modbus it understands the protocol, so instead of "bytes differ" you
get a real reason, for example:

> `txid 0x0007: expected function 0x03 (read-holding-registers), got exception
> 0x83 code 0x02 (illegal-data-address)`

At the end you get a one-line verdict: *replies matched the capture*, or *N
divergences from the capture*.

| `-verify` | meaning |
|---|---|
| `lenient` *(default)* | check and report differences, but keep going; a changed register value is fine (real devices drift) |
| `strict` | stop the moment a reply structurally differs (an exception, wrong function, bad id) |
| `off`    | don't inspect reply content at all |

### Adaptive — stay in sync even if the device answers differently

The naïve way to replay assumes the device returns the **exact same number of
bytes** as your recording. Real equipment often doesn't — it might return a
short error (a Modbus exception), an extra register, or a different-length body.
The naïve replay then hangs, waiting for bytes that never come.

**Adaptive mode** makes livewire behave like a real TCP endpoint: it
acknowledges what the device *actually* sent and treats a reply as complete once
the device goes quiet — so the session runs to a clean close **even when the
answer doesn't byte-match the capture**. Each request/response turn is tracked
on its own, so one odd reply never knocks the rest out of sync.

It's the default because it's what you want for reproducing SCADA exchanges. For
a strict byte-for-byte replay against a device you expect to answer identically,
turn it off:

```
livewire live -in capture.pcap -iface eth0 -target 192.168.1.50:502 -adaptive=false
```

---

## 4. Ways to run it

### 4a. Command line (single flow)

```
livewire live -in capture.pcap -iface eth0 -target 192.168.1.50:502
```

If the capture has more than one connection, pick one with `-flow N` (find the
numbers with `livewire info -in capture.pcap`).

### 4b. Whole pcap at once

Replay **every** connection in the capture:

```
livewire live -in capture.pcap -iface eth0 -target 192.168.1.50:502 -all
```

By default the flows replay **concurrently**, and with `-pace` they start at
their captured time offsets — so connections that overlapped in the recording
overlap on the wire too. That's what "only happens under load" bugs need:

```
livewire live -in capture.pcap -iface eth0 -target 192.168.1.50:502 -all -pace
```

Add `-sequential` to replay them one at a time instead. You get a per-flow
result and a summary at the end.

### 4c. Terminal dashboard (TUI)

Same thing with a live status screen in your terminal instead of scrolling text:

```
livewire live -in capture.pcap -iface eth0 -target 192.168.1.50:502 -tui
```

### 4d. Browser dashboard (the GUI / web mode)

Prefer clicking to typing? Start the dashboard and open it in a browser:

```
livewire web
```

Then go to **http://127.0.0.1:8080**. From the page you can list interfaces,
load or capture a pcap, pick a flow, and run the replay — with the same smart
defaults (waits for and validates replies, stays coherent on divergence). Live
replay still needs Administrator/root, so start `livewire web` from an elevated
terminal if you plan to replay.

Serve it on a different address or read pcaps from another folder:

```
livewire web -addr 0.0.0.0:9000 -dir ./captures
```

> The dashboard binds to localhost by default. Only use `0.0.0.0` on a trusted
> network — anyone who can reach the port can drive replays.

### 4e. Guided reproduction (`reproduce`)

`reproduce` is a thin, prompt-driven front end over the `live` path for operators
who shouldn't have to reason about flags. It runs the most faithful default and
reports a plain verdict; tuning is opt-in and only suggested when the default run
diverges.

```
livewire reproduce <capture>.pcap [--to <device-ip>] [--on <connection>]
```

What it does:

- **Target.** Takes the device IP from `--to`, or prompts for it
  (non-interactive without `--to` is an error). The port is taken per-flow from
  the capture — the recorded server IP is *not* reused, since the peer's device
  is on a different network.
- **Interface.** Uses `--on`, or presents a numbered menu. On non-Windows it
  marks the connection whose subnet contains the device IP as *recommended* and
  pre-selects it (Enter accepts). On Windows it lists the Npcap device names
  (subnet matching isn't reliable there). Non-interactive with an unambiguous
  single/recommended match auto-selects; otherwise it errors asking for `--on`.
- **Replay.** Runs every flow through the shared concurrent runner with the
  reliable defaults — `-verify lenient`, `-adaptive`, handshake synthesis for
  mid-stream captures — with per-frame tracing off for clean output.
- **Verdict.** Prints, per connection, `SAME AS THE RECORDING` (completed and
  replies matched), `DIFFERENT FROM THE RECORDING` (completed but replies
  diverged, with the specifics), or `DID NOT COMPLETE` (with a plain reason).
- **Report.** Always writes a JSON report next to the capture
  (`<capture>.report.json`, override with `--report`), including the per-flow
  likely-cause diagnosis.

Scenario flags map to the same knobs as `live`, and are printed as suggestions
if the default run didn't reproduce:

| `reproduce` flag | equivalent `live` behaviour |
|---|---|
| `--under-load` | `-pace` (original timing + concurrent overlap) |
| `--exact-tcp` | `-raw-l4` (send the client's frames verbatim) |
| `--strict` | `-verify strict` (abort on the first divergence) |
| `--to` / `--on` | `-target` / `-iface` |

### Try it safely first (dry run, no NIC)

Leave off `-iface` and livewire simulates the whole replay without touching the
network — good for sanity-checking a capture before you point it at real gear:

```
livewire live -in capture.pcap
```

---

## 5. Other commands (offline, no setup needed)

| Command | What it does | Example |
|---|---|---|
| `info`    | summarise a pcap — flows, protocols, handshakes | `livewire info -in capture.pcap` |
| `ifaces`  | list interfaces you can capture/replay on | `livewire ifaces` |
| `capture` | record traffic from an interface into a pcap | `livewire capture -iface eth0 -out out.pcap -duration 10s` |
| `replay`  | stateless blast of a capture at a set rate (no waiting) | `livewire replay -in capture.pcap -iface eth0` |
| `convert` | pcapng → classic pcap | `livewire convert -in in.pcapng -out out.pcap` |
| `rewrite` | static edits (MAC/TTL/VLAN/seq) | `livewire rewrite -in in.pcap -out out.pcap -ttl 64` |

Run `livewire <command> -h` for that command's options. Every command prints a
short usage line if you get an argument wrong.

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `permission denied` / no packets sent | Run elevated: `sudo` on Linux, an **Administrator** terminal on Windows. |
| Windows: replay opens but the connection resets | WinDivert isn't next to `livewire.exe`. See install step 2. Or the interface name is wrong — copy it from `livewire ifaces`. |
| Windows: `wpcap.dll` not found | Install **Npcap** (npcap.com). |
| Replay reports divergences | That's verify doing its job — the live device answered differently than the recording. The message says exactly how. |
| Replay hung on an older build | Update — adaptive mode (now the default) fixes hangs caused by different-length replies. |
| "capture lacks a full handshake" (dry-run) | The dry-run analysis needs the SYN/SYN-ACK. On the live path livewire now synthesizes one automatically — just run the replay. |

---

## 7. Getting a more faithful reproduction

The defaults already reproduce most exchanges. These extras help when a bug is
sensitive to *timing*, or when your capture doesn't start at the beginning.

### Match the original timing — `-pace`

By default the replay runs as fast as the device answers. Some bugs only show up
under the original request rate / inter-packet gaps. `-pace` replays each packet
on the capture's own clock:

```
livewire live -in capture.pcap -iface eth0 -target 192.168.1.50:502 -pace
```

### Replay a capture that starts mid-session

If a pcap has no opening SYN (you started capturing after the connection was
already up), livewire now **synthesizes a handshake** automatically on the live
path — it fabricates a SYN, learns the real device's sequence numbers, and slots
your mid-stream data in behind it. Nothing to configure; you'll see a
`synthesizing a SYN...` line. (This is best-effort/experimental: the synthetic
SYN carries fewer options than a real one, but most devices accept it.)

### Save a shareable report — `-report`

Write a JSON summary of the run — per flow: completed or not, frames sent,
whether replies matched the capture, and every exact divergence. Handy to attach
to a ticket or diff across devices/firmware:

```
livewire live -in capture.pcap -iface eth0 -target 192.168.1.50:502 -all -report run.json
```

### Protocol awareness

Reply checking understands both **Modbus** (port 502) and **DNP3** (port 20000):
it pairs each live reply with the captured one and names exactly what differed
(an exception, a wrong function code, an un-echoed id, drifted values). For these
framed protocols a turn also completes the instant a full reply arrives, so
`-pace` aside, the replay is as quick as it is accurate.

### The optional flags at a glance

Everything below is optional — the bare `live` command already does the smart
thing. Keep this list short in your head:

| Flag | When you want it |
|---|---|
| `-all` | replay every connection in the pcap (concurrently), not just one |
| `-pace` | reproduce the original timing — intra-flow gaps *and* inter-flow start offsets (some bugs need it) |
| `-report FILE` | save a JSON summary — per flow: result, divergences, and a likely-cause diagnosis to share or diff |
| `-raw-l4` | replay the client's frames *exactly* as captured (retransmits, RSTs, original acks) for bugs triggered by messy TCP |
| `-verify strict` | fail the run on any reply difference (default is `lenient`) |
| `-adaptive=false` | strict byte-for-byte replay (default adapts to the device) |
| `-sequential` | with `-all`, replay flows one at a time instead of concurrently |
| `-tui` | live status screen in the terminal |

### When a run doesn't reproduce the issue

With `-report`, each flow gets a **diagnosis** line explaining the most likely
reason it diverged — the device answered differently (state/firmware), reset the
connection, stopped responding, or couldn't be opened — so you know what to
change rather than guessing.

Reproduction has a hard ceiling worth knowing: livewire replays the **client**
side against a live device. It reproduces client-request-driven and timing-driven
behaviour well, but it **cannot** reproduce a fault triggered by something the
*device* originated, nor one that depends on the device's internal state
(firmware, prior writes, mode). Put the device in the same starting state first.

### Still on the wishlist

- **Payload-level rewriting** — adjust an app-layer field (a unit id, a register
  address) on the way out, to retarget a captured exchange at a different device
  without re-capturing.
- **Server-side replay** — livewire acting as the *device*, to reproduce
  client-side bugs (the mirror of what it does today).
- **HTTP/TLS reply awareness** — the same precise "what differed" diagnostics for
  web and encrypted protocols, beyond Modbus and DNP3.
