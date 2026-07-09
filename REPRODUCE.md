# How to reproduce the issue we sent you

We recorded a problem talking to a device like yours and saved it as a capture
file (ending in `.pcap`). This tool replays that exact conversation against
**your** device so we can confirm the problem happens on your end and you can
fix it. It only talks to the one device you point it at.

You need three things: the tool, the `.pcap` file we sent, and your device's IP
address. It takes about two minutes.

---

## Step 1 — Get the tool onto the machine

Use the machine that can reach the device on the network.

**Windows**

1. Copy `livewire.exe` (we sent it) to a folder, e.g. `C:\livewire\`.
2. Install **Npcap** from https://npcap.com (normal installer, click through).
3. Put the two `WinDivert` files we sent (`WinDivert.dll`, `WinDivert64.sys`)
   in the same folder as `livewire.exe`.
4. Open **PowerShell as Administrator** (right-click → Run as administrator) and
   go to the folder:  `cd C:\livewire`

**Linux**

1. Copy `livewire` to the machine and make it runnable:  `chmod +x ./livewire`
2. You'll run the command with `sudo` (it needs permission to use the network).

---

## Step 2 — Run one command

Put the `.pcap` file in the same folder, then run:

```
# Windows (in the Administrator PowerShell)
.\livewire.exe reproduce issue.pcap

# Linux
sudo ./livewire reproduce issue.pcap
```

It will ask you two simple questions:

1. **Your device's IP address** — type it in (e.g. `192.168.1.50`) and press Enter.
2. **Which network connection to use** — it shows a numbered list and marks the
   right one as *recommended*. Just press Enter to accept it, or type the number.

That's it. It runs on its own and prints the result.

> Prefer no questions? Add your device's address directly:
> `livewire reproduce issue.pcap --to 192.168.1.50`

---

## Step 3 — Read the result

At the end you'll see one of these:

- **SAME AS THE RECORDING** — your device behaved exactly like our recording.
  The problem reproduces on your device. 
- **DIFFERENT FROM THE RECORDING** — the conversation finished but your device
  answered differently. It prints exactly what differed. The problem did **not**
  reproduce as recorded (often a different device state or firmware).
- **DID NOT COMPLETE** — the exchange stopped early (for example, the device
  reset the connection or stopped responding). It says what happened.

---

## Step 4 — Send the report back

The tool saves a file next to the capture called something like
`issue.report.json`. **Send that file back to us** — it contains everything we
need to see what your device did.

---

## If it didn't reproduce and you expected it to

Run it again with one extra word, as the tool suggests:

- Timing- or load-related problem:  `livewire reproduce issue.pcap --under-load`
- A low-level network glitch:        `livewire reproduce issue.pcap --exact-tcp`

Still stuck? Just send us the report file and we'll take it from there.

---

### Quick fixes

| It says… | Do this |
|---|---|
| `permission denied` / nothing sent | Windows: use an **Administrator** PowerShell. Linux: put `sudo` in front. |
| `wpcap.dll not found` (Windows) | Install **Npcap** from npcap.com. |
| the connection resets immediately (Windows) | Make sure the two `WinDivert` files are in the same folder as `livewire.exe`. |
| it couldn't pick a network connection | Run `livewire ifaces` to see the names, then add `--on <name>` to the command. |
