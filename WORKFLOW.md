# Replay an exchange deliberately

The release candidate is `0.9.0-rc.1`. Automatic inspection remains useful;
replay intent is now a separate choice. It is a prerelease; 0.8.0 remains the stable download.

## Inspect, select, preview, run

```sh
livewire check issue.pcap -details
livewire reproduce issue.pcap --mode application --session tcp-0 --dry-run
livewire reproduce issue.pcap --mode application --session tcp-0 -t 192.168.1.50
```

Use the session IDs shown for that capture. Repeat `--session` to include more
than one exchange. Selecting FTP control or data includes the entire related
group. Changing the capture can change its session IDs; inspect it again.

Without selection, the whole capture is in scope. Background ARP or unsupported
traffic can block that scope. Select the intended exchange instead of forcing
all traffic through a different driver. Reports retain excluded packet indexes
and counts. A match describes selected sessions only.

| Intent | Behavior |
|---|---|
| `application` | Uses supported application adapters or fresh TLS/FTP/SSH sessions; no implicit transport fallback. |
| `transport` | Uses supported stateful transport behavior, without interpreting application messages. Confirmed encrypted sessions needing fresh security state are blocked. Unrecognized binary payloads can be exercised as transport data without claiming application equivalence. |
| `wire` | Injects selected captured frames at recorded timing. Requires `-i`; no target rewriting or reply comparison. |
| `auto` | Keeps compatibility protocol routing, with explicit blockers and the same preview. |

Plain application/transport targets are IP addresses and use captured ports.
Secure targets accept `host:port`. Socket-based application replay does not need
a packet interface or packet-driver elevation. Packet drivers still do.

`--dry-run` inspects the capture, validates the chosen mode and supplied target,
and shows requirements and report destinations. It sends nothing and writes no
report. Missing credentials are listed as requirements; preview alone does not
prove keys/certificates will work against a live peer. A blocked preview exits
nonzero. `check` remains an inspection command and can successfully describe a
blocked capture; inspect its structured readiness when automating.

## Secure exchanges

```sh
livewire reproduce tls.pcap --mode application -t device.example:443 -keylog sslkeys.log -ca device-ca.pem
livewire check ftps.pcap --mode application -keylog sslkeys.log -details
livewire reproduce ssh.pcap --mode application -t device:22 -user operator -key device.key -host-key device.pub -cmd "show status" -expect ready
```

FTPS negotiation is decrypted offline to associate data sessions when a matching
key log is supplied. No key log is consumed merely because it exists nearby.
Multiple independent secure exchanges require explicit session selection; this
version does not coordinate arbitrary mixed secure sessions in one run.

SSH always requires a pinned host key in the primary workflow. Passwords, key
material, command bodies, and response bodies are excluded from reports. SSH
output evidence contains lengths and digests. Blank expectations do not count
as verification. TLS identity verification remains enabled by default.

Fresh secure sessions support functional replay. Timing/exact-transport options
and actual-packet output are rejected instead of silently ignored. Add `-n 5`
for fresh repeated attempts and `-gap 0s` for no settle delay.

## Dashboard

Run `livewire web -dir ./captures` and open the local URL printed by the command.
Put capture files in that directory, select one, choose replay intent in
**Replay intent & settings**, then use **Inspect & preview**. Select sessions
in the coverage table and inspect again. Review the target before **Start replay**.

TLS/FTP/SSH inputs appear only for a fresh-session route. Key logs, CA files,
private keys, and pinned public keys must be in the dashboard working directory.
Supported private-key suffixes are `.key`, `.pem`, or `.txt`; pinned host keys
use `.pub` or `.txt`. These files are read through the existing rooted file API.

Changing a capture, mode, session selection, rule pack, key log, or UDP boundary
invalidates the preview. A changed capture digest rejects a stale start. Start
is disabled during active work; Stop remains available. Results distinguish a
match, difference, incomplete exchange, unverified completion, and wire-only
execution. Detailed differences and downloadable reports appear after the run.

**Two-sided DUT** is an independent topology choice. Its preview uses the actual
two-sided actor plan. Choose transport or wire intent: the lab does not provide
application-semantic equivalence. Full-capture topology mapping remains required;
session selection and fresh secure application replay are one-sided features.

## Compatibility and API additions

- `live <capture>` aliases `reproduce`, including flags on either side of the
  positional capture. `live -in <capture>` keeps the historical TCP engine.
- Noninteractive commands without `--mode` retain automatic routing. Interactive
  reproduction asks for intent unless an explicit mode/profile was provided.
- `--wire` and `-profile wire` select explicit wire replay. Existing protocol
  commands remain available for compatibility.
- `/api/plan` accepts `mode`, `sessions`, `shape` (`one`/`lab`), and
  `secure.keylog`. It returns shared `readiness`, `mode`, selected/excluded packet
  counts, and `captureDigest` alongside existing fields.
- `/api/run` adds `mode`, `sessions`, `captureDigest`, and `secure` inputs:
  `keylog`, `ca`, `serverName`, `user`, `password`, `privateKey`, `hostKey`,
  `commands`, `expects`, `timeoutSeconds`, `insecureSkipVerify`.
- Omitted `gapMs` retains the default; explicit `0` means no wait.
- `/api/lab` accepts explicit `mode` and `captureDigest` for reviewed starts.
- Excluded plan entries have `excluded: true`; consumers must not count them as
  failed or executed sessions. Whole-capture exact-once coverage is retained.
- Legacy JSON confidence fields remain for compatibility; human inspection
  reports capture quality instead of presenting that heuristic as a guarantee.

## Verification before release

Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and
`node --test scripts/dashboard.test.cjs`. The JavaScript checks exercise the
shipped state transitions; they do not replace visual browser QA.

Before promoting 0.9 to a stable release, complete the existing CI/reproducibility/security gates,
Windows/Linux physical NIC and DUT smoke tests, browser keyboard/visual checks,
and the planned network/QA-engineer pilot. Do not treat a development build as
evidence that those external acceptance checks passed.
