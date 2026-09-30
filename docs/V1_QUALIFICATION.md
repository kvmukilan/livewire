# Version 1 qualification scope

Version 1 uses the `software-lab` qualification profile. The gate binds all
evidence to the reviewed CLI source digest and exact Windows/Linux amd64
executable hashes. Physical NIC/device and human-pilot qualification are
separate; software-lab evidence does not assert either.

## Version 1.1 command contract

`live` establishes stateful application sessions. `reproduce` sends the
recorded packets statelessly, and `replay` remains its compatibility alias.
These commands require different evidence: successful application comparison
cannot be inferred from raw transmission, and recorded packets cannot establish
a new TLS session merely because their bytes were sent.

| Required two-hour run | Platform | What is checked |
|---|---|---|
| Application `live` | Windows amd64 | 16 application cases with checked live responses, plus a separately checked TLS connection-only case |
| Application `live` | Linux amd64 | The same 17 cases against independent protocol peers |
| Advanced packet `live` | Linux amd64 | Live datagram/echo and TCP behavior; explicit wire compatibility |
| Stateless `reproduce` | Linux amd64 | Exact captured frame bytes, order and counts; unverified application outcome |
| Stateless compatibility `replay` | Linux amd64 | The same packet contract through the retained alias |

Every required case must have successful executions spanning at least two hours.
Each CLI process repeats the selected exchange or capture, with independently
checked output and cleanup. Reports retain actual commands, executable/source
hashes, start/end times, failure counts and hash-bound captures/transcripts.
Short smoke tests and interrupted runs cannot satisfy the gate. Repeated-process
soaks do not claim one process remained alive for two hours.

Version 1.1 also checks activity throughout the recorded span. An execution
must finish within two minutes, the next execution must start within one minute,
and each case must run again within five minutes. The producer stops on a
continuity failure before crediting the affected execution; the independent
transcript validator checks these limits again. Sleeping or suspended hosts,
backward clock changes and long idle gaps cannot qualify through elapsed wall
time alone. A failed run needs a new output directory and a fresh full soak.

Historical v1.0.0 retains its six-run rules and v1.0.1 its seven-run rules.
Their published evidence and manifests remain unchanged. Version 1.1 records
must exercise the corrected commands; older application `reproduce` results
cannot qualify stateless reproduction.

## Application protocols

The application matrix uses the public `live <capture>` default without a mode
flag. Peers check actual requests and live protocol state:

| Cases | Independent peer checks |
|---|---|
| HTTP/1, HTTP/1 over TLS | Live login cookie, authenticated follow-up request, split replies |
| DNS/TCP, DNS over TLS | Pipelined questions and replies in the opposite order |
| Modbus/TCP, Modbus over TLS | Function/address/count and reordered transaction replies |
| MQTT 3.1.1 and MQTT 5, plaintext and TLS | Keepalives, bidirectional QoS 2, identifiers, aliases and limits |
| DNP3, DNP3 over TLS | Changed fragmentation, unsolicited traffic and confirmations |
| FTP, explicit FTPS, implicit FTPS | Fresh control/data connections, upload/download counts and digests, verified TLS |
| SSH | Fresh pinned host identity, explicit command outputs and exit status |
| TLS connection only | Captured SNI/ALPN and supported version selection, fresh ClientHello randomness, verified handshake and zero application bytes |

The HTTP/1 TLS application fixture embeds its TLS secrets in PCAPNG and requires
no separate key-log file. Other TLS application cases exercise explicit key-log
input. The connection-only case has no decryption secrets: successful TLS setup
is counted separately as a handshake observation, while the CLI must report
application replay incomplete and unverified, with no compared responses. It
cannot satisfy the checks for any of the 16 application replay cases. Together
the five runs require 43 platform/suite/command/case combinations.

TLS soak captures use TLS 1.2 while fresh peers negotiate TLS 1.3. The opposite
version direction, HTTP/1.1 ALPN, secure `live -in`, active FTP roles and
protection, custom rules and IPv6 TCP/UDP have separate regression coverage.
HTTP/2/3 application replay and TLS client-certificate authentication remain
outside the supported CLI scope. Unknown security and unsupported protocol
forms must stop before an application send.

## Packet and stateless protocols

Owned Linux namespaces and virtual Ethernet links exercise DNS/UDP, generic
UDP, ICMPv4/v6, adaptive TCP, captured TCP and explicit advanced wire replay.
Adaptive TCP tests include packet loss, delay and reordering. These checks use
Linux software networking, not physical devices or Windows Npcap fault scenarios.

The stateless fixture includes representative recorded frames for supported
application families and transports, including HTTP/1, DNS, Modbus, MQTT,
DNP3, FTP/data, FTPS/TLS ciphertext, SSH, TCP/UDP, ICMPv4/v6 and an unknown
EtherType. Independent captures must match every transmitted frame, in order,
for every pass. Reports must record the actual invoked command and
`verified: false`. This establishes byte transmission across protocol fixtures,
not valid fresh sessions or successful server operations. Pacing is scheduled
from the capture; network timing is not claimed identical to the recording.

## Automated checks and qualification status

Native Windows/Linux checks cover build, vet, tests, dashboard state,
static/vulnerability analysis, race, shuffle, fuzz, coverage, corpus, protocol
faults, recovery/cleanup, loader limits and published-version comparisons.
Current completion evidence belongs in [RELEASE_AUDIT.md](RELEASE_AUDIT.md).
The changed 1.1 source is not qualified by the prior version's passing runs.

The [v1.0.1 evidence index](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/README.md)
retains its seven completed matrices, and [v1.0.0](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/README.md)
retains its original six. Their additional single-process HTTP checks remain
historical results rather than a memory-leak guarantee for new builds.

Validate the current release checkout with verified artifacts present:

```sh
GOTOOLCHAIN=go1.26.7 go run ./scripts/qualify validate -version 1.1.0 -artifacts dist/v1.1.0 qualification/stable.json
```

## Repeat the software labs

The [hosted qualification workflow](../.github/workflows/qualification.yml)
runs these five matrices on separate GitHub Windows/Linux runners. Dispatch it
with the full candidate commit, reviewed source digest, version and frozen
Windows/Linux amd64 executable hashes. It checks out that commit, builds with
Go 1.26.7 using the release flags, and refuses a mismatched binary before running
the lab. An independent Go transcript check must actually run and pass before
the workflow exports qualifying evidence. Cancellation, continuity failures or
cleanup failures produce diagnostics instead of a passing bundle.

Artifacts contain allowlisted reports, transcripts, synthetic packet evidence,
checksums and workflow/toolchain provenance. Application fixture captures,
embedded TLS secrets, key logs, private keys and executables are excluded.
Download and independently revalidate the exact artifacts before adding them to
the release manifest; workflow success alone does not complete release review.

Use the exact release checkout and checksum-verified binaries. Every run needs
a fresh output directory. Build and run the lab executable directly so it
receives cancellation. Omitting `-cases` runs every application case.

Windows PowerShell:

```powershell
$env:GOTOOLCHAIN = 'go1.26.7'
New-Item -ItemType Directory -Path coverage -Force | Out-Null
go build -buildvcs=false -o coverage/replaylab.exe ./scripts/replaylab
if ($LASTEXITCODE -ne 0) { throw 'Replay lab build failed' }
./coverage/replaylab.exe -binary ./dist/v1.1.0/livewire-1.1.0-windows-amd64.exe -source-root . -command live -out coverage/lab-windows-live -environment 'Windows amd64 independent loopback peers' -duration 2h -interval 5s -repeat 3 -process-timeout 45s
```

Linux shell:

```sh
mkdir -p coverage
chmod +x dist/v1.1.0/livewire-1.1.0-linux-amd64
GOTOOLCHAIN=go1.26.7 go build -buildvcs=false -o coverage/replaylab ./scripts/replaylab || exit 1
./coverage/replaylab -binary "$PWD/dist/v1.1.0/livewire-1.1.0-linux-amd64" -source-root . -command live -out coverage/lab-linux-live -environment 'Linux amd64 independent loopback peers' -duration 2h -interval 5s -repeat 3 -process-timeout 45s
```

The packet harness requires root, Python 3, `iproute2`, `iptables`, `tcpdump`,
IPv6, network namespaces, virtual Ethernet and `netem`. It creates and cleans
only its own interfaces/namespaces. Set `SOURCE_DIGEST` to the source digest
from the exact release's reviewed manifest before running these commands:

```sh
sudo python3 scripts/replaylab_raw.py --binary "$PWD/dist/v1.1.0/livewire-1.1.0-linux-amd64" --output "$PWD/coverage/lab-linux-packet" --source-digest "$SOURCE_DIGEST" --version 1.1.0 --command live --duration 7200 --round-gap 20 --netem
sudo python3 scripts/replaylab_raw.py --binary "$PWD/dist/v1.1.0/livewire-1.1.0-linux-amd64" --output "$PWD/coverage/lab-linux-reproduce" --source-digest "$SOURCE_DIGEST" --version 1.1.0 --command reproduce --duration 7200 --round-gap 20
sudo python3 scripts/replaylab_raw.py --binary "$PWD/dist/v1.1.0/livewire-1.1.0-linux-amd64" --output "$PWD/coverage/lab-linux-replay" --source-digest "$SOURCE_DIGEST" --version 1.1.0 --command replay --duration 7200 --round-gap 20
```

Application labs create private capture keys and credentials. Publish only
reviewed allowlisted evidence; never publish fixture key logs or private keys.
Changing CLI source or executable bytes requires fresh qualification.

## Remaining boundaries

- Software peers do not establish physical NIC, industrial-device or Windows
  driver fault qualification. Native arm64 execution and uncoached human pilots
  remain separate requirements.
- Matching responses alone do not establish a device crash or another field
  fault. Retain independent target-side logs and the relevant starting state.
- Fresh application TCP does not reproduce captured packet loss/segmentation.
  Stateless packets do not negotiate a new connection. Advanced transport
  retains documented limits on TCP adaptation and recovery.
- Durable application resume never restores sockets, TLS state, authentication
  tokens or credentials. Uncertain writes require an explicit recovery contract.
- Website usability checks and dashboard API tests are separate from physical
  replay qualification. Record any actual visual/browser testing explicitly.
