# Additional long-process HTTP cookie checks

Four separate CLI processes completed against independent plaintext HTTP/1.1 peers on loopback: `live` and `reproduce` on Windows amd64 and Linux amd64 under WSL2. Each process made **840 attempts × 5 captured HTTP sessions = 4,200 fresh connections**, with **8,400 independently validated requests and compared responses**. Every retained session completed, matched, verified, and reported complete cleanup. Each peer recorded 4,200 closed connections, zero active connections at completion, and zero rejected exchanges. A separate OS observation confirmed that the four CLI PIDs and peer listening sockets were absent after completion; the methods and times are retained in `cleanup-observations.json`.

The existing CLI limit is 1,000 attempts, so these are 840 attempts, not 4,200 attempts. Five independent captured flows per attempt preserved the requested total fresh connections; a five-second gap kept each CLI process alive for about 70 minutes. Each flow logged in without any inherited cookie, received a fresh per-connection cookie, then had to return exactly that cookie on `/data`. A reused or captured cookie would have failed independent peer validation.

The frozen source is `f01dd0fd79190f0e3754fdc535fe187a75ade0341e482eb24d8fa1809c7f7122`. Per-run summaries retain the exact tested binary hash, single CLI PID, real start/finish times, successful exit, request/connection counters, and resource samples. `summary.json` independently re-counts every report attempt/session and every peer completion event, recalculates resource summaries, and hashes the complete private reports and transcripts. Only reviewed summaries are copied here; captures and cookie values are omitted.

| Process | Elapsed seconds | RSS median, first third → last third (MiB) | Observed RSS range (MiB) | Observed handles or file descriptors |
| --- | ---: | ---: | ---: | --- |
| windows-live | 4199.714 | 17.60 → 19.93 | 8.96–22.07 | 51–170 handles |
| windows-reproduce | 4199.711 | 17.47 → 19.53 | 8.91–21.54 | 50–170 handles |
| linux-live | 4209.172 | 14.64 → 16.48 | 6.96–17.07 | 4–7 fileDescriptors |
| linux-reproduce | 4209.141 | 14.27 → 16.04 | 6.97–17.47 | 4–6 fileDescriptors |

Resources were sampled every 15 seconds. These measurements have no predefined pass/fail threshold and do not prove that all possible leaks are absent. Sampled RSS and OS high-water marks may miss activity after the final sample; Go heap/runtime reservation is a different measurement. The process retains repetition report state, which is included in its memory use. Complete resource/peer transcripts remain privately available under `coverage/v1-long-process-pacing` with hashes in the summary.

These successful additional checks do **not** replace the mandatory two-hour application/packet matrix and make no physical NIC/device or human-pilot claim. The earlier intentionally interrupted HTTP runs used superseded binaries and remain private diagnostics, excluded from these results.

## Reproduction

Use a fresh release checkout with the same executable-source digest and the exact tested Windows or Linux executable. `harness.py.txt` is the unchanged executed harness. Its only local dependency is the digest function loaded from `coverage/package-v1-qualification.py`. `source-digest-helper.py.txt` supplies the exact three required functions (`need`, `no_links`, `source_digest`) extracted from the original ignored helper; it omits the unrelated packaging command. `source-provenance.json` records original/copied hashes and the extraction. Install these files in a fresh checkout so existing private helper files are not replaced.

The harness uses the Python standard library and requires Python 3.10 or later; these runs used Python 3.14.4 on Windows and Python 3.13.12 on Linux.

PowerShell (set `$replayCommand` to `live` or `reproduce`, using a new output directory for each):

```powershell
New-Item -ItemType Directory -Path coverage -Force | Out-Null
$reproRoot = (Get-Location).Path
$harnessPath = Join-Path $reproRoot 'coverage/long-http-cookie.py'
$digestPath = Join-Path $reproRoot 'coverage/package-v1-qualification.py'
if ((Test-Path -LiteralPath $harnessPath) -or (Test-Path -LiteralPath $digestPath)) { throw 'Refusing existing helper files; use a fresh checkout/worktree.' }
[System.IO.File]::Copy((Join-Path $reproRoot 'qualification/v1.0.0/long-process-http/harness.py.txt'), $harnessPath, $false)
[System.IO.File]::Copy((Join-Path $reproRoot 'qualification/v1.0.0/long-process-http/source-digest-helper.py.txt'), $digestPath, $false)
$replayCommand = 'live'
python coverage/long-http-cookie.py --root $reproRoot --binary "$reproRoot/dist/v1.0.0/livewire-1.0.0-windows-amd64.exe" --command $replayCommand --out "$reproRoot/coverage/http-repro/windows-$replayCommand" --attempts 840 --sessions 5 --gap 5s --sample-seconds 15
```

Linux (set `replay_command` to `live` or `reproduce`):

```sh
mkdir -p coverage
python3 - <<'PY' || exit 1
from pathlib import Path
source = Path('qualification/v1.0.0/long-process-http')
pairs = [(source/'harness.py.txt', Path('coverage/long-http-cookie.py')),
         (source/'source-digest-helper.py.txt', Path('coverage/package-v1-qualification.py'))]
if any(target.exists() for _, target in pairs):
    raise FileExistsError('Refusing existing helper files; use a fresh checkout/worktree.')
for original, target in pairs:
    with target.open('xb') as output:
        output.write(original.read_bytes())
PY
replay_command=live
python3 coverage/long-http-cookie.py --root "$PWD" --binary "$PWD/dist/v1.0.0/livewire-1.0.0-linux-amd64" --command "$replay_command" --out "$PWD/coverage/http-repro/linux-$replay_command" --attempts 840 --sessions 5 --gap 5s --sample-seconds 15
```

Adjust only the executable path if the matching release artifact is stored elsewhere. Each invocation starts one CLI process and its independent peer. The two commands can run in separate terminals with distinct output directories. To stop gracefully, create `stop.request` inside that run's output directory; an interrupted run cannot pass.

For a short setup check, use a new output directory and replace the last options with `--attempts 2 --sessions 5 --gap 20ms --sample-seconds 0.05`. This produces 10 sessions and 20 requests. `reproduction-smoke.json` retains the successful short check of all four platform/command combinations from a separate clean worktree using copies of these published files only. Those setup checks are separate from the completed long runs.
