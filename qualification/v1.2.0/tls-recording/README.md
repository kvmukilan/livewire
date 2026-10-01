# Automatic TLS recording verification

The [native CI job](https://github.com/kvmukilan/livewire/actions/runs/36826110837/job/110252053390) passed all 12 recording-to-replay cases on the frozen v1.2.0 source, plus the AF_PACKET capture ownership check. [proof.json](proof.json) identifies the candidate and job, and binds the normalized [test output](ci-test-output.txt). The original hosted job log remains available at the linked job.

Each case runs the actual CLI with `capture -tls -- <application>` and Linux AF_PACKET in an isolated loopback network namespace. An independent Python TLS client exports keys through the child-only `SSLKEYLOGFILE`. The resulting PCAPNG is then passed to `live` with no external key log. The independent fresh peer checks the request and supplies the response; the CLI must report completed, verified, matching application replay using embedded secrets.

| Application | Captured TLS versions |
|---|---|
| HTTP/1 | 1.2 and 1.3 |
| Modbus | 1.2 and 1.3 |
| DNS/TCP | 1.2 and 1.3 |
| MQTT 3.1.1 | 1.2 and 1.3 |
| MQTT 5 | 1.2 and 1.3 |
| DNP3 | 1.2 and 1.3 |

These are short feature integration checks, not additional two-hour recording soaks. The separate release matrices qualify repeated replay across the supported protocol cases. This evidence does not claim physical devices, arbitrary applications, HTTP/2/3, mutual TLS, or recovery from old encrypted captures without matching secrets.

The recording application must support key export. Temporary key logs, private keys, credentials and secret-bearing fixture captures are excluded from published evidence. The generic Windows/Linux process, permission and cleanup tests run in the native and hosted test gates.

## Windows Npcap loopback

A separate [Windows result](windows-loopback.json) passed the same 12 protocol/TLS-version combinations through the installed Npcap loopback driver using the exact frozen Windows release executable. Each case recorded a Python TLS client into one PCAPNG, selected its intended session, and verified one request and response over a fresh TLS session with embedded secrets. DLT_NULL loopback packets were handled successfully. Original CLI reports and output logs were reconciled by hash before this summary was published.

This adds actual Windows capture-driver loopback coverage, not physical NIC/DUT or Npcap fault-injection qualification. Captures and raw logs stay private because the interface can contain unrelated local traffic as well as TLS secrets.

## Protected FTPS control and data connections

Eight additional cases on each of [Windows Npcap loopback](ftps-windows-amd64.json) and [Linux AF_PACKET isolated loopback](ftps-linux-amd64.json) used the exact frozen release executable: active and passive uploads and downloads, under captured TLS 1.2 and 1.3. An independent Python `ftplib.FTP_TLS` client recorded both protected connections into one PCAPNG. The real `live` command then selected the recorded control/data sessions and completed verified transfer replay with embedded secrets and fresh synthetic credentials. Each result was checked against the transfer byte counts and hashes in its original CLI report.

Active FTP reverses TCP initiation but retains the FTP client's TLS role. These checks cover automatic secret collection in both TCP directions. They bring the short recording integration total to **40 cases** across both platforms; they do not add two-hour recording-soak or physical-device claims.
