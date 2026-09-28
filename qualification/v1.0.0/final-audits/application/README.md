# Additional application soak audit

These are additional post-run observations from the four completed Windows and Linux `live`/`reproduce` application soaks. The audit finished on 2026-09-28 at 23:25:43 UTC. It checked 44,308 retained evidence hashes, reconciled 30,672 CLI reports and 40,896 CLI iterations, verified the source and binary pins, and observed closure of all 64 owned target listener ports and the owned harness/CLI processes. Every protocol case spanned at least 7,200 seconds, with no failed executions.

The main release validator evidence remains the reports and transcripts referenced by the stable qualification manifest. This additional bundle does not change the manifest or replace those records. It covers software peers, not physical devices or human pilots. Each CLI process ran three repetitions; it does not establish that one CLI process stayed alive for two hours.

| File | Retention method |
| --- | --- |
| `application-final-audit.redacted.json` | All audit results preserved; only unrelated listener inventory removed as documented below. |
| `application-final-audit.txt` | Copy with CRLF line endings normalized to LF; summary wording unchanged. |
| `application-final-audit.py.txt` | Exact byte copy of the auditor, renamed for inspection. |
| `provenance.json` | Original and retained hashes, exact redaction paths, method, and privacy review. |
| `SHA256SUMS` | Checksums of the retained files, including this README. |

All public bundle files use UTF-8 without a byte-order mark and LF line endings, so Git checkout normalization preserves their checksums. The original private text summary contained 11 CRLF line endings; only those line endings changed in its public copy. Its original and retained SHA256 hashes are recorded separately in `provenance.json`. The auditor source already used LF and remains an exact byte copy.

The unredacted source JSON remains private at `coverage/v1-soak/application-final-audit.json`. Its SHA256 is `678752acff970d1958000b02e0ddd705ab092dca7cc50ab998b7f44f745ee069`. It contained unrelated host listener addresses, ports, and process identifiers. The public JSON was produced by parsing that file, deep-copying it, deleting exactly these two fields, and serializing the result with two-space indentation and a final newline:

- `/osCleanupObservations/windows/listeners` (45 unrelated entries)
- `/osCleanupObservations/linux/listeners` (1 unrelated entry)

All other JSON values and arrays are unchanged. The owned target ports, observation timestamps, empty `remainingTargetListeners` and `remainingOwnedProcesses` arrays, run results, capture digests, and source/binary hashes remain available. No private key, credential, cookie content, or unrelated process record is included. Raw PCAPs, TLS key logs, certificates, and other fixture files remain private; the audit retains their relevant digests without their contents.

The auditor is historical methodology, not a standalone public reproduction script. It requires the original ignored run directories and candidate binaries, a Windows checkout with Python 3.11 or later, PowerShell's process/TCP inspection commands, and the historical `kali-linux` WSL environment with Python 3. It contains private local filesystem references, including the original WSL checkout path. Its original output paths use exclusive creation and already exist in the audit environment. Running it on another machine requires adapting paths and supplying the private inputs; it cannot reconstruct the original completion-time OS observations. Its raw output collects broader host listener information and must receive a privacy review before publication.
