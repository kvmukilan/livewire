# Livewire v1.1.0 software qualification evidence

Qualification record prepared 2026-10-01. Five completed GitHub-hosted software-lab runs cover **43 platform/suite/command/case combinations**, **14,822 CLI processes** and **44,466 CLI repetitions**, with zero recorded case failures and verified owned-resource cleanup. Every case spans at least 7,200 seconds. These totals include **1,299 separately observed TLS handshakes** and **148,698 stateless frames**; neither count is an application match.

| Platform | Suite / command | Cases | CLI processes | CLI repetitions | Minimum case span (s) | Run elapsed (s) | Report |
|---|---|---:|---:|---:|---:|---:|---|
| windows-amd64 | application / `live` | 17 | 3,638 | 10,914 | 7206.988056400 | 7235.838167200 | [windows-live/report.json](windows-live/report.json) |
| linux-amd64 | application / `live` | 17 | 3,723 | 11,169 | 7222.556205843 | 7250.736658439 | [linux-live/report.json](linux-live/report.json) |
| linux-amd64 | packet / `live` | 7 | 5,208 | 15,624 | 7208.025291000 | 7216.212544000 | [linux-packet/live.run.json](linux-packet/live.run.json) |
| linux-amd64 | stateless / `reproduce` | 1 | 1,126 | 3,378 | 7200.641842000 | 7201.792510000 | [linux-stateless-reproduce/reproduce.run.json](linux-stateless-reproduce/reproduce.run.json) |
| linux-amd64 | stateless / `replay` | 1 | 1,127 | 3,381 | 7202.456890000 | 7203.488622000 | [linux-stateless-replay/replay.run.json](linux-stateless-replay/replay.run.json) |

Each process used three repetitions. These are repeated CLI processes across a continuous two-hour matrix, not one uninterrupted two-hour application connection. Continuity checks bound individual executions to 120 seconds, suite idle gaps to 60 seconds, and case idle gaps to 300 seconds. Suspended, interrupted, failed and older-source diagnostic runs are excluded.

`live` creates fresh application sessions; `reproduce` sends the captured frames statelessly, and `replay` remains its compatibility alias. Each Windows/Linux application matrix contains 16 application comparison cases plus one `tls-handshake` case. The handshake case verifies a fresh TLS handshake and peer identity, sends zero application bytes, and deliberately leaves captured application replay incomplete, unverified and unmatched. It contributes handshake observations only. Stateless cases verify captured frame bytes, order and counts, and check that independent capture timestamps fall within the corresponding execution window. This does not establish original inter-packet timing fidelity, an application response match or fault reproduction. Explicit packet wire/transport cases likewise do not establish an application match.

Matching TLS secrets embedded in PCAPNG or supplied with `-keylog` allow supported captured plaintext to run on fresh verified TLS sessions. TLS application fixtures cover captured TLS 1.2 with fresh TLS 1.3; the separate handshake fixture preserves a TLS 1.2 offer. HTTP/2/3 application replay and TLS client-certificate authentication remain outside this qualification. No physical NIC/DUT, Windows Npcap driver fault behavior, native Linux arm64 runtime, or uncoached human-pilot qualification is claimed. A software response comparison or transport error alone does not establish an industrial-device fault.

## Evidence and identities

The [stable manifest](../stable.json) binds all five reports and both native check manifests. Each run directory includes `provenance.json`, `validation.json` and `SHA256SUMS`: 15 hosted proof files bind the exact candidate, workflow revision, native environment and independent Go transcript validation. Report references bind the retained per-attempt reports, peer transcripts and permitted synthetic packet captures. Private application fixtures, embedded TLS secrets, credentials, certificates, keylogs and executables are omitted. The documentation summary was recomputed from the current packaged reports; its SHA-256 is `3a4d8196e77a73fbd11a69b16b309cc9130da3885838b8771d3263c8210f833d`. Final official manifest validation remains a required publication gate.

- Tested candidate: `3d681f0b359129ebc6a86198e91a539f8ec52bfc`.
- Frozen executable source digest: `15d01d24a23a63aab99b41740f7bcf2f3f01739eabecc615d510c2980cf8f41a`.
- Toolchain: Go 1.26.7.

- windows-amd64: `a9163c27c754f819806963e3b9baeb250aba3de8881a1119780df3e6cbc60627`
- linux-amd64: `425a6d38786837f5c84ccd00d63bf6ad0c44ee262f225575d79f80678056c9dd`
- linux-arm64: `616aa58cd5d568375dabd7fe6aad52e28064a1b2bb6cb2467bb5de3c73c39d11`

- `windows-live/report.json`: `836b7e8335aeabdfcce35a33dca677d0ba45223fc98c9c526bbb8ca24d6cb225`; UTC 2026-09-30T18:18:21.5863533Z to 2026-09-30T20:18:57.4245205Z.
- `linux-live/report.json`: `2d37e10554541078c65365be31a2e614633faa26af882dddef7ac552ffd62b98`; UTC 2026-09-30T18:17:27.005836198Z to 2026-09-30T20:18:17.742494637Z.
- `linux-packet/live.run.json`: `7e30d3249f5ed4863cb7ef347d8f354b5cf59e373fc0f7738fcad9c0d6bd18c7`; UTC 2026-09-30T18:17:27.198804Z to 2026-09-30T20:17:43.411348Z.
- `linux-stateless-reproduce/reproduce.run.json`: `b342e30da1f4c9e557f6abfcea27d4d7d1b71c0f3ae808fd6138f9bde573f46b`; UTC 2026-09-30T18:17:15.197056Z to 2026-09-30T20:17:16.989566Z.
- `linux-stateless-replay/replay.run.json`: `d35c629113891c11a6f3b3bcfd2ca87bea103238737d8dbb02b3287844f80bdd`; UTC 2026-09-30T18:17:12.552653Z to 2026-09-30T20:17:16.041275Z.

## Native and browser checks

Windows and Linux passed build, vet, tests, dashboard checks, Python exporter/raw-lab tests, lint/security, race, shuffle, fuzz, coverage, corpus, protocol-fault and recovery/cleanup checks, plus six benchmark cases. Each native corpus run checked 35 cases; aggregate coverage was Windows 69.1% and Linux 69.2%. Windows also passed the recorded published-version comparison. The independently reviewed private native-audit original has SHA-256 `10d3b27ecfbacac075793fe6d8140e3f3216918c6441972890c4521c0bd7c067`; its private paths, process inventory, scratch executable and coverage profiles are not copied here. Packaged [Windows checks](windows-checks/checks.json) and [Linux checks](linux-checks/checks.json) retain the bound public-safe evidence. Native vulnerability scans found zero called-symbol and zero imported-package vulnerabilities; a module-only finding is not a finding in imported application code.

The Windows comparison used an independently audited continuation after its sparse checkout omitted committed historical checksum manifests. Only that comparison was retried after restoring the frozen files. All 14 earlier successful command records remained unchanged; the original runner failure and the successful continuation exit are retained separately.

Candidate CI completed successfully for the tested source: [push 36757281568](https://github.com/kvmukilan/livewire/actions/runs/36757281568), [pull_request 36757286314](https://github.com/kvmukilan/livewire/actions/runs/36757286314), with all eight jobs in each run successful. These candidate results do not substitute for CI on the later final evidence/docs commit.

The [reviewed rendered dashboard proof](dashboard-browser/README.md) used installed Chromium 153.0.8010.12 through Playwright at desktop 1440x1100 and mobile 390x844. Two previews opened no target connection. It observed amber application-incomplete status after a fresh verified keyless handshake with zero application bytes, successful application replay from embedded secrets without an external keylog, and a real wrong-host certificate failure remaining red. All 10 owned processes and 3 listeners were absent after cleanup. The idle hidden dashboard required a bounded forced stop; this is not evidence of graceful dashboard shutdown. Raw screenshots/fixtures/secrets/certificates remain private; safe summary and screenshot hashes are retained.

## Publication boundary and history

Before publication, the release process must validate the final stable manifest against the final assets, rebuild the full final commit from a fresh clean checkout, compare all 23 assets byte-for-byte (including exactly 19 flat Windows ZIP members), and preserve the three frozen executable hashes. The final evidence/docs commit must pass its own push and PR CI before merge/tag. The tag-triggered [Release workflow](https://github.com/kvmukilan/livewire/actions/workflows/release.yml) must rebuild, verify the committed checksums and SBOM, and publish the assets and attestations. Downloaded asset hashes and six attestation subjects must then be verified against the tagged merge commit. These are required publication gates; this document does not claim those later steps have completed. Consult the [v1.1.0 release](https://github.com/kvmukilan/livewire/releases/tag/v1.1.0) and workflow for actual publication status.

Published v1.0.0 and v1.0.1 tags, assets and evidence remain immutable. Their historical `reproduce` application behavior is recorded under those versions; v1.1.0 corrects the current command contract without rewriting past release evidence. See [v1.0.1 evidence](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/README.md) and [v1.0.0 evidence](https://github.com/kvmukilan/livewire/blob/v1.0.0/qualification/v1.0.0/README.md).

## Supplemental Modbus over TLS check

A separate [short Modbus-over-TLS check](modbus-embedded/README.md) used the same frozen Linux executable with matching TLS secrets embedded in PCAPNG and no external keylog. Three fresh, non-resumed TLS connections produced six verified Modbus responses, including reversed response order and split writes. This supports the embedded-secret application path; it is not an additional two-hour run, mTLS, full Modbus Security, or physical-device qualification.
