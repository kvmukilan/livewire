# Linux automated checks for v1.0.1

Pinned Go 1.26.7 passed build, vet, full tests, dashboard checks, static/security analysis, race, shuffle, seven fuzz targets at 200,000 iterations each, coverage and the maintained corpus. Additional package checks exercised protocol faults and recovery/cleanup. All six loader benchmark cases passed. The checks ran from a clean native Linux checkout under WSL2. An earlier mounted-checkout attempt was stopped for slow metadata traversal and is retained privately as an excluded diagnostic.

The reviewed source digest is `8300e2e6ea1c0a0991103e8ff7664c5afa5d677d5a9fd09da540abca0c7c5dcb` at commit `99600ceae7c179eb758895cf6657d646ae1fe466`. `launch.json` records the actual host/toolchain settings. Each `<check>.json` retains its command, start/finish times, exit code and source digest before/after execution; the adjacent log retains the result. `completed.json` records successful completion. `checks.json` binds the retained files by SHA256, including nested corpus and benchmark evidence.

| Statement coverage | Observed | Required |
| --- | ---: | ---: |
| Aggregate | 67.8% | 60% |
| PCAP I/O | 85.3% | 85% |
| Dashboard backend | 63.0% | 60% |
| CLI | 48.8% | 30% |
| Packet backend | 31.0% | 20% |

The loader accepted 10, 100 and 512 MiB and 1,000,000-record inputs. The 513 MiB and 1,000,001-record cases passed by rejecting the documented over-limit input. Resource records retain their actual measurement methods; sampled process memory and Go runtime accounting are not interchangeable.

Fault and recovery checks exercise response reset/timeout outcomes, TLS response deadlines, exclusion of unrelated setup/cancellation/maintenance failures from fault proof, durable completed boundaries, uncertain writes, journal identity/corruption and transport cleanup. Current regression tests also cover fresh-session defaults, secure legacy dispatch, both captured TLS versions, certificate/key failures, global wire ordering, checked stateless pacing and truthful evidence-publication failure status. Test logs establish executed checks; the separate final soaks establish two-hour case spans.

`govulncheck` found no vulnerability in called code or imported packages. It reported required-module advisory [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) for the unmaintained OpenPGP family in `golang.org/x/crypto`; Livewire does not import those affected packages. This is not a claim that every package in every required module is vulnerability-free. Staticcheck and gosec passed.

Retained text is UTF-8 without BOM and uses LF endings before hashing. Large raw coverage profiles and temporary benchmark executables are excluded from the public bundle. Private qualification fixtures and key material are not published. [Publication-selection records](publication-review.json) retain the exclusions separately; no completed test result is rewritten.

These automated checks do not assert physical NIC/device or Windows Npcap driver qualification, native arm64 runtime, human-pilot usability, or visual-browser QA. The seven separate completed software-lab reports retain the current two-hour qualification evidence.
