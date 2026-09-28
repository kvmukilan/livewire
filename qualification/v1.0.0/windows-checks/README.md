# Windows automated checks for 1.0.0

Reviewed executable source: `f01dd0fd79190f0e3754fdc535fe187a75ade0341e482eb24d8fa1809c7f7122` at commit `26a90c8f419046cda70da850ab5f5481aa1bd5c1`. Platform: `windows-amd64`.

Pinned Go 1.26.7 completed build, vet, full tests, and dashboard tests, then staticcheck found naming warning ST1012 in the ignored diagnostic probe under `coverage/`. The probe received `//go:build ignore`; executable source and its digest did not change. The original exit-1 log is retained honestly. A successful continuation ran lint, race, shuffle, fuzz, coverage, and corpus, followed by fresh benchmark and release-comparison commands.

`logs/01-gates-resolved-ignored-probe-lint.log` contains build/vet/test/dashboard passes and the resolved ignored-probe warning. Log 02 contains all remaining gate passes and coverage percentages; logs 03/04 contain fresh benchmark and release comparison results. Command/exit records are in `execution/`.

| Required check | Completed evidence |
| --- | --- |
| build | `go build ./...` passed in gate logs |
| vet | `go vet ./...` passed in gate logs |
| test | `go test -count=1 ./...` passed in gate logs |
| race | `go test -race -count=1 ./...` passed in gate logs |
| dashboard | `node --test scripts/dashboard.test.cjs` passed in gate logs |
| corpus | Nine required packages passed; named test JSONL transcripts and bound corpus results retained in `corpus/` |
| protocol-faults | Reviewed mapping from completed full test/race runs for CLI, replay, TLS, adapters, dissect, and engine packages to scenarios below |
| recovery-cleanup | Reviewed mapping from completed full test/race runs and named corpus tests for durable state, transport shutdown, guards, and evidence cleanup |

Additional completed gates include static/vulnerability analysis, three shuffled repetitions across packages plus twenty webui repetitions, and seven fuzz targets with 200,000 iterations each. Coverage floors passed: aggregate coverage: 67.1% (required 60%); pcapio coverage: 85.3% (required 85%); webui coverage: 62.6% (required 60%); cmd coverage: 46.7% (required 30%); backend coverage: 30.0% (required 20%).

All six fresh benchmark cases passed on pinned Go 1.26.7 and bind to this source digest. The expected 513 MiB and 1,000,001-record input-limit rejections are successful limit tests. Memory fields retain their actual sampling method; heap/runtime reservation and sampled RSS are distinct measurements.

## Reviewed scenarios and boundaries

Protocol faults: `TestFrontDoorsObserveFaultWithoutClaimingMatch` exercises reset and timeout through both front doors; `TestTLSResponseFaultAndActualRequestCount` checks TLS response timeout; `TestApplicationResponseTimeoutAcrossFrontDoors` checks response budgets. `TestFaultExpectationExcludesUnrelatedFailures` and `TestExpectedResponseFailureMarkerExcludesMaintenanceAndCancellation` exclude unrelated dial, EOF, maintenance, cancellation, journal, and cleanup failures from fault proof. The new `internal/replay/pacing_deadline_test.go` regressions exercise absolute capture/exchange deadlines, tiny capture targets, legacy unspecified-timeout behavior, and maintenance/control failure propagation.

Recovery: `TestCompletedReadResumeDoesNotResendAndAliasesAgree`, `TestUncertainWriteRequiresLiveRecoveryProof`, `TestProcessTerminationResumeDecisions`, `TestJournalLockAndIdentity`, `TestJournalTailRecoveryAndCommittedCorruption`, and `TestPreviewDoesNotMutateAndFailedWritesStop` cover durable progress and safe recovery. The process-termination test kills actual children at before-send, after-send, after-response, and completed boundaries; it does not claim termination during checkpoint publication.

Cleanup: retained named corpus transcripts cover backend/guard release on success, error, and cancellation; FTP blocked control/data cancellation and response deadlines; atomic-output collisions; and retained evidence after cancelled repetitions. These are software checks, including simulated backend/guard behavior. Package-pass logs establish the completed runs; this review does not invent a separate named gate.

## Evidence handling

Copies are UTF-8 without BOM with LF endings before hashing. `copy-index.json` records original and copied hashes; `checks.json` hashes every retained file. Nested corpus and benchmark references were reverified. `source-freeze.json` is the contemporaneous pre-qualification template with pending fields, not the final release manifest. `build-proof.json` records two matching builds of the tested source. Large raw coverage profiles, captures, credentials, private keys, and executable files are omitted. Prior-source checks remain in the private `coverage/v1-checks-pre-pacing-archive` and are not current evidence.

These completed automated checks do not assert two-hour soak completion, physical NIC/device or Windows Npcap fault qualification, or human-pilot validation. The separately retained pacing failure diagnostic is explicitly excluded from passing qualification.
