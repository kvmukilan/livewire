# Linux packet and stateless final audit

This supplemental audit recounts the completed v1.0.1 packet live/reproduce and
stateless replay runs. The source digest, exact Linux executable hash, original
process exit observations, per-case counts, and exact successful spans are in
`result.json` and `harness-exits.json`. All cases span at least 7,200 seconds.
For the wire cases, the run schema calls the observed frame count
`requestsObserved`; this is a frame count, not an application-request claim.
`framesObserved` appears only where the original run explicitly supplies it.

The independent Python audit rehashed every bound artifact and reparsed each
independent capture using the frozen repository's packet verifier. The Go
recorded-transcript checks executed against the completed reports, checking
evidence bindings and packet/stateless proof. Exact commands and exit codes are
retained beside their UTF-8/LF logs. These recorded checks do not generate a new
soak. The release's full qualification validator remains a separate gate.

The raw harness and Go validators are already public source at the frozen commit
recorded in `result.json`; private audit glue is not a second implementation of
protocol verification. Audit glue, original console logs, and full process
snapshots remain under ignored `coverage/`. `process-cleanup.json` publishes
only the owned process/namespace checks and the private snapshot hash, avoiding
unrelated process arguments. No fixture keys or private captures are included.

For repeated validation from the repository root, set `GOTOOLCHAIN=go1.26.7`,
`LIVEWIRE_PACKET_LAB_SMOKE` to the absolute completed linux-packet directory and
`LIVEWIRE_STATELESS_LAB_SMOKE` to the absolute completed linux-stateless directory,
then run:

```text
go test -count=1 -v ./internal/qualification -run '^TestRecorded(Packet|Stateless)LabTranscript$'
```

This is WSL2 software-network evidence. Frame replay does not claim application
matching; transport TCP does not claim supported application semantics. Physical
NIC/device behavior, Windows packet drivers, and human usability are unqualified.
`checksums.json` binds every other file in this supplemental audit bundle.
