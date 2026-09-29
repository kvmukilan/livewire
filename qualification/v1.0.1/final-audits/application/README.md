# v1.0.1 application final audit

These are additional post-run observations for the four completed application
software-peer soaks: Windows and Linux, each running `live` and `reproduce`.
The main qualification evidence remains the source-bound run reports, execution
transcripts, independent peer checks and retained CLI reports validated by the
repository's qualification command. This bundle does not replace that gate or
assert completion of the separate packet/stateless matrices or publication.

The audit reconciled all 16 cases per run, actual three-repeat CLI executions,
request and response counters, report comparisons, capture and artifact hashes,
source/binary pins, successful two-hour case spans, process exits and cleanup.
Windows exit codes came from original process handles held by a monitor; Linux
exit codes came from the assigned supervisors. Independent final observations
checked only owned processes and target listeners. All four CLI harnesses had
exited before the cleanup snapshots.

`application-final-audit.json` is a clearly redacted copy of the private audit:
run target endpoint lists, Windows process identifiers and audited port lists
were removed. Listener counts replace port lists. Every run/case result, count,
span, hash and cleanup conclusion remains. Exact JSON Pointer removals and the
original private JSON hash are recorded in `provenance.json`.
`application-final-audit.txt` is an exact safe copy. `process-exits.json` retains
scoped exit proof, `harness-completion.log` retains only each final completion
line, and `cleanup-observations.json` retains the scoped final observations.

Raw fixture captures, TLS private keys/keylogs, credentials, baseline process
arguments, auditor code and unrelated host inventory remain private and are not
included. Private evidence paths in provenance identify retained source records;
they are not promises that those private records are distributed. Code-free
publication is intentional. All retained text is UTF-8 without a BOM and uses LF.
`SHA256SUMS` covers every retained file except itself.

This is software-lab evidence. It does not claim physical NIC/device, native
arm64, visual-browser or human-pilot qualification, a general memory-leak bound,
or one continuously running CLI process for two hours. Each CLI process ran
three repetitions; the full protocol matrix was exercised over two hours.
