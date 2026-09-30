# Livewire 1.1.0 release audit

The command correction is in qualification. `live` is stateful application
replay; `reproduce` is stateless captured-packet transmission. `replay` remains
a stateless compatibility alias. See [command migration](V1_FOLLOWUP.md).

No v1.1.0 completion claim is made until source-bound automated checks, the
five required two-hour software-lab runs, final manifest validation, clean
artifact reproduction and final CI have passed. Publication also requires
the tag-triggered release workflow, exact published checksums and provenance
verification. This record will be completed with the actual evidence before
stable publication.

The immutable [v1.0.1 audit](https://github.com/kvmukilan/livewire/blob/v1.0.1/docs/RELEASE_AUDIT.md)
and [evidence](https://github.com/kvmukilan/livewire/blob/v1.0.1/qualification/v1.0.1/README.md)
remain the record for that version, not qualification for these changes.

Physical NICs/DUTs, native Linux arm64 runtime and human-pilot qualification
remain outside the software-lab profile. Dashboard API tests and website tests
are separate evidence; neither is a substitute for physical-device testing.
Windows binaries remain unsigned and should be verified using checksums and
GitHub provenance attestations.
