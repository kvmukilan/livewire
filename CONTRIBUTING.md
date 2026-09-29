# Contributing

Livewire has one application Go module with no cgo. Go 1.26.7 or newer builds it. Release
artifacts are built with Go 1.26.7, and CI also tests the current 1.27.x.

## Build and test

```sh
go build ./...
go run ./scripts/task check   # build, vet, test, dashboard tests, lint
```

`go run ./scripts/task` lists every target. `all` runs the same gates CI runs
on every push: the race detector, shuffled tests, fuzz smoke, coverage floors,
and the regression corpus. Analysis tool versions are pinned in
`scripts/task/main.go` and nowhere else. The dashboard tests need Node.js;
everything else needs only Go.

## Layout

| Path | Holds |
|---|---|
| `cmd/livewire/` | the CLI, one file per command: flag parsing, prompts, and output |
| `internal/` | the engine, protocol adapters, replay planner, drivers, and the embedded dashboard |
| `scripts/` | the task runner, release packaging, and qualification tooling |
| `docs/` | operator documentation; the README stays short |
| `qualification/` | regression corpus and retained release evidence; a data-only module keeps Go package discovery out of artifact directories |
| `dist/v*/` | only the checksum manifest and SBOM of each published release |

## Conventions

- Every option keeps one canonical short name: `-in`, `-i`, `-t`, `-n`, `-o`,
  `-details`. Older spellings stay accepted as aliases. A deprecated alias
  warns on use and names the flag to use instead; it is removed only in a major
  release.
- Never change an explicitly selected replay mode, never reuse captured
  ciphertext as a fresh secure session, and never report a match a driver did not verify.
- Reports are additive. New fields may appear; existing fields keep their
  meaning, and a single-run report keeps its shape.
- Secrets never reach logs, reports, evidence metadata, or support bundles.
  Route every message through the redaction helpers.
- Documentation and help text spell options with one dash, the way the binary
  prints them. Both spellings parse.

## Releasing

Releases are cut from a tag. Before tagging:

1. Add the version section to `CHANGELOG.md`.
2. Set the version in `internal/buildinfo/buildinfo.go` and the release named at
   the top of each download block in `docs/SETUP.md`.
3. On Windows with Go 1.26.7, run `./scripts/release.ps1 -Version <x.y.z>`. It
   writes `dist/v<x.y.z>/`. Commit only `SHA256SUMS` and the SBOM from it; the
   binaries are ignored.
4. Push the tag. The release workflow rebuilds every artifact, proves the
   rebuilt checksum manifest is byte-identical to the committed one, publishes
   the rebuilt files to the Releases page, and attests them.

A stable tag (no `-rc` suffix) additionally requires `qualification/stable.json`
to validate against source-bound evidence for its declared profile. Version 1
uses the software-lab profile; physical-device qualification stays separate.
Run qualification tools from the repository root. `docs/PRODUCTION.md` describes
the procedure. The public Vercel site is planned in [WEBSITE_PLAN.md](docs/WEBSITE_PLAN.md).
