# v1.0.1 security advisory reachability review

The frozen Linux source scan reported **zero vulnerabilities in called code, zero in imported packages, and one advisory in a required module**. This is not a claim of zero module advisories or proof that unknown vulnerabilities do not exist.

The required module is `golang.org/x/crypto@v0.56.0`. [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) concerns its unmaintained OpenPGP package family; the published entry lists all versions and no fixed version. None of its seven affected packages appears in the retained dependency closure. Livewire imports other packages in the module for SSH and cryptographic primitives. This finding does not establish a reachable vulnerability in this frozen Linux build and did not block the release review.

| Review pin | Value |
| --- | --- |
| Observed | `2026-09-29T20:48:11.850174+00:00` |
| Executable-source commit | `99600ceae7c179eb758895cf6657d646ae1fe466` |
| Source digest | `8300e2e6ea1c0a0991103e8ff7664c5afa5d677d5a9fd09da540abca0c7c5dcb` |
| Toolchain | `Go 1.26.7 linux/amd64` |
| Scanner | `govulncheck v1.7.0` |

The source commit is the qualification freeze. A later documentation/evidence-only release commit may differ while preserving this executable-source digest. This review covers Linux source-mode scanning; it makes no broader platform, unsupported-build, or future-database claim.

The recorded commands ran from the frozen native Linux checkout with `GOTOOLCHAIN=go1.26.7` and `GOFLAGS="-buildvcs=false -mod=readonly"`:

```sh
go version
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 -show verbose ./...
go list -deps ./...
```

All recorded commands exited zero. [The scan output](govulncheck.stdout.log), [dependency closure](dependencies.stdout.log), [toolchain output](toolchain.stdout.log), [review metadata](review.json), and the retained [official advisory JSON](GO-2026-5932.json) support the conclusion. The original advisory was fetched from `https://vuln.go.dev/ID/GO-2026-5932.json` during the review; this bundle does not refresh its contents.

[Provenance](provenance.json) records private-original and retained hashes, the two omitted metadata fields, and text normalization. Files were reviewed for private paths, credentials, key material and unrelated host inventory. The initial PowerShell bootstrap log, empty stderr files and private diagnostic scripts are omitted. Text is UTF-8 without BOM with LF and one final newline before hashing; normalized copies are not mislabeled as byte-identical originals. `SHA256SUMS` covers every other file in this bundle.

This supplemental review does not replace the source-bound automated-check logs or the authoritative release qualification manifest. No dependency, executable source, test result, or qualification transcript was changed to prepare it.
