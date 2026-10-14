# Packaging

Package-manager manifests for Livewire releases. They are pinned to the published release assets and their
`SHA256SUMS`; nothing here builds from source. Update the version, URLs and hashes together on each release.

## Scoop (works today, no extra repo needed)

Users can install straight from this manifest URL:

```powershell
scoop install https://raw.githubusercontent.com/kvmukilan/livewire/main/packaging/scoop/livewire.json
```

`checkver: github` + `autoupdate` let `scoop update` follow new tags once the manifest lives in a bucket.
To publish in a bucket later, create a repo (e.g. `kvmukilan/scoop-bucket`) with `bucket/livewire.json` and users run
`scoop bucket add kvmukilan https://github.com/kvmukilan/scoop-bucket`. Submitting to the community
`ScoopInstaller/Extras` bucket is optional and is a public PR in the maintainer's name.

## winget (needs a PR to microsoft/winget-pkgs, filed by the maintainer)

`packaging/winget/manifests/k/kvmukilan/livewire/1.2.0/` follows the winget-pkgs layout (manifest schema 1.6.0).
The installer is the release zip with `livewire.exe` as a nested portable, exposed as the `livewire` command.

Validate locally before filing:

```powershell
winget validate --manifest packaging\winget\manifests\k\kvmukilan\livewire\1.2.0
winget install --manifest packaging\winget\manifests\k\kvmukilan\livewire\1.2.0   # needs "Enable local manifest files" in winget settings
```

Then copy the three YAML files into a fork of https://github.com/microsoft/winget-pkgs under
`manifests/k/kvmukilan/livewire/1.2.0/` and open a PR titled `New package: kvmukilan.livewire version 1.2.0`.
The binary is unsigned (see `WINDOWS-UNSIGNED.txt` in the release); winget accepts unsigned portable packages,
but SmartScreen may warn on first run. Future versions can be submitted with
`wingetcreate update kvmukilan.livewire --version <ver> --urls <zip-url> --submit`.

## Homebrew (not included)

A tap needs its own repo (`kvmukilan/homebrew-tap`) with a formula that downloads the Linux/macOS binaries.
Livewire currently publishes Linux amd64/arm64 only, so a formula would be Linux-only until macOS builds exist.
