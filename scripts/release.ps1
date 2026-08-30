[CmdletBinding()]
param(
    [string]$Version = "0.8.0",
    [string]$OutputRoot = "dist"
)

$ErrorActionPreference = "Stop"
$requiredGo = "go1.26.7"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$distRoot = [IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
$output = [IO.Path]::GetFullPath((Join-Path $distRoot ("v" + $Version)))

if (-not $output.StartsWith($distRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to write release outside $distRoot"
}
if ((& go env GOVERSION).Trim() -ne $requiredGo) {
    throw "Release artifacts require $requiredGo; set GOTOOLCHAIN=$requiredGo"
}
if (Test-Path -LiteralPath $output) {
    Remove-Item -LiteralPath $output -Recurse -Force
}
New-Item -ItemType Directory -Path $output -Force | Out-Null

$reported = (& go run ./cmd/livewire version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $reported -ne "livewire $Version") {
    throw "Version mismatch: expected livewire $Version, got '$reported'"
}

$targets = @(
    @{ GOOS = "linux"; GOARCH = "amd64"; Name = "livewire-$Version-linux-amd64" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Name = "livewire-$Version-linux-arm64" },
    @{ GOOS = "windows"; GOARCH = "amd64"; Name = "livewire-$Version-windows-amd64.exe" }
)
$documents = @("LICENSE", "README.md", "SETUP.md", "WINDOWS-QUICKSTART.md", "DOCUMENTATION.md", "CHANGELOG.md", "SECURITY.md", "RELEASE_AUDIT.md")

Push-Location $repo
try {
    $env:SOURCE_DATE_EPOCH = "946684800"
    foreach ($target in $targets) {
        $env:GOOS = $target.GOOS
        $env:GOARCH = $target.GOARCH
        $env:CGO_ENABLED = "0"
        # Go's default build ID includes action hashes that can differ between
        # otherwise identical toolchain installations. Omitting it makes the
        # executable bytes portable across clean Windows release runners.
        $ldflags = "-buildid= -s -w -X github.com/kvmukilan/livewire/internal/buildinfo.Version=$Version"
        & go build -buildvcs=false -trimpath -ldflags $ldflags -o (Join-Path $output $target.Name) ./cmd/livewire
        if ($LASTEXITCODE -ne 0) { throw "Build failed for $($target.GOOS)/$($target.GOARCH)" }
        $moduleInfo = (& go version -m (Join-Path $output $target.Name) 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or $moduleInfo -notmatch 'github.com/kvmukilan/livewire') {
            throw "Module inspection failed for $($target.Name)"
        }
    }

    foreach ($name in @("GOOS", "GOARCH", "CGO_ENABLED")) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }

    foreach ($document in $documents) {
        $source = Join-Path $repo $document
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Release document is missing: $document"
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $output $document)
    }
    Copy-Item -LiteralPath (Join-Path $repo "scripts\setup-windows.ps1") -Destination (Join-Path $output "setup-windows.ps1")

    $unsignedNotice = @"
Livewire v$Version for Windows is not Authenticode-signed.

Verify SHA256SUMS before execution and obtain the release only from:
https://github.com/kvmukilan/livewire/releases/tag/v$Version

GitHub publishes build provenance attestations for the binaries, ZIP, SBOM,
and checksum manifest. Windows may display an unknown-publisher warning.
"@
    [IO.File]::WriteAllText((Join-Path $output "WINDOWS-UNSIGNED.txt"), $unsignedNotice.Trim() + "`n", [Text.UTF8Encoding]::new($false))

    $sbomPath = Join-Path $output "livewire-$Version.cdx.json"
    & go run ./scripts/releasegen.go sbom -version $Version -output $sbomPath
    if ($LASTEXITCODE -ne 0) { throw "Deterministic SBOM generation failed" }

    $windowsStage = Join-Path $output "windows-amd64"
    New-Item -ItemType Directory -Path $windowsStage -Force | Out-Null
    foreach ($name in @(
        "livewire-$Version-windows-amd64.exe", "setup-windows.ps1", "WINDOWS-QUICKSTART.md",
        "SETUP.md", "DOCUMENTATION.md", "README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md",
        "RELEASE_AUDIT.md", "WINDOWS-UNSIGNED.txt", "livewire-$Version.cdx.json"
    )) {
        Copy-Item -LiteralPath (Join-Path $output $name) -Destination $windowsStage
    }
    Rename-Item -LiteralPath (Join-Path $windowsStage "livewire-$Version-windows-amd64.exe") -NewName "livewire.exe"

    $zipPath = Join-Path $output "livewire-$Version-windows-amd64.zip"
    & go run ./scripts/releasegen.go zip -source $windowsStage -output $zipPath
    if ($LASTEXITCODE -ne 0) { throw "Deterministic Windows ZIP generation failed" }
    Remove-Item -LiteralPath $windowsStage -Recurse -Force

    $checksumPath = Join-Path $output "SHA256SUMS"
    & go run ./scripts/releasegen.go checksums -directory $output -output $checksumPath
    if ($LASTEXITCODE -ne 0) { throw "Deterministic checksum generation failed" }
} finally {
    foreach ($name in @("GOOS", "GOARCH", "CGO_ENABLED", "SOURCE_DATE_EPOCH")) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    Pop-Location
}

Write-Host "Built reproducible Livewire v$Version artifacts in $output"
Get-Content -LiteralPath $checksumPath
