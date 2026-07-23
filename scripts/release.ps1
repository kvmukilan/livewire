[CmdletBinding()]
param(
    [string]$Version = "0.5.0",
    [string]$OutputRoot = "dist"
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$output = Join-Path $repo (Join-Path $OutputRoot ("v" + $Version))

if (Test-Path -LiteralPath $output) {
    $resolvedOutput = (Resolve-Path -LiteralPath $output).Path
    $resolvedDist = [IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
    if (-not $resolvedOutput.StartsWith($resolvedDist, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove output outside $resolvedDist"
    }
    Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
}
New-Item -ItemType Directory -Path $output | Out-Null

$reported = (& go run ./cmd/livewire version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $reported -ne "livewire $Version") {
    throw "Version mismatch: expected livewire $Version, got '$reported'"
}

$targets = @(
    @{ GOOS = "linux"; GOARCH = "amd64"; Name = "livewire-$Version-linux-amd64" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Name = "livewire-$Version-linux-arm64" },
    @{ GOOS = "windows"; GOARCH = "amd64"; Name = "livewire-$Version-windows-amd64.exe" }
)

Push-Location $repo
try {
    foreach ($target in $targets) {
        $env:GOOS = $target.GOOS
        $env:GOARCH = $target.GOARCH
        $env:CGO_ENABLED = "0"
        # The local workspace is intentionally untagged and dirty during RC
        # preparation. Avoid embedding the previous repository tag as a
        # misleading module version; the binary reports its explicit version.
        & go build -buildvcs=false -trimpath -ldflags "-s -w" -o (Join-Path $output $target.Name) ./cmd/livewire
        if ($LASTEXITCODE -ne 0) { throw "Build failed for $($target.GOOS)/$($target.GOARCH)" }
    }
    foreach ($document in @("LICENSE", "README.md", "SETUP.md", "WINDOWS-QUICKSTART.md", "DOCUMENTATION.md", "CHANGELOG.md", "SECURITY.md")) {
        $source = Join-Path $repo $document
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Release document is missing: $document"
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $output $document)
    }

    $setupScript = Join-Path $repo "scripts\setup-windows.ps1"
    Copy-Item -LiteralPath $setupScript -Destination (Join-Path $output "setup-windows.ps1")

    $windowsStage = Join-Path $output "windows-amd64"
    New-Item -ItemType Directory -Path $windowsStage | Out-Null
    foreach ($name in @(
        "livewire-$Version-windows-amd64.exe",
        "setup-windows.ps1",
        "WINDOWS-QUICKSTART.md",
        "SETUP.md",
        "DOCUMENTATION.md",
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "SECURITY.md"
    )) {
        Copy-Item -LiteralPath (Join-Path $output $name) -Destination $windowsStage
    }
    Rename-Item -LiteralPath (Join-Path $windowsStage "livewire-$Version-windows-amd64.exe") -NewName "livewire.exe"
    Compress-Archive -Path (Join-Path $windowsStage "*") -DestinationPath (Join-Path $output "livewire-$Version-windows-amd64.zip")
    Remove-Item -LiteralPath $windowsStage -Recurse -Force
} finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}

$checksumPath = Join-Path $output "SHA256SUMS"
$lines = Get-ChildItem -LiteralPath $output -File |
    Where-Object Name -ne "SHA256SUMS" |
    Sort-Object Name |
    ForEach-Object { "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name }
[IO.File]::WriteAllLines($checksumPath, $lines, [Text.UTF8Encoding]::new($false))

Write-Host "Built local Livewire v$Version artifacts in $output"
Get-Content -LiteralPath $checksumPath
