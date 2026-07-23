[CmdletBinding()]
param(
    [string]$ExeDirectory = ".",
    [string]$NpcapInstaller = "",
    [string]$WinDivertUrl = "https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
)

$ErrorActionPreference = "Stop"
$exeDir = [IO.Path]::GetFullPath($ExeDirectory)
$exe = Join-Path $exeDir "livewire.exe"

if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw "livewire.exe was not found in $exeDir"
}

Write-Host "Livewire directory: $exeDir"

function Test-NpcapReady {
    $service = Get-Service npcap -ErrorAction SilentlyContinue
    $dll = Join-Path $env:WINDIR "System32\Npcap\wpcap.dll"
    return $null -ne $service -and (Test-Path -LiteralPath $dll -PathType Leaf)
}

if (-not (Test-NpcapReady)) {
    if ($NpcapInstaller) {
        $installer = (Resolve-Path -LiteralPath $NpcapInstaller).Path
        Write-Host "Starting the interactive Npcap installer..."
        $process = Start-Process -FilePath $installer -Verb RunAs -Wait -PassThru
        if ($process.ExitCode -notin @(0, 3010)) {
            throw "Npcap installer exited with code $($process.ExitCode)"
        }
    }
}

if (Test-NpcapReady) {
    Write-Host "Npcap: ready"
} else {
    Write-Warning "Npcap is not ready. Download the signed installer from https://npcap.com/ and rerun this script with -NpcapInstaller <path>."
}

$dllDest = Join-Path $exeDir "WinDivert.dll"
$sysDest = Join-Path $exeDir "WinDivert64.sys"
if ((Test-Path -LiteralPath $dllDest -PathType Leaf) -and
    (Test-Path -LiteralPath $sysDest -PathType Leaf)) {
    Write-Host "WinDivert: ready"
} else {
    $tempRoot = Join-Path $env:TEMP "livewire-windivert-2.2.2"
    $archive = Join-Path $env:TEMP "WinDivert-2.2.2-A.zip"

    if (Test-Path -LiteralPath $tempRoot) {
        $resolvedTemp = (Resolve-Path -LiteralPath $tempRoot).Path
        $expectedTemp = [IO.Path]::GetFullPath($tempRoot)
        if (-not $resolvedTemp.Equals($expectedTemp, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to replace unexpected temporary path $resolvedTemp"
        }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }

    Write-Host "Downloading official WinDivert 2.2.2 binaries..."
    Invoke-WebRequest -UseBasicParsing -Uri $WinDivertUrl -OutFile $archive
    Expand-Archive -LiteralPath $archive -DestinationPath $tempRoot

    $dll = Get-ChildItem -LiteralPath $tempRoot -Recurse -File -Filter WinDivert.dll |
        Where-Object FullName -Match '[\\/]x64[\\/]' |
        Select-Object -First 1
    $sys = Get-ChildItem -LiteralPath $tempRoot -Recurse -File -Filter WinDivert64.sys |
        Select-Object -First 1
    if ($null -eq $dll -or $null -eq $sys) {
        throw "The WinDivert archive did not contain the expected 64-bit DLL and driver"
    }

    Copy-Item -LiteralPath $dll.FullName -Destination $dllDest -Force
    Copy-Item -LiteralPath $sys.FullName -Destination $sysDest -Force
    Write-Host "WinDivert: copied beside livewire.exe"
}

Get-Item -LiteralPath $exe, $dllDest, $sysDest |
    Select-Object Name, Length, LastWriteTime |
    Format-Table -AutoSize

Write-Host "Next commands (run from an Administrator PowerShell):"
Write-Host "  .\livewire.exe ifaces"
Write-Host "  .\livewire.exe reproduce .\issue.pcap -to 192.168.1.50 -on '\Device\NPF_{GUID}'"
Write-Host "  .\livewire.exe live -in .\issue.pcap -iface '\Device\NPF_{GUID}' -target 192.168.1.50 -all"
