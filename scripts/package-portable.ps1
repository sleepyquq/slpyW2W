[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$ReleaseName = 'slpyW2W'
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$desktopRoot = Join-Path $projectRoot 'apps\hk-proton-desktop'
$builtApp = Join-Path $projectRoot 'target\release\hk-proton-desktop.exe'
$mihomo = Join-Path $projectRoot 'tools\mihomo\1.19.28\bin\mihomo-windows-amd64-compatible.exe'
$releaseRoot = Join-Path $projectRoot (Join-Path 'release' $ReleaseName)
$expectedMihomoSha256 = 'A3799F2D75C623A7C6D307E1FAF88269E24DD746C59DF3E9F1C84D5CFBFF6C92'

if (-not (Test-Path -LiteralPath $mihomo -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'fetch-mihomo.ps1')
}

$actualMihomoSha256 = (Get-FileHash -LiteralPath $mihomo -Algorithm SHA256).Hash
if ($actualMihomoSha256 -ne $expectedMihomoSha256) {
    throw 'Mihomo SHA-256 does not match the pinned manifest.'
}

Push-Location $desktopRoot
try {
    $env:CARGO_NET_OFFLINE = 'true'
    npm run tauri build -- --no-bundle
    if ($LASTEXITCODE -ne 0) {
        throw 'Tauri release build failed.'
    }
}
finally {
    Pop-Location
}

New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
Copy-Item -LiteralPath $builtApp -Destination (Join-Path $releaseRoot 'slpyW2W.exe') -Force
$legacyExternalCore = Join-Path $releaseRoot 'mihomo.exe'
if (Test-Path -LiteralPath $legacyExternalCore -PathType Leaf) {
    Remove-Item -LiteralPath $legacyExternalCore -Force
}
$legacyProductExecutable = Join-Path $releaseRoot 'HK-Proton.exe'
if (Test-Path -LiteralPath $legacyProductExecutable -PathType Leaf) {
    Remove-Item -LiteralPath $legacyProductExecutable -Force
}

$manifest = [ordered]@{
    product = 'slpyW2W'
    version = '0.1.0'
    mihomoVersion = '1.19.28'
    files = @(
        [ordered]@{
            name = 'slpyW2W.exe'
            sha256 = (Get-FileHash -LiteralPath (Join-Path $releaseRoot 'slpyW2W.exe') -Algorithm SHA256).Hash
        }
    )
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $releaseRoot 'manifest.json') -Encoding UTF8

Write-Output $releaseRoot
