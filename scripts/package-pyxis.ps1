[CmdletBinding()]
param(
    [string]$ConfigRoot = 'E:\Aaaovo\Documents\tools\hk-proton',
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$ReleaseName = 'slpyW2W-pyxis'
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$desktopRoot = Join-Path $projectRoot 'apps\hk-proton-desktop'
$builtApp = Join-Path $projectRoot 'target\release\hk-proton-desktop.exe'
$mihomo = Join-Path $projectRoot 'tools\mihomo\1.19.28\bin\mihomo-windows-amd64-compatible.exe'
$releaseRoot = Join-Path $projectRoot (Join-Path 'release' $ReleaseName)
$productFile = 'slpyW2W - pyxis.exe'
$expectedMihomoSha256 = 'A3799F2D75C623A7C6D307E1FAF88269E24DD746C59DF3E9F1C84D5CFBFF6C92'

$resolvedConfigRoot = (Resolve-Path -LiteralPath $ConfigRoot).Path
if (-not (Test-Path -LiteralPath $resolvedConfigRoot -PathType Container)) {
    throw 'pyxis 配置来源目录不存在。'
}
if (-not (Test-Path -LiteralPath $mihomo -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'fetch-mihomo.ps1')
}
$actualMihomoSha256 = (Get-FileHash -LiteralPath $mihomo -Algorithm SHA256).Hash
if ($actualMihomoSha256 -ne $expectedMihomoSha256) {
    throw 'Mihomo SHA-256 does not match the pinned manifest.'
}

$previousConfigRoot = $env:SLPYW2W_PYXIS_CONFIG_ROOT
$previousPyxisBuild = $env:VITE_PYXIS_BUILD
Push-Location $desktopRoot
try {
    $env:CARGO_NET_OFFLINE = 'true'
    $env:SLPYW2W_PYXIS_CONFIG_ROOT = $resolvedConfigRoot
    $env:VITE_PYXIS_BUILD = 'true'
    npm run tauri build -- --no-bundle --features pyxis --config src-tauri/tauri.pyxis.conf.json
    if ($LASTEXITCODE -ne 0) {
        throw 'pyxis Tauri release build failed.'
    }
}
finally {
    Pop-Location
    if ($null -eq $previousConfigRoot) {
        Remove-Item Env:\SLPYW2W_PYXIS_CONFIG_ROOT -ErrorAction SilentlyContinue
    }
    else {
        $env:SLPYW2W_PYXIS_CONFIG_ROOT = $previousConfigRoot
    }
    if ($null -eq $previousPyxisBuild) {
        Remove-Item Env:\VITE_PYXIS_BUILD -ErrorAction SilentlyContinue
    }
    else {
        $env:VITE_PYXIS_BUILD = $previousPyxisBuild
    }
}

New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
$productPath = Join-Path $releaseRoot $productFile
Copy-Item -LiteralPath $builtApp -Destination $productPath -Force
$legacyExternalCore = Join-Path $releaseRoot 'mihomo.exe'
if (Test-Path -LiteralPath $legacyExternalCore -PathType Leaf) {
    Remove-Item -LiteralPath $legacyExternalCore -Force
}

$manifest = [ordered]@{
    product = 'slpyW2W - pyxis'
    version = '0.1.0'
    profileCount = 9
    mihomoVersion = '1.19.28'
    files = @(
        [ordered]@{
            name = $productFile
            sha256 = (Get-FileHash -LiteralPath $productPath -Algorithm SHA256).Hash
        }
    )
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $releaseRoot 'manifest.json') -Encoding UTF8

Write-Output $releaseRoot
