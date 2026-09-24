[CmdletBinding()]
param(
    [string]$ConfigRoot = '',
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$ReleaseName = 'slpyW2W-pyxis-installer'
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$desktopRoot = Join-Path $projectRoot 'apps\hk-proton-desktop'
$tauriConfigPath = Join-Path $desktopRoot 'src-tauri\tauri.conf.json'
$bundleRoot = Join-Path $projectRoot 'target\release\bundle\nsis'
$mihomo = Join-Path $projectRoot 'tools\mihomo\1.19.28\bin\mihomo-windows-amd64-compatible.exe'
$releaseRoot = Join-Path $projectRoot (Join-Path 'release' $ReleaseName)
$targetRoot = Join-Path $projectRoot 'target'
$packageStage = Join-Path $targetRoot ("pyxis-member-package-stage-" + [Guid]::NewGuid().ToString('N'))
$resolvedTargetRoot = [IO.Path]::GetFullPath($targetRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$resolvedPackageStage = [IO.Path]::GetFullPath($packageStage)
$expectedMihomoSha256 = 'A3799F2D75C623A7C6D307E1FAF88269E24DD746C59DF3E9F1C84D5CFBFF6C92'
if (-not $resolvedPackageStage.StartsWith($resolvedTargetRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw '拒绝使用 target 目录之外的导入包暂存路径。'
}

if ([string]::IsNullOrWhiteSpace($ConfigRoot)) {
    $ConfigRoot = Join-Path $projectRoot 'pyxis-vpn-conf'
}
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

$tauriConfig = Get-Content -LiteralPath $tauriConfigPath -Raw | ConvertFrom-Json
$version = [string]$tauriConfig.version
if ([string]::IsNullOrWhiteSpace($version)) {
    throw 'tauri.conf.json does not contain a release version.'
}

$previousConfigRoot = $env:SLPYW2W_PYXIS_CONFIG_ROOT
$previousPackageStage = $env:SLPYW2W_PYXIS_PACKAGE_STAGE
$previousPyxisBuild = $env:VITE_PYXIS_BUILD
$previousCargoNetOffline = $env:CARGO_NET_OFFLINE

New-Item -ItemType Directory -Path $packageStage | Out-Null
Push-Location $desktopRoot
try {
    # 发布构建只使用锁定依赖；配置来源只用于生成各成员独立的导入包。
    $env:CARGO_NET_OFFLINE = 'true'
    $env:SLPYW2W_PYXIS_CONFIG_ROOT = $resolvedConfigRoot
    $env:SLPYW2W_PYXIS_PACKAGE_STAGE = $packageStage
    $env:VITE_PYXIS_BUILD = 'true'
    npm run tauri build -- --features pyxis --config src-tauri/tauri.pyxis.conf.json
    if ($LASTEXITCODE -ne 0) {
        throw 'pyxis Tauri installer build failed.'
    }
    $members = @('cheyuxuan', 'yanggengbo', 'zhenjiabao', 'zuoanna', 'zhouwantong')
    foreach ($member in $members) {
        $packagePath = Join-Path $packageStage "${member}.hkproton"
        if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
            throw "缺少成员导入包：$member"
        }
    }
}
catch {
    if (Test-Path -LiteralPath $resolvedPackageStage) {
        Remove-Item -LiteralPath $resolvedPackageStage -Recurse -Force
    }
    throw
}
finally {
    Pop-Location
    if ($null -eq $previousConfigRoot) {
        Remove-Item Env:\SLPYW2W_PYXIS_CONFIG_ROOT -ErrorAction SilentlyContinue
    }
    else {
        $env:SLPYW2W_PYXIS_CONFIG_ROOT = $previousConfigRoot
    }
    if ($null -eq $previousPackageStage) {
        Remove-Item Env:\SLPYW2W_PYXIS_PACKAGE_STAGE -ErrorAction SilentlyContinue
    }
    else {
        $env:SLPYW2W_PYXIS_PACKAGE_STAGE = $previousPackageStage
    }
    if ($null -eq $previousPyxisBuild) {
        Remove-Item Env:\VITE_PYXIS_BUILD -ErrorAction SilentlyContinue
    }
    else {
        $env:VITE_PYXIS_BUILD = $previousPyxisBuild
    }
    if ($null -eq $previousCargoNetOffline) {
        Remove-Item Env:\CARGO_NET_OFFLINE -ErrorAction SilentlyContinue
    }
    else {
        $env:CARGO_NET_OFFLINE = $previousCargoNetOffline
    }
}

try {
    $installer = Get-ChildItem -LiteralPath $bundleRoot -Filter "*$version*-setup.exe" -File |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $installer) {
        throw "找不到版本 $version 对应的 NSIS 安装包。"
    }

    New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
    $installerDestination = Join-Path $releaseRoot $installer.Name
    Copy-Item -LiteralPath $installer.FullName -Destination $installerDestination -Force

    $memberRoot = Join-Path $releaseRoot 'members'
    New-Item -ItemType Directory -Path $memberRoot -Force | Out-Null
    $members = @('cheyuxuan', 'yanggengbo', 'zhenjiabao', 'zuoanna', 'zhouwantong')
    $memberPackages = @()
    foreach ($member in $members) {
        $packageName = "${member}.hkproton"
        $packageSource = Join-Path $packageStage $packageName
        $packageDestination = Join-Path $memberRoot $packageName
        Copy-Item -LiteralPath $packageSource -Destination $packageDestination -Force
        $memberPackages += [ordered]@{
            memberId = $member
            name = "members/$packageName"
            sha256 = (Get-FileHash -LiteralPath $packageDestination -Algorithm SHA256).Hash
        }
    }

    $files = @(
        [ordered]@{
            name = $installer.Name
            sha256 = (Get-FileHash -LiteralPath $installerDestination -Algorithm SHA256).Hash
        }
    )
    foreach ($package in $memberPackages) {
        $files += [ordered]@{ name = $package.name; sha256 = $package.sha256 }
    }

    $manifest = [ordered]@{
        product = 'slpyW2W - Pyxis VPN'
        version = $version
        installer = 'nsis'
        packageFormat = 'hk-proton-member-package'
        packageSchemaVersion = 3
        profileCount = 51
        memberCount = 5
        sections = @('firstHopAndRelay', 'firstHopDirectOnly', 'secondHop')
        mihomoVersion = '1.19.28'
        updaterArtifacts = $false
        memberPackages = $memberPackages
        files = $files
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $releaseRoot 'manifest.json') -Encoding UTF8

    Write-Output $releaseRoot
}
finally {
    if (Test-Path -LiteralPath $resolvedPackageStage) {
        Remove-Item -LiteralPath $resolvedPackageStage -Recurse -Force
    }
}
