[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$ReleaseName = 'slpyW2W-installer',
    [switch]$EnableUpdater,
    [string]$UpdaterEndpoint = $env:HK_PROTON_UPDATER_ENDPOINT,
    [string]$UpdaterPublicKey = $env:HK_PROTON_UPDATER_PUBLIC_KEY,
    [string]$UpdaterPublicKeyFile = $env:HK_PROTON_UPDATER_PUBLIC_KEY_FILE
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$desktopRoot = Join-Path $projectRoot 'apps\hk-proton-desktop'
$tauriConfigPath = Join-Path $desktopRoot 'src-tauri\tauri.conf.json'
$mihomo = Join-Path $projectRoot 'tools\mihomo\1.19.28\bin\mihomo-windows-amd64-compatible.exe'
$bundleRoot = Join-Path $projectRoot 'target\release\bundle\nsis'
$releaseRoot = Join-Path $projectRoot (Join-Path 'release' $ReleaseName)
$expectedMihomoSha256 = 'A3799F2D75C623A7C6D307E1FAF88269E24DD746C59DF3E9F1C84D5CFBFF6C92'
$releaseConfigPath = $null
$originalCargoNetOffline = $env:CARGO_NET_OFFLINE

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

$tauriArguments = @('build')
if ($EnableUpdater) {
    if ([string]::IsNullOrWhiteSpace($UpdaterEndpoint) -or $UpdaterEndpoint -notmatch '^https://') {
        throw '启用应用内更新时必须提供 HTTPS 的 HK_PROTON_UPDATER_ENDPOINT。'
    }

    if ([string]::IsNullOrWhiteSpace($UpdaterPublicKey) -and -not [string]::IsNullOrWhiteSpace($UpdaterPublicKeyFile)) {
        if (-not (Test-Path -LiteralPath $UpdaterPublicKeyFile -PathType Leaf)) {
            throw 'HK_PROTON_UPDATER_PUBLIC_KEY_FILE does not point to a file.'
        }
        $UpdaterPublicKey = Get-Content -LiteralPath $UpdaterPublicKeyFile -Raw
    }
    if ([string]::IsNullOrWhiteSpace($UpdaterPublicKey)) {
        throw '启用应用内更新时必须提供 HK_PROTON_UPDATER_PUBLIC_KEY 或 HK_PROTON_UPDATER_PUBLIC_KEY_FILE。'
    }
    if ([string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY)) {
        throw '启用应用内更新时必须在构建环境设置 TAURI_SIGNING_PRIVATE_KEY；私钥不会从文件复制到仓库。'
    }

    # 用临时配置注入公开更新元数据；公钥可公开，但不把发布端点绑定进开发配置。
    $releaseConfigPath = [System.IO.Path]::GetTempFileName()
    $releaseConfig = [ordered]@{
        bundle = [ordered]@{
            createUpdaterArtifacts = $true
        }
        plugins = [ordered]@{
            updater = [ordered]@{
                pubkey = $UpdaterPublicKey
                endpoints = @($UpdaterEndpoint)
            }
        }
    }
    $releaseConfig | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $releaseConfigPath -Encoding UTF8
    $tauriArguments += @('--config', $releaseConfigPath)
}

Push-Location $desktopRoot
try {
    # 发布构建只使用锁定依赖；依赖缓存缺失时由调用者先执行 cargo fetch。
    $env:CARGO_NET_OFFLINE = 'true'
    & npm run tauri -- @tauriArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Tauri installer build failed.'
    }
}
finally {
    Pop-Location
    if ($null -eq $originalCargoNetOffline) {
        Remove-Item -LiteralPath 'Env:CARGO_NET_OFFLINE' -ErrorAction SilentlyContinue
    }
    else {
        $env:CARGO_NET_OFFLINE = $originalCargoNetOffline
    }
    if ($null -ne $releaseConfigPath -and (Test-Path -LiteralPath $releaseConfigPath -PathType Leaf)) {
        Remove-Item -LiteralPath $releaseConfigPath -Force
    }
}

$installer = Get-ChildItem -LiteralPath $bundleRoot -Filter "*$version*-setup.exe" -File |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 1
if ($null -eq $installer) {
    throw "找不到版本 $version 对应的 NSIS 安装包。"
}

New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
$installerDestination = Join-Path $releaseRoot $installer.Name
Copy-Item -LiteralPath $installer.FullName -Destination $installerDestination -Force

$files = @(
    [ordered]@{
        name = $installer.Name
        sha256 = (Get-FileHash -LiteralPath $installerDestination -Algorithm SHA256).Hash
    }
)

if ($EnableUpdater) {
    $signature = Get-ChildItem -LiteralPath $bundleRoot -Filter "$($installer.BaseName).sig" -File |
        Select-Object -First 1
    if ($null -eq $signature) {
        throw '启用应用内更新时找不到 NSIS 安装包签名文件。'
    }
    $signatureDestination = Join-Path $releaseRoot $signature.Name
    Copy-Item -LiteralPath $signature.FullName -Destination $signatureDestination -Force
    $files += [ordered]@{
        name = $signature.Name
        sha256 = (Get-FileHash -LiteralPath $signatureDestination -Algorithm SHA256).Hash
    }
}

$manifest = [ordered]@{
    product = 'slpyW2W'
    version = $version
    installer = 'nsis'
    mihomoVersion = '1.19.28'
    updaterArtifacts = [bool]$EnableUpdater
    files = $files
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $releaseRoot 'manifest.json') -Encoding UTF8

Write-Output $releaseRoot
