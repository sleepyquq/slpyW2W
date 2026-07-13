[CmdletBinding()]
param(
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $projectRoot 'tools\mihomo\1.19.28'
}

$resolvedParent = [System.IO.Path]::GetFullPath($Destination)
if (-not $resolvedParent.StartsWith($projectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Destination 必须位于 slpyW2W 工作区内。'
}

$asset = 'mihomo-windows-amd64-compatible-v1.19.28.zip'
$url = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.28/$asset"
$expectedSha256 = '6D8A079D01B3631E73E56B7B42A067AFC14F9E3AD99F2880D38BB141CF8FCBE7'

New-Item -ItemType Directory -Path $resolvedParent -Force | Out-Null
$archive = Join-Path $resolvedParent $asset
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri $url -OutFile $archive
}

$actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($actualSha256 -ne $expectedSha256) {
    throw 'Mihomo release SHA-256 校验失败；不会解压或执行该文件。'
}

$binDirectory = Join-Path $resolvedParent 'bin'
if (-not (Test-Path -LiteralPath $binDirectory)) {
    Expand-Archive -LiteralPath $archive -DestinationPath $binDirectory
}

$executable = Join-Path $binDirectory 'mihomo-windows-amd64-compatible.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'Mihomo 压缩包结构与锁定清单不一致。'
}

Write-Output "Mihomo v1.19.28 已校验：$actualSha256"
Write-Output $executable
