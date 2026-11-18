<#
.SYNOPSIS
    Скачивает движок подключения «VPN поверх SSH» (sing-box) и архив его исходников, сверяя SHA-256.

.DESCRIPTION
    Версия, адреса и хеши - в third_party\sing-box\manifest.json. Программа кладётся в
    third_party\sing-box\bin (в git не хранится), архив исходников - в third_party\sing-box\work:
    он прикладывается к выпуску рядом с установщиком (условие GPL-3.0).

    Обычный запуск требует хеши в манифесте и останавливается при любом расхождении.
    -Pin закрепляет новую версию: скачивает файлы, показывает их хеши и записывает в манифест.
    Закреплять только после проверки файла; изменение манифеста - отдельным коммитом.

.EXAMPLE
    scripts\fetch-sing-box.ps1
    scripts\fetch-sing-box.ps1 -Pin
#>
param(
    [switch]$Pin,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$base = Join-Path $root 'third_party\sing-box'
$manifestPath = Join-Path $base 'manifest.json'
$work = Join-Path $base 'work'
$bin = Join-Path $base 'bin'
$manifest = Get-Content $manifestPath -Raw -Encoding utf8 | ConvertFrom-Json

function Hash([string]$path) { (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Fetch($item, [string]$what) {
    $target = Join-Path $work $item.name
    if ($Force -or -not (Test-Path $target)) {
        Write-Host "Скачивание: $($item.url)"
        Invoke-WebRequest $item.url -OutFile "$target.part" -UseBasicParsing
        Move-Item "$target.part" $target -Force
    }

    $actual = Hash $target
    if ($Pin) {
        Write-Host "$what`: SHA-256 $actual"
        $item.sha256 = $actual
    }
    elseif (-not $item.sha256) {
        throw "В $manifestPath нет SHA-256 для «$what»: версия не закреплена. Закрепление: scripts\fetch-sing-box.ps1 -Pin."
    }
    elseif ($actual -ne $item.sha256.ToLowerInvariant()) {
        Remove-Item $target -Force
        throw "SHA-256 «$what» ($actual) не совпадает с $manifestPath ($($item.sha256)). Файл удалён: скачан повреждённым или подменён."
    }

    return $target
}

New-Item -ItemType Directory -Force -Path $work, $bin | Out-Null
$archive = Fetch $manifest.archive 'архив выпуска'
Fetch $manifest.source 'архив исходников' | Out-Null

# Архив распаковывается в отдельную пустую папку: из неё берутся только программа и текст лицензии.
$unpacked = Join-Path $work 'unpacked'
if (Test-Path $unpacked) { Remove-Item $unpacked -Recurse -Force }
Expand-Archive $archive -DestinationPath $unpacked
$exe = Get-ChildItem $unpacked -Recurse -Filter $manifest.executable.name | Select-Object -First 1
if (-not $exe) { throw "В архиве $($manifest.archive.name) нет $($manifest.executable.name)" }
$actualExe = Hash $exe.FullName
if ($Pin) {
    Write-Host "Программа: SHA-256 $actualExe"
    $manifest.executable.sha256 = $actualExe
}
elseif ($actualExe -ne $manifest.executable.sha256.ToLowerInvariant()) {
    throw "SHA-256 $($manifest.executable.name) ($actualExe) не совпадает с $manifestPath ($($manifest.executable.sha256))."
}

Copy-Item $exe.FullName (Join-Path $bin $manifest.executable.name) -Force
$license = Get-ChildItem $unpacked -Recurse -Filter 'LICENSE*' | Select-Object -First 1
if ($license) { Copy-Item $license.FullName (Join-Path $bin 'LICENSE.txt') -Force }
Remove-Item $unpacked -Recurse -Force

if ($Pin) {
    # Манифест хранится с CRLF и без BOM, как остальные файлы репозитория.
    $json = ($manifest | ConvertTo-Json -Depth 5) -replace "`r?`n", "`r`n"
    [IO.File]::WriteAllText($manifestPath, $json + "`r`n", (New-Object Text.UTF8Encoding $false))
    Write-Host "Хеши записаны в $manifestPath. Проверьте файл и закоммитьте манифест отдельным коммитом."
}

Write-Host "Движок: $(Join-Path $bin $manifest.executable.name) (версия $($manifest.version))"
