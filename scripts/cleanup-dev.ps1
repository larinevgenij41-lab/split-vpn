<#
.SYNOPSIS
    Убирает следы разработки. Запускать с повышением (через elevated.ps1).

.DESCRIPTION
    Всегда: секрет и профиль прототипа (%ProgramData%\SplitVpn.Dev), одноразовые задачи SplitVpn.Dev.*,
    сторожевая задача. С -Service: recover, удаление службы SplitVpn и %ProgramFiles%\SplitVpn.Dev\service.
    С -All: также dev-утилита. С -RemoveData: %ProgramData%\SplitVpn (настройки, база, секреты службы).
#>
param(
    [switch]$Service,
    [switch]$All,
    [switch]$RemoveData
)

$ErrorActionPreference = 'Continue'
$dev = Join-Path $env:ProgramFiles 'SplitVpn.Dev'
$devData = Join-Path $env:ProgramData 'SplitVpn.Dev'

Get-ScheduledTask -TaskName 'SplitVpn.Dev.*' -ErrorAction SilentlyContinue | ForEach-Object {
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
    Write-Host "Задача удалена: $($_.TaskName)"
}

foreach ($name in 'secret.bin', 'proto.json', 'proto.pbk', 'dns-backup.json', 'watchdog.down') {
    $path = Join-Path $devData $name
    if (Test-Path $path) { Remove-Item -Force $path; Write-Host "Удалён: $path" }
}

if ($Service -or $All) {
    $exe = Join-Path $dev 'service\SplitVpn.Service.exe'
    if (Test-Path $exe) {
        & $exe recover --uninstall
        Write-Host "recover: код $LASTEXITCODE"
    }

    if (Get-Service -Name 'SplitVpn' -ErrorAction SilentlyContinue) {
        sc.exe delete SplitVpn | Write-Host
    }

    Remove-Item -Recurse -Force (Join-Path $dev 'service'), (Join-Path $dev 'watchdog.ps1') -ErrorAction SilentlyContinue
}

if ($All) {
    Remove-Item -Recurse -Force $dev, $devData -ErrorAction SilentlyContinue
    Write-Host "Удалены $dev и $devData"
}

if ($RemoveData) {
    Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'SplitVpn') -ErrorAction SilentlyContinue
    Write-Host 'Удалены данные службы %ProgramData%\SplitVpn'
}

$global:LASTEXITCODE = 0
