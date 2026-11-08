<#
.SYNOPSIS
    Убирает следы разработки. Запускать с повышением (через elevated.ps1).

.DESCRIPTION
    Всегда: секрет и профиль прототипа (%ProgramData%\SplitVpn.Dev), одноразовые задачи SplitVpn.Dev.*,
    сторожевая задача. С -Service: файлы %ProgramFiles%\SplitVpn.Dev\service, а если служба SplitVpn
    запускает dev-файл — ещё recover --uninstall (с данными %ProgramData%\SplitVpn) и удаление службы.
    Служба с тем же именем из MSI не трогается.
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
    # У dev-службы и службы из MSI одно имя SplitVpn и общий каталог данных. «recover --uninstall» и sc delete
    # снесли бы установленную программу: её службу, фильтры и данные. Поэтому — только если служба запускает
    # именно dev-файл; иначе служба и данные не трогаются, убираются лишь файлы dev-установки.
    $exe = Join-Path $dev 'service\SplitVpn.Service.exe'
    $registered = Get-CimInstance Win32_Service -Filter "Name='SplitVpn'" -ErrorAction SilentlyContinue
    $imagePath = if ($registered) { [string]$registered.PathName } else { '' }
    # ImagePath — путь в кавычках или без них, возможно с аргументами.
    $serviceExe = if ($imagePath -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($imagePath -match '^\s*(\S+?\.exe)\b') { $Matches[1] } else { $imagePath.Trim() }
    $isDevService = $registered -and $serviceExe -and
        [string]::Equals([IO.Path]::GetFullPath($serviceExe), [IO.Path]::GetFullPath($exe), [StringComparison]::OrdinalIgnoreCase)

    if ($isDevService) {
        if (Test-Path $exe) {
            & $exe recover --uninstall
            Write-Host "recover: код $LASTEXITCODE"
        }

        sc.exe delete SplitVpn | Write-Host
    }
    elseif ($registered) {
        Write-Warning "Служба SplitVpn запускает «$imagePath», а не dev-файл ${exe}: это установленная программа. Служба, её фильтры и данные %ProgramData%\SplitVpn не тронуты; удалите программу через «Параметры → Приложения»."
    }
    else {
        Write-Host 'Службы SplitVpn нет: recover и удаление службы пропущены (остатки в сети снимает scripts\recover-network.ps1).'
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
