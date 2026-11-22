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

if ($Service -or $All) {
    # У dev-службы и службы из MSI одно имя SplitVpn и общий каталог данных. «recover --uninstall» и sc delete
    # снесли бы установленную программу: её службу, фильтры и данные. Поэтому — только если служба запускает
    # именно dev-файл; иначе служба и данные не трогаются, убираются лишь файлы dev-установки.
    $exe = Join-Path $dev 'service\SplitVpn.Service.exe'
    $registered = Get-CimInstance Win32_Service -Filter "Name='SplitVpn'" -ErrorAction Stop
    $imagePath = if ($registered) { [string]$registered.PathName } else { '' }
    # ImagePath — путь в кавычках или без них, возможно с аргументами.
    $serviceExe = if ($imagePath -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($imagePath -match '^\s*(.+?\.exe)\b') { $Matches[1] } else { $imagePath.Trim() }
    $isDevService = $registered -and $serviceExe -and
        [string]::Equals([IO.Path]::GetFullPath($serviceExe), [IO.Path]::GetFullPath($exe), [StringComparison]::OrdinalIgnoreCase)

    if ($isDevService) {
        if (-not (Test-Path -LiteralPath $exe)) { throw "Нет программы восстановления $exe. Служба сохранена." }
        if (Test-Path $exe) {
            & $exe recover --uninstall
            if ($LASTEXITCODE -ne 0) { throw "Сеть не восстановлена, код $LASTEXITCODE. Файлы для повтора сохранены." }
            Write-Host "recover: код $LASTEXITCODE"
        }

        sc.exe delete SplitVpn | Write-Host
        if ($LASTEXITCODE -ne 0) { throw "Ошибка удаления службы, код $LASTEXITCODE" }
    }
    elseif ($registered) {
        Write-Warning "Служба SplitVpn запускает «$imagePath», а не dev-файл ${exe}: это установленная программа. Служба, её фильтры и данные %ProgramData%\SplitVpn не тронуты; удалите программу через «Параметры → Приложения»."
    }
    else {
        Write-Host 'Службы SplitVpn нет: recover и удаление службы пропущены (остатки в сети снимает scripts\recover-network.ps1).'
    }

    Remove-Item -Recurse -Force (Join-Path $dev 'service'), (Join-Path $dev 'watchdog.ps1') -ErrorAction SilentlyContinue
}

$protoBackup = Join-Path $devData 'dns-backup.json'
$protoBook = Join-Path $devData 'proto.pbk'
$retainPrototype = $false
$hasBackup = (Test-Path $protoBackup) -and @((Get-Content -LiteralPath $protoBackup -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) | Where-Object { $_ }).Count -gt 0
if ($hasBackup -or (Test-Path $protoBook)) {
    $registered = Get-CimInstance Win32_Service -Filter "Name='SplitVpn'" -ErrorAction Stop
    if ($registered) {
        $retainPrototype = $true
        Write-Warning 'Служба SplitVpn зарегистрирована. Данные восстановления прототипа и dev-утилита сохранены.'
    } else {
        $recover = Join-Path $dev 'cli\splitvpn-cli.exe'
        if (-not (Test-Path $recover)) { throw "Сохранены данные прототипа: нет $recover" }
        & $recover recover
        if ($LASTEXITCODE -ne 0) { throw "Данные прототипа сохранены для повторного восстановления." }
    }
}
Get-ScheduledTask -TaskName 'SplitVpn.Dev.*' -ErrorAction SilentlyContinue | ForEach-Object {
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
    Write-Host "Задача удалена: $($_.TaskName)"
}
$removeNames = @('secret.bin', 'proto.json', 'watchdog.down')
if (-not $retainPrototype) { $removeNames += 'proto.pbk', 'dns-backup.json' }
foreach ($name in $removeNames) {
    $path = Join-Path $devData $name
    if (Test-Path $path) { Remove-Item -Force $path; Write-Host "Удалён: $path" }
}

if ($All -and -not $retainPrototype) {
    Remove-Item -Recurse -Force $dev, $devData -ErrorAction SilentlyContinue
    Write-Host "Удалены $dev и $devData"
}

if ($RemoveData) {
    Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'SplitVpn') -ErrorAction SilentlyContinue
    Write-Host 'Удалены данные службы %ProgramData%\SplitVpn'
}

$global:LASTEXITCODE = 0
