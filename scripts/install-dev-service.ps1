<#
.SYNOPSIS
    Публикует службу и dev-утилиту и устанавливает службу «SplitVpn» для испытаний КТ2–КТ4.

.DESCRIPTION
    Без повышения: dotnet publish в artifacts\publish. Затем через elevated.ps1 (UAC):
    - остановка службы, если она есть (фильтры, маршруты и соединение остаются — новая служба их подхватит);
    - копирование в %ProgramFiles%\SplitVpn.Dev\service и \cli (писать туда могут только администраторы);
    - sc create SplitVpn (Auto, LocalSystem), восстановление после сбоев 5/5/30 с, запуск;
    - сторожевая задача SplitVpn.Dev.Watchdog от SYSTEM: при загрузке и каждые 5 минут; если служба
      не работает дольше 3 минут — recover. Снимается cleanup-dev.ps1 перед КТ5.
#>
param(
    [switch]$InstallOnly,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$publish = Join-Path $root 'artifacts\publish'
$serviceName = 'SplitVpn'

if (-not $InstallOnly) {
    foreach ($project in 'SplitVpn.Service', 'SplitVpn.Cli', 'SplitVpn.App') {
        $target = Join-Path $publish ($project -replace '^SplitVpn\.', '').ToLowerInvariant()
        if (Test-Path $target) { Remove-Item -Recurse -Force $target }
        dotnet publish (Join-Path $root "src\$project\$project.csproj") -c Release -o $target --nologo -v q
        if ($LASTEXITCODE -ne 0) { throw "Публикация $project завершилась с кодом $LASTEXITCODE" }
    }

    $flags = if ($NoStart) { ' -NoStart' } else { '' }
    & (Join-Path $PSScriptRoot 'elevated.ps1') -Name 'install-dev-service' -Command "& '$PSCommandPath' -InstallOnly$flags"
    exit $LASTEXITCODE
}

$dev = Join-Path $env:ProgramFiles 'SplitVpn.Dev'
$serviceDir = Join-Path $dev 'service'
$cliDir = Join-Path $dev 'cli'
$appDir = Join-Path $dev 'app'
$exe = Join-Path $serviceDir 'SplitVpn.Service.exe'

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host 'Остановка службы (системные объекты сохраняются для подхвата)...'
    Stop-Service -Name $serviceName -Force
    (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

Get-Process -Name 'SplitVpn' -ErrorAction SilentlyContinue | Stop-Process -Force
foreach ($pair in @(@('service', $serviceDir), @('cli', $cliDir), @('app', $appDir))) {
    New-Item -ItemType Directory -Force -Path $pair[1] | Out-Null
    robocopy (Join-Path $publish $pair[0]) $pair[1] /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Копирование $($pair[0]) завершилось с кодом $LASTEXITCODE" }
}

if (-not $existing) {
    sc.exe create $serviceName binPath= "`"$exe`"" start= auto obj= LocalSystem DisplayName= 'Раздельный VPN' | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "sc create завершился с кодом $LASTEXITCODE" }
    sc.exe description $serviceName 'Раздельный VPN: SSTP-подключение, маршруты RU напрямую, защита WFP и DNS-посредник.' | Out-Null
} else {
    sc.exe config $serviceName binPath= "`"$exe`"" start= auto | Out-Null
}

sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
sc.exe failureflag $serviceName 1 | Out-Null

$watchdog = @'
$ErrorActionPreference = 'Continue'
$root = Join-Path $env:ProgramData 'SplitVpn.Dev'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$down = Join-Path $root 'watchdog.down'
$log = Join-Path $root 'watchdog.log'
$service = Get-Service -Name 'SplitVpn' -ErrorAction SilentlyContinue
if (-not $service -or $service.Status -eq 'Running') { Remove-Item $down -ErrorAction SilentlyContinue; return }
if (-not (Test-Path $down)) { Set-Content -Path $down -Value (Get-Date -Format o); return }
if ((Get-Item $down).LastWriteTime -gt (Get-Date).AddMinutes(-3)) { return }
Add-Content -Path $log -Value "$(Get-Date -Format o) служба $($service.Status) дольше 3 минут — recover"
& (Join-Path $env:ProgramFiles 'SplitVpn.Dev\service\SplitVpn.Service.exe') recover *>> $log
Remove-Item $down -ErrorAction SilentlyContinue
'@
$watchdogPath = Join-Path $dev 'watchdog.ps1'
Set-Content -Path $watchdogPath -Value $watchdog -Encoding UTF8
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$watchdogPath`""
$triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'SplitVpn.Dev.Watchdog' -Action $action -Trigger $triggers -Principal $principal -Force | Out-Null
Write-Host 'Сторожевая задача SplitVpn.Dev.Watchdog установлена.'

if (-not $NoStart) {
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

Get-Service -Name $serviceName | Format-List Name, Status, StartType | Out-String | Write-Host
sc.exe qfailure $serviceName | Write-Host
$global:LASTEXITCODE = 0
