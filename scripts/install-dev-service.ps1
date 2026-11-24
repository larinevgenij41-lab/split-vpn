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

# Разрешения на запись корня репозитория для Everyone, Authenticated Users и BUILTIN\Users — по SID
# (имена локализованы). Копия функции из publish-release.ps1, где такое дерево — ошибка выпуска.
function Get-WritableTreeGrants([string]$path) {
    $broad = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-545' = 'BUILTIN\Users' }
    $writeMask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    foreach ($rule in (Get-Acl -LiteralPath $path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne 'Allow' -or -not $broad.ContainsKey($sid)) { continue }
        if (([long]$rule.FileSystemRights -band $writeMask) -eq 0) { continue }
        "$($broad[$sid]) ($sid): $($rule.FileSystemRights)"
    }
}

# Публикация из дерева уходит в службу от SYSTEM, а повышенная часть исполняет сам этот скрипт из дерева.
try { $writableGrants = @(Get-WritableTreeGrants $root) }
catch { $writableGrants = @(); Write-Warning "Не удалось проверить разрешения ${root}: $($_.Exception.Message)" }
if ($writableGrants.Count) {
    Write-Warning "Корень репозитория $root доступен на запись обычным пользователям — подменённый ими код попадёт в службу, работающую от SYSTEM:`n  $($writableGrants -join "`n  ")`nКак закрыть доступ — см. scripts\publish-release.ps1 (проверка ACL) или docs\RELEASE.md."
}

function Test-DevServiceImage([string]$imagePath, [string]$expected) {
    if ($imagePath -match '^\s*"([^"]+)"(?:\s|$)') { $file = $Matches[1] }
    elseif ($imagePath -match '^\s*(.+?\.exe)(?:\s|$)') { $file = $Matches[1] }
    else { return $false }
    return [string]::Equals([IO.Path]::GetFullPath($file), [IO.Path]::GetFullPath($expected), [StringComparison]::OrdinalIgnoreCase)
}

if (-not $InstallOnly) {
    foreach ($project in 'SplitVpn.Service', 'SplitVpn.Cli', 'SplitVpn.App') {
        $target = Join-Path $publish ($project -replace '^SplitVpn\.', '').ToLowerInvariant()
        if (Test-Path $target) { Remove-Item -Recurse -Force $target }
        dotnet publish (Join-Path $root "src\$project\$project.csproj") -c Release -o $target --nologo -v q
        if ($LASTEXITCODE -ne 0) { throw "Публикация $project завершилась с кодом $LASTEXITCODE" }
    }

    $servicePublish = Join-Path $publish 'service'
    dotnet publish (Join-Path $root 'src\SplitVpn.OpenConnect\SplitVpn.OpenConnect.csproj') -c Release -o $servicePublish --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "Не удалось опубликовать помощник AnyConnect" }
    & (Join-Path $servicePublish 'SplitVpn.OpenConnect.exe') --version
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $servicePublish 'wintun.dll'))) { throw "Не удалось проверить комплект AnyConnect и Wintun" }
    & (Join-Path $PSScriptRoot 'copy-sing-box.ps1') -Destination (Join-Path $publish 'service') | Out-Null
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
if ($existing) {
    $registered = (Get-CimInstance Win32_Service -Filter "Name='SplitVpn'" -ErrorAction Stop).PathName
    if (-not (Test-DevServiceImage $registered $exe)) { throw "Другая установка SplitVpn уже использует службу. Установка остановлена до изменений." }
}

# Готовим полный комплект до остановки службы. Прежние каталоги остаются доступны для отката.
$stage = Join-Path $dev ([guid]::NewGuid().ToString('N'))
$parts = 'service', 'cli', 'app'
$old = @()
$new = @()
$wasRunning = $existing -and $existing.Status -eq 'Running'
try {
    foreach ($part in $parts) {
        $destination = Join-Path $stage $part
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        robocopy (Join-Path $publish $part) $destination /E /R:2 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "Ошибка копирования $part, код $LASTEXITCODE" }
    }
    foreach ($required in 'SplitVpn.Service.exe', 'SplitVpn.OpenConnect.exe', 'wintun.dll', 'sing-box.exe') {
        if (-not (Test-Path -LiteralPath (Join-Path $stage "service\$required") -PathType Leaf)) { throw "В публикации отсутствует $required" }
    }
    if ($existing -and $existing.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Get-Process -Name 'SplitVpn' -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq (Join-Path $appDir 'SplitVpn.exe') } | Stop-Process -Force
    foreach ($part in $parts) {
        $live = Join-Path $dev $part
        if (Test-Path -LiteralPath $live) {
            [IO.Directory]::Move($live, (Join-Path $stage "$part.old"))
            $old += $part
        }
        [IO.Directory]::Move((Join-Path $stage $part), $live)
        $new += $part
    }
} catch {
    foreach ($part in $new) { [IO.Directory]::Move((Join-Path $dev $part), (Join-Path $stage $part)) }
    foreach ($part in $old) { [IO.Directory]::Move((Join-Path $stage "$part.old"), (Join-Path $dev $part)) }
    if ($wasRunning -and (Get-Service $serviceName).Status -eq 'Stopped') { Start-Service $serviceName }
    if (Test-Path -LiteralPath $stage) { [IO.Directory]::Delete($stage, $true) }
    throw
}
[IO.Directory]::Delete($stage, $true)

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
if ($LASTEXITCODE -ne 0) { return }
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
