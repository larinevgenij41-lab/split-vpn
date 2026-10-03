<#
.SYNOPSIS
    Запускает команду с повышением прав (UAC) из неповышенной сессии и возвращает её вывод и код.

.DESCRIPTION
    Команда передаётся повышенному процессу через -EncodedCommand, без промежуточного файла,
    который можно подменить без прав администратора. Вывод пишется в logs\<время>-<имя>.log.
    С ключом -AsSystem команда выполняется от SYSTEM через одноразовую задачу планировщика.

.EXAMPLE
    .\scripts\elevated.ps1 -Name inspect -Command '& .\src\SplitVpn.Cli\bin\Debug\net10.0-windows10.0.19041.0\win-x64\splitvpn-cli.exe inspect'
#>
param(
    [Parameter(Mandatory = $true)][string]$Command,
    [switch]$NoElevate,
    [string]$Name = 'elevated',
    [switch]$AsSystem,
    [int]$FailsafeMinutes = 0,
    [int]$TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root 'logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $logs "$stamp-$Name.log"
$exitFile = "$log.exit"

function Quote([string]$value) { "'" + $value.Replace("'", "''") + "'" }

function Encode([string]$script) { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script)) }

$failsafeLog = Join-Path $logs "$stamp-$Name-failsafe.log"
$failsafeRecover = "& (Join-Path `$env:ProgramFiles 'SplitVpn.Dev\cli\splitvpn-cli.exe') recover *> '$failsafeLog'; Unregister-ScheduledTask -TaskName 'SplitVpn.Dev.Failsafe' -Confirm:`$false"
$failsafeEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($failsafeRecover))
$armFailsafe = if ($FailsafeMinutes -gt 0) { @"
`$fsAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -EncodedCommand $failsafeEncoded'
`$fsTriggers = @((New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($FailsafeMinutes)), (New-ScheduledTaskTrigger -AtStartup))
`$fsPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'SplitVpn.Dev.Failsafe' -Action `$fsAction -Trigger `$fsTriggers -Principal `$fsPrincipal -Force -ErrorAction Stop | Out-Null
Write-Host 'Предохранитель взведён: recover через $FailsafeMinutes мин или при загрузке, если сценарий не завершится.'
"@ } else { '' }
$disarmFailsafe = if ($FailsafeMinutes -gt 0) { "Unregister-ScheduledTask -TaskName 'SplitVpn.Dev.Failsafe' -Confirm:`$false -ErrorAction SilentlyContinue" } else { '' }

# Сценарий, который выполняется в целевом контексте (администратор или SYSTEM).
$payload = @"
`$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Set-Location $(Quote $root)
Start-Transcript -Path $(Quote $log) -Force | Out-Null
$(if (-not $AsSystem) { $armFailsafe })
`$code = 1
try {
    `$global:LASTEXITCODE = 0
    & ([scriptblock]::Create($(Quote $Command)))
    `$code = if (`$LASTEXITCODE -is [int]) { `$LASTEXITCODE } else { 0 }
} catch {
    Write-Host ('ОШИБКА: ' + `$_)
    `$code = 1
} finally {
    $(if (-not $AsSystem) { $disarmFailsafe })
    Stop-Transcript | Out-Null
    Set-Content -Path $(Quote $exitFile) -Value `$code -Encoding ASCII
}
"@

if ($AsSystem) {
    $taskName = "SplitVpn.Dev.$Name.$stamp"
    $inner = Encode $payload
    $runner = @"
$armFailsafe
`$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -EncodedCommand $inner'
`$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $(Quote $taskName) -Action `$action -Principal `$principal -Force | Out-Null
Start-ScheduledTask -TaskName $(Quote $taskName)
`$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while (-not (Test-Path $(Quote $exitFile)) -and (Get-Date) -lt `$deadline) { Start-Sleep -Milliseconds 500 }
Unregister-ScheduledTask -TaskName $(Quote $taskName) -Confirm:`$false
if (Test-Path $(Quote $exitFile)) { $disarmFailsafe }
"@
    $encoded = Encode $runner
} else {
    $encoded = Encode $payload
}

try {
    $verb = if ($NoElevate) { @{} } else { @{ Verb = 'RunAs' } }
    # Окно свёрнуто: щелчок в консоли (режим выделения QuickEdit) останавливает вывод и вместе с ним сценарий.
    $process = Start-Process -FilePath 'powershell.exe' @verb -PassThru -WindowStyle Minimized `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
} catch {
    Write-Host "Повышение отменено или недоступно: $_"
    exit 125
}

if (-not $process.WaitForExit($TimeoutSeconds * 1000 + 30000)) {
    Write-Host "Превышено время ожидания повышенного процесса ($TimeoutSeconds с)."
    exit 124
}

if (Test-Path $log) { Get-Content -Path $log -Encoding UTF8 }
if (-not (Test-Path $exitFile)) {
    Write-Host 'Код завершения не получен: сценарий не завершился штатно.'
    exit 1
}

$code = [int](Get-Content -Path $exitFile -Raw).Trim()
Remove-Item -Path $exitFile -Force
Write-Host "Код завершения: $code; журнал: $log"
exit $code
