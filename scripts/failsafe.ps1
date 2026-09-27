<#
.SYNOPSIS
    Предохранитель испытаний: задача SYSTEM «SplitVpn.Dev.Failsafe» через N минут и при загрузке.

.DESCRIPTION
    Запускать с повышением (обычно внутри команды elevated.ps1). Срабатывание:
    - есть файл logs\failsafe.disarm, созданный после взведения, — предохранитель снимается без действий;
    - иначе проверяется TCP 1.1.1.1:443: связь есть — снимается без действий;
    - связи нет — recover службы (или dev-утилиты) и снятие задачи.
    Снять без повышения: создать logs\failsafe.disarm (New-Item D:\VPN\logs\failsafe.disarm -Force).
#>
param(
    [Parameter(Mandatory = $true)][int]$Minutes
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root 'logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$disarm = Join-Path $logs 'failsafe.disarm'
$log = Join-Path $logs 'failsafe.log'
Remove-Item $disarm -ErrorAction SilentlyContinue
$armedAt = (Get-Date).ToString('o')

$check = @"
`$armedAt = [DateTime]::Parse('$armedAt')
`$disarm = '$disarm'
`$log = '$log'
function Done { Unregister-ScheduledTask -TaskName 'SplitVpn.Dev.Failsafe' -Confirm:`$false -ErrorAction SilentlyContinue }
if ((Test-Path `$disarm) -and (Get-Item `$disarm).LastWriteTime -gt `$armedAt) { Add-Content `$log "`$(Get-Date -Format o) снят файлом"; Done; return }
`$client = New-Object Net.Sockets.TcpClient
`$online = `$client.ConnectAsync('1.1.1.1', 443).Wait(5000) -and `$client.Connected
`$client.Dispose()
if (`$online) { Add-Content `$log "`$(Get-Date -Format o) связь есть — без действий"; Done; return }
Add-Content `$log "`$(Get-Date -Format o) связи нет — recover"
`$exe = @((Join-Path `$env:ProgramFiles 'SplitVpn.Dev\service\SplitVpn.Service.exe'), (Join-Path `$env:ProgramFiles 'SplitVpn.Dev\cli\splitvpn-cli.exe')) | Where-Object { Test-Path `$_ } | Select-Object -First 1
& `$exe recover *>> `$log
Done
"@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($check))
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
$triggers = @((New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($Minutes)), (New-ScheduledTaskTrigger -AtStartup))
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'SplitVpn.Dev.Failsafe' -Action $action -Trigger $triggers -Principal $principal -Force | Out-Null
Write-Host "Предохранитель взведён на $Minutes мин; снять: New-Item '$disarm' -Force"
