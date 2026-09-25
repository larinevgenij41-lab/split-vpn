<#
.SYNOPSIS
    Сценарии сбоев КТ2 на установленной dev-службе. Запускать с повышением (через elevated.ps1).

.DESCRIPTION
    Каждый сценарий: действие → ожидание → проверки → возврат в «Подключено». Итог — logs\kt2-results-<время>.json.
    Перед запуском взводится предохранитель (failsafe.ps1). Сценарии по умолчанию — все автоматические;
    сон, гибернация, перезагрузка и перезапуск BFE сюда не входят.
#>
param(
    [string[]]$Scenario = @('double-connect', 'keep-protection', 'off', 'kill-connected', 'kill-applying', 'rasdial-disconnect',
        'wrong-password', 'memory-password-kill', 'drift', 'adapter-toggle', 'test-profile', 'dns-names', 'secret-scan', 'recover'),
    [int]$FailsafeMinutes = 60,
    [string]$ResultsTag = 'kt2'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = Split-Path -Parent $PSScriptRoot
$cli = Join-Path $env:ProgramFiles 'SplitVpn.Dev\cli\splitvpn-cli.exe'
$serviceExe = Join-Path $env:ProgramFiles 'SplitVpn.Dev\service\SplitVpn.Service.exe'
$wifi = 'Беспроводная сеть'
$entry = 'Раздельный VPN'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultsPath = Join-Path $root "logs\$ResultsTag-results-$stamp.json"
$results = New-Object System.Collections.Generic.List[object]

& (Join-Path $PSScriptRoot 'failsafe.ps1') -Minutes $FailsafeMinutes

function Log([string]$text) { Write-Host "$(Get-Date -Format 'HH:mm:ss') $text" }

function Status {
    try { (& $cli status --json | Out-String) | ConvertFrom-Json } catch { $null }
}

function WaitState([string[]]$states, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        $s = Status
        if ($s -and $s.state -in $states) { return $s }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return (Status)
}

function Probe([string]$ip, [int]$port = 443) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $ok = $client.ConnectAsync($ip, $port).Wait(5000) -and $client.Connected
        $local = if ($ok) { $client.Client.LocalEndPoint.Address.ToString() } else { $null }
        [pscustomobject]@{ Ok = $ok; Local = $local }
    } catch { [pscustomobject]@{ Ok = $false; Local = $null } } finally { $client.Dispose() }
}

function WfpGroups { (& $cli wfp-groups | Out-String) | ConvertFrom-Json }
function MarkedRoutes { @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object RouteMetric -eq 3917).Count }
function WifiDns { ((Get-DnsClientServerAddress -InterfaceAlias $wifi -AddressFamily IPv4).ServerAddresses) -join ',' }
function ServicePid { (Get-CimInstance Win32_Service -Filter "Name='SplitVpn'").ProcessId }
function LastEventId { $line = & $cli events --last 1 | Select-Object -Last 1; if ($line -match '^\s*(\d+)') { [int]$Matches[1] } else { 0 } }
function EventsSince([int]$id) { @(& $cli events --since $id --last 500) }
function DialsSince([int]$id) { @(EventsSince $id | Where-Object { $_ -match 'Подключение к' }).Count }

function Snapshot {
    $s = Status
    $foreign = Probe '1.1.1.1'
    $russian = Probe '77.88.55.242'
    [ordered]@{
        State = $s.state; Intent = $s.intent; Protection = $s.protectionActive; Suspended = $s.protectionSuspended
        ForeignOk = $foreign.Ok; ForeignLocal = $foreign.Local; RussianOk = $russian.Ok; RussianLocal = $russian.Local
        WifiDns = WifiDns; MarkedRoutes = MarkedRoutes; Wfp = (WfpGroups).total
    }
}

function EnsureConnected {
    $s = Status
    if (-not $s) {
        Start-Service SplitVpn -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $s = Status
    }
    if ($s.state -ne 'Connected') { & $cli connect | Out-Null }
    $s = WaitState @('Connected') 120
    if ($s.state -ne 'Connected') {
        # Испытание не должно оставлять компьютер без интернета: не подключилось — снимаем защиту целиком.
        Log "НЕ УДАЛОСЬ подключиться (состояние: $($s.state)) — снимаю защиту, интернет напрямую"
        & $cli disconnect | Out-Null
        throw "Подключение не восстановлено: $($s.state) $($s.errorText)"
    }
}

function ReadJson([string]$path) { Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json }
function WriteJson($object, [string]$path) { $object | ConvertTo-Json -Depth 8 | Set-Content $path -Encoding UTF8 }

function Check($record, [string]$name, [bool]$condition) {
    $record.Checks[$name] = $condition
    if (-not $condition) { $record.Passed = $false }
}

function Run([string]$name, [scriptblock]$body) {
    if ($name -notin $Scenario) { return }
    Log "=== $name"
    $record = [ordered]@{ Name = $name; Passed = $true; Checks = [ordered]@{}; Data = [ordered]@{}; Error = $null; Started = (Get-Date).ToString('o') }
    try {
        EnsureConnected
        & $body $record
    } catch {
        $record.Passed = $false
        $record.Error = "$_"
    } finally {
        try { EnsureConnected } catch { $record.Data.RestoreError = "$_"; $record.Passed = $false }
        $record.Finished = (Get-Date).ToString('o')
        $results.Add([pscustomobject]$record)
        $results | ConvertTo-Json -Depth 6 | Set-Content -Path $resultsPath -Encoding UTF8
        Log ("--- $name : " + $(if ($record.Passed) { 'ПРОЙДЕН' } else { 'НЕ ПРОЙДЕН' }))
    }
}

Run 'double-connect' {
    param($r)
    $before = LastEventId; $pidBefore = ServicePid
    & $cli connect | Out-Null
    Start-Sleep -Seconds 5
    $r.Data.After = Snapshot
    Check $r 'нет нового дозвона' ((DialsSince $before) -eq 0)
    Check $r 'служба та же' ((ServicePid) -eq $pidBefore)
    Check $r 'подключено' ($r.Data.After.State -eq 'Connected')
}

Run 'keep-protection' {
    param($r)
    & $cli disconnect --keep-protection | Out-Null
    $r.Data.Protected = Snapshot
    Check $r 'состояние Отключено' ($r.Data.Protected.State -eq 'Disconnected')
    Check $r 'защита включена' ($r.Data.Protected.Protection -eq $true)
    Check $r 'иностранный адрес заблокирован' (-not $r.Data.Protected.ForeignOk)
    Check $r 'RU напрямую через Wi-Fi' ($r.Data.Protected.RussianOk -and $r.Data.Protected.RussianLocal -like '192.168.1.*')
    Check $r 'DNS loopback' ($r.Data.Protected.WifiDns -eq '127.0.0.1')
    Check $r 'фильтры на месте' ($r.Data.Protected.Wfp -gt 0)
    & $cli connect | Out-Null
    $s = WaitState @('Connected') 90
    $r.Data.Reconnected = Snapshot
    Check $r 'подключение снова' ($s.state -eq 'Connected' -and $r.Data.Reconnected.ForeignLocal -like '192.168.44.*')
}

Run 'off' {
    param($r)
    & $cli disconnect | Out-Null
    $r.Data.Off = Snapshot
    Check $r 'фильтров нет' ($r.Data.Off.Wfp -eq 0)
    Check $r 'маршрутов с меткой нет' ($r.Data.Off.MarkedRoutes -eq 0)
    Check $r 'DNS не loopback' ($r.Data.Off.WifiDns -ne '127.0.0.1')
    Check $r 'иностранный адрес напрямую' ($r.Data.Off.ForeignOk -and $r.Data.Off.ForeignLocal -like '192.168.1.*')
    & $cli connect | Out-Null
    $s = WaitState @('Connected') 90
    Check $r 'подключение снова' ($s.state -eq 'Connected')
}

Run 'kill-connected' {
    param($r)
    $before = LastEventId; $pidBefore = ServicePid
    taskkill /F /PID $pidBefore | Out-Null
    Start-Sleep -Milliseconds 800
    $r.Data.WhileDead = [ordered]@{ Wfp = (WfpGroups).total; ForeignOk = (Probe '1.1.1.1').Ok; WifiDns = WifiDns; MarkedRoutes = MarkedRoutes }
    Check $r 'фильтры пережили kill' ($r.Data.WhileDead.Wfp -gt 0)
    Check $r 'DNS остался loopback' ($r.Data.WhileDead.WifiDns -eq '127.0.0.1')
    $s = WaitState @('Connected') 90
    $r.Data.After = Snapshot
    # После перезапуска журнал службы нумеруется заново.
    $events = EventsSince 0
    Check $r 'служба перезапущена SCM' ((ServicePid) -ne $pidBefore -and (ServicePid) -gt 0)
    Check $r 'подхват без дозвона' ((@($events | Where-Object { $_ -match 'Подхвачено' }).Count -ge 1) -and ((DialsSince 0) -eq 0))
    Check $r 'подключено' ($s.state -eq 'Connected')
}

Run 'kill-applying' {
    param($r)
    & $cli disconnect | Out-Null
    $before = LastEventId
    Start-Process -FilePath $cli -ArgumentList 'connect' -WindowStyle Hidden | Out-Null
    Start-Sleep -Milliseconds 1500
    taskkill /F /PID (ServicePid) | Out-Null
    $r.Data.WhileDead = [ordered]@{ Wfp = (WfpGroups).total; ForeignOk = (Probe '1.1.1.1').Ok }
    Check $r 'защита не снята при kill' ($r.Data.WhileDead.Wfp -gt 0)
    $s = WaitState @('Connected') 120
    $r.Data.After = Snapshot
    $r.Data.Dials = DialsSince 0
    Check $r 'подключено после перезапуска' ($s.state -eq 'Connected')
    Check $r 'не больше двух дозвонов' ($r.Data.Dials -le 2)
}

Run 'rasdial-disconnect' {
    param($r)
    $before = LastEventId
    $r.Data.Rasdial = (rasdial $entry /disconnect 2>&1 | Out-String).Trim()
    # Отключение извне (код 631): защита остаётся, повторов нет — ждём команды пользователя.
    $s = WaitState @('DisconnectedExternally') 30
    Start-Sleep -Seconds 10
    $r.Data.Gap = Snapshot
    $r.Data.Events = EventsSince $before
    Check $r 'состояние «VPN отключён извне»' ($s.state -eq 'DisconnectedExternally' -and (Status).state -eq 'DisconnectedExternally')
    Check $r 'намерение Protected, без повторов' ((Status).intent -eq 'Protected' -and (DialsSince $before) -eq 0)
    Check $r 'иностранный адрес заблокирован, защита на месте' (-not $r.Data.Gap.ForeignOk -and $r.Data.Gap.Wfp -gt 0)
    Check $r 'событие записано' (@($r.Data.Events | Where-Object { $_ -match 'отключён извне' }).Count -ge 1)
    & $cli connect | Out-Null
    $s = WaitState @('Connected') 90
    Check $r 'подключение по команде' ($s.state -eq 'Connected')
}

Run 'wrong-password' {
    param($r)
    & $cli disconnect --keep-protection | Out-Null
    $file = Join-Path $env:TEMP "kt2-wrong-$([guid]::NewGuid().ToString('N')).txt"
    Set-Content -Path $file -Value ([guid]::NewGuid().ToString('N')) -NoNewline
    & $cli password --password-file $file | Out-Null
    $before = LastEventId
    & $cli connect | Out-Null
    $s = WaitState @('Error') 60
    Start-Sleep -Seconds 20
    $r.Data.Error = Snapshot
    $r.Data.Dials = DialsSince $before
    Check $r 'состояние Ошибка' ((Status).state -eq 'Error')
    Check $r 'категория аутентификации' ((Status).errorCategory -eq 'Authentication')
    # Сервер может сначала закрыть соединение (629, повторяемая ошибка) и лишь затем ответить 691.
    $afterAuth = @(EventsSince $before | Select-String -Pattern 'Отказ аутентификации' -Context 0, 100 | ForEach-Object { $_.Context.PostContext } | Where-Object { $_ -match 'Подключение к' })
    $r.Data.DialsAfterAuthFailure = $afterAuth.Count
    Check $r 'после 691 повторов нет' ($afterAuth.Count -eq 0)
    Check $r 'защита сохранена' (-not $r.Data.Error.ForeignOk -and $r.Data.Error.Wfp -gt 0)
    & $cli profile set --name 'Основной' --from-dev-creds | Out-Null
    & $cli connect | Out-Null
    Check $r 'после верного пароля подключено' ((WaitState @('Connected') 90).state -eq 'Connected')
}

Run 'memory-password-kill' {
    param($r)
    & $cli profile set --name 'Основной' --from-dev-creds --no-save-password | Out-Null
    Check $r 'сохранённый секрет удалён' (@(EventsSince 0 | Where-Object { $_ -match 'Сохранённый пароль' }).Count -ge 1)
    & $cli connect | Out-Null
    WaitState @('Connected') 90 | Out-Null
    taskkill /F /PID (ServicePid) | Out-Null
    $s = WaitState @('Connected') 90
    Check $r 'после kill подхват без пароля' ($s.state -eq 'Connected')
    rasdial $entry /disconnect | Out-Null
    WaitState @('DisconnectedExternally') 30 | Out-Null
    & $cli connect | Out-Null
    $s = WaitState @('PasswordRequired') 60
    $r.Data.NoPassword = Snapshot
    Check $r 'требуется пароль' ($s.state -eq 'PasswordRequired')
    Check $r 'защита сохранена' (-not $r.Data.NoPassword.ForeignOk -and $r.Data.NoPassword.Wfp -gt 0)
    & $cli profile set --name 'Основной' --from-dev-creds | Out-Null
    & $cli connect | Out-Null
    Check $r 'восстановлено' ((WaitState @('Connected') 90).state -eq 'Connected')
}

Run 'drift' {
    param($r)
    $before = LastEventId
    $groupsBefore = WfpGroups
    $routesBefore = MarkedRoutes
    $victim = Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.RouteMetric -eq 3917 -and $_.DestinationPrefix -notlike '*/1' } | Select-Object -First 1
    $r.Data.Actions = @((& $cli wfp-delete-one --group Direct | Out-String).Trim(), "удалён маршрут $($victim.DestinationPrefix)")
    $victim | Remove-NetRoute -Confirm:$false
    Set-DnsClientServerAddress -InterfaceAlias $wifi -ServerAddresses 9.9.9.9
    $r.Data.Drifted = [ordered]@{ Wfp = (WfpGroups).total; MarkedRoutes = MarkedRoutes; WifiDns = WifiDns }
    $deadline = (Get-Date).AddSeconds(80)
    do { Start-Sleep -Seconds 5; $now = [ordered]@{ Wfp = (WfpGroups).total; MarkedRoutes = MarkedRoutes; WifiDns = WifiDns } }
    while ((Get-Date) -lt $deadline -and -not ($now.Wfp -eq $groupsBefore.total -and $now.MarkedRoutes -eq $routesBefore -and $now.WifiDns -eq '127.0.0.1'))
    $r.Data.Restored = $now
    $r.Data.Events = @(EventsSince $before | Where-Object { $_ -match 'извне' })
    Check $r 'изменения видны' ($r.Data.Drifted.Wfp -lt $groupsBefore.total -and $r.Data.Drifted.WifiDns -ne '127.0.0.1')
    Check $r 'фильтры восстановлены' ($now.Wfp -eq $groupsBefore.total)
    Check $r 'маршруты восстановлены' ($now.MarkedRoutes -eq $routesBefore)
    Check $r 'DNS восстановлен' ($now.WifiDns -eq '127.0.0.1')
    Check $r 'события записаны' ($r.Data.Events.Count -ge 2)
}

Run 'adapter-toggle' {
    param($r)
    $before = LastEventId
    Disable-NetAdapter -Name $wifi -Confirm:$false
    Start-Sleep -Seconds 12
    $r.Data.Down = [ordered]@{ State = (Status).state; Wfp = (WfpGroups).total }
    Enable-NetAdapter -Name $wifi -Confirm:$false
    $s = WaitState @('Connected') 180
    $r.Data.After = Snapshot
    $r.Data.Events = EventsSince $before
    Check $r 'без сети защита остаётся' ($r.Data.Down.Wfp -gt 0)
    Check $r 'подключено после включения' ($s.state -eq 'Connected')
    Check $r 'разделение работает' ($r.Data.After.ForeignLocal -like '192.168.44.*' -and $r.Data.After.RussianLocal -like '192.168.1.*')
}

Run 'bfe-restart' {
    param($r)
    $before = LastEventId
    $groupsBefore = (WfpGroups).total
    # Перезапуск BFE перезапускает и зависимые службы (брандмауэр): static-фильтры пропадают, служба обязана их пересоздать.
    Restart-Service BFE -Force
    $r.Data.BfeRestarted = (Get-Service BFE).Status.ToString()
    $deadline = (Get-Date).AddSeconds(90)
    do { Start-Sleep -Seconds 3; $now = (WfpGroups).total; $s = Status } while ((Get-Date) -lt $deadline -and -not ($now -eq $groupsBefore -and $s.state -eq 'Connected'))
    $r.Data.After = Snapshot
    $r.Data.Events = @(EventsSince $before | Where-Object { $_ -match 'BFE|Неполное' })
    Check $r 'BFE снова работает' ($r.Data.BfeRestarted -eq 'Running')
    Check $r 'фильтры пересозданы' ($r.Data.After.Wfp -eq $groupsBefore)
    Check $r 'перезапуск замечен службой' (@($r.Data.Events | Where-Object { $_ -match 'BFE' }).Count -ge 1)
    Check $r 'подключено, разделение работает' ($r.Data.After.State -eq 'Connected' -and $r.Data.After.ForeignLocal -like '192.168.44.*' -and $r.Data.After.RussianLocal -like '192.168.1.*')
}

Run 'test-profile' {
    param($r)
    $r.Data.Connected = (& $cli test-profile 2>&1 | Out-String).Trim()
    Check $r 'отчёт по сеансу при подключении' ($LASTEXITCODE -eq 0 -and $r.Data.Connected -match 'Подключено')
    & $cli disconnect --keep-protection | Out-Null
    $r.Data.Protected = (& $cli test-profile 2>&1 | Out-String).Trim()
    Check $r 'при сохранённой защите — отказ' ($r.Data.Protected -match 'отключите VPN')
    & $cli disconnect | Out-Null
    $before = LastEventId
    $r.Data.Off = (& $cli test-profile 2>&1 | Out-String).Trim()
    Check $r 'пробный дозвон успешен' ($LASTEXITCODE -eq 0 -and $r.Data.Off -match 'успешно')
    Start-Sleep -Seconds 2
    Check $r 'после пробы соединения нет, защиты нет' (-not (rasdial | Select-String $entry) -and (WfpGroups).total -eq 0 -and (Status).intent -eq 'Off')
    Check $r 'обычный дозвон не начинался' ((DialsSince $before) -eq 0)
}

Run 'dns-names' {
    param($r)
    $marker = 'kt2probe' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    1..100 | ForEach-Object { Resolve-DnsName "$marker-$_.example.com" -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null }
    Start-Sleep -Seconds 3
    $hits = @(Get-ChildItem (Join-Path $env:ProgramData 'SplitVpn'), (Join-Path $env:ProgramData 'SplitVpn.Dev') -Recurse -File -ErrorAction SilentlyContinue |
        Select-String -Pattern $marker -SimpleMatch -List -ErrorAction SilentlyContinue)
    $r.Data.Hits = @($hits | ForEach-Object { $_.Path })
    Check $r 'имён нет в данных службы' ($hits.Count -eq 0)
}

Run 'secret-scan' {
    param($r)
    $r.Data.Scan = @(& $cli secret-scan --path (Join-Path $env:ProgramData 'SplitVpn') --path (Join-Path $root 'logs') --path (Join-Path $env:ProgramFiles 'SplitVpn.Dev'))
    Check $r 'пароль не найден в файлах' ($LASTEXITCODE -eq 0)
    $acl = (Get-Acl (Join-Path $env:ProgramData 'SplitVpn\secrets.bin')).Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }
    $r.Data.SecretsAcl = $acl
    Check $r 'секрет доступен только SYSTEM и администраторам' (-not ($acl | Where-Object { $_ -notmatch 'SYSTEM|СИСТЕМА|Администраторы|Administrators' }))
}

Run 'recover' {
    param($r)
    Set-DnsClientServerAddress -InterfaceAlias $wifi -ServerAddresses 9.9.9.9
    $r.Data.Recover1 = (& $serviceExe recover | Out-String).Trim()
    $r.Data.Recover1Code = $LASTEXITCODE
    $r.Data.Recover2 = (& $serviceExe recover | Out-String).Trim()
    $r.Data.Recover2Code = $LASTEXITCODE
    $r.Data.AfterRecover = [ordered]@{ Service = (Get-Service SplitVpn).Status.ToString(); Wfp = (WfpGroups).total; MarkedRoutes = MarkedRoutes; WifiDns = WifiDns; Ras = (rasdial | Out-String).Trim(); ForeignLocal = (Probe '1.1.1.1').Local }
    Check $r 'recover дважды успешен' ($r.Data.Recover1Code -eq 0 -and $r.Data.Recover2Code -eq 0)
    Check $r 'служба остановлена' ($r.Data.AfterRecover.Service -eq 'Stopped')
    Check $r 'фильтров и маршрутов нет' ($r.Data.AfterRecover.Wfp -eq 0 -and $r.Data.AfterRecover.MarkedRoutes -eq 0)
    Check $r 'ручной DNS не перетёрт' ($r.Data.AfterRecover.WifiDns -eq '9.9.9.9')
    Check $r 'интернет напрямую' ($r.Data.AfterRecover.ForeignLocal -like '192.168.1.*')
    Set-DnsClientServerAddress -InterfaceAlias $wifi -ResetServerAddresses

    # Подделка канала при остановленной службе: клиент должен отказаться.
    $fakeScript = '$s = New-Object IO.Pipes.NamedPipeServerStream(''SplitVpn.Control'', [IO.Pipes.PipeDirection]::InOut, 1); $s.WaitForConnection(); Start-Sleep -Seconds 5; $s.Dispose()'
    $fake = Start-Process powershell -ArgumentList '-NoProfile', '-Command', $fakeScript -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 5
    $r.Data.FakePipe = try { (& $cli status 2>&1 | Out-String).Trim() } catch { "$_" }
    Stop-Process -Id $fake.Id -Force -ErrorAction SilentlyContinue
    Check $r 'поддельный канал отвергнут' ($r.Data.FakePipe -match 'не службой')

    Start-Service SplitVpn
    Start-Sleep -Seconds 4
    $s = Status
    $r.Data.Suspended = [ordered]@{ Suspended = $s.protectionSuspended; Wfp = (WfpGroups).total }
    Check $r 'после старта защита приостановлена' ($s.protectionSuspended -eq $true -and $r.Data.Suspended.Wfp -eq 0)
    & $cli connect | Out-Null
    Check $r 'Подключить снимает приостановку' ((WaitState @('Connected') 90).state -eq 'Connected')
}

# ---------- КТ4: база, режим и профиль на лету (запускать явно: -Scenario geo-bad-import,geo-rollback,switch-mode,switch-profile) ----------

Run 'geo-bad-import' {
    param($r)
    $revision = (Status).geoRevision
    $bad = Join-Path $env:TEMP 'kt4-bad-geo.txt'
    Set-Content -Path $bad -Value '<!DOCTYPE html><html><body>Rate limited</body></html>' -Encoding ASCII
    $r.Data.Html = (& $cli geo import --file $bad 2>&1 | Out-String).Trim()
    Check $r 'HTML отклонён' ($LASTEXITCODE -ne 0)
    Set-Content -Path $bad -Value "0.0.0.0/0`n10.0.0.0/8" -Encoding ASCII
    $r.Data.Zero = (& $cli geo import --file $bad 2>&1 | Out-String).Trim()
    Check $r '0/0 и частные сети отклонены' ($LASTEXITCODE -ne 0)
    Remove-Item $bad -ErrorAction SilentlyContinue
    Check $r 'активная база не изменилась' ((Status).geoRevision -eq $revision)
    Check $r 'подключение не пострадало' ((Status).state -eq 'Connected')
}

Run 'geo-rollback' {
    param($r)
    $original = (Status).geoRevision
    $list = Get-Content (Join-Path $env:ProgramData "SplitVpn\geo\revisions\$original\list.txt")
    $modified = Join-Path $env:TEMP 'kt4-geo-modified.txt'
    # Та же база без одной сети: валидна, отличается от активной.
    Set-Content -Path $modified -Value ($list | Select-Object -Skip 1) -Encoding ASCII
    $r.Data.Import = (& $cli geo import --file $modified 2>&1 | Out-String).Trim()
    Remove-Item $modified -ErrorAction SilentlyContinue
    $imported = (Status).geoRevision
    Check $r 'импорт активирован' ($LASTEXITCODE -eq 0 -and $imported -ne $original)
    Check $r 'разделение работает после импорта' ((Probe '77.88.55.242').Local -like '192.168.1.*' -and (Probe '1.1.1.1').Local -like '192.168.44.*')
    $r.Data.Rollback = (& $cli geo rollback 2>&1 | Out-String).Trim()
    Check $r 'откат вернул исходную' ((Status).geoRevision -eq $original)
    Check $r 'заменённая ревизия пропускается' ((Status).geoSkippedCount -ge 1)
    $r.Data.Update = (& $cli geo update 2>&1 | Out-String).Trim()
    Check $r 'плановая проверка не вернула пропущенную' ((Status).geoRevision -eq $original)
    & $cli geo clear-skipped | Out-Null
    Check $r 'пропуск снят' ((Status).geoSkippedCount -eq 0)
    Check $r 'подключено' ((Status).state -eq 'Connected')
}

Run 'switch-mode' {
    param($r)
    $file = Join-Path $env:TEMP 'kt4-settings.json'
    & $cli settings get --out $file | Out-Null
    $json = ReadJson $file
    $json.routingMode = 'AllViaVpn'; WriteJson $json $file
    & $cli settings set --file $file | Out-Null
    Start-Sleep -Seconds 4
    $r.Data.AllViaVpn = Snapshot
    Check $r 'весь через VPN: RU идёт в туннель' ($r.Data.AllViaVpn.RussianLocal -like '192.168.44.*' -and $r.Data.AllViaVpn.ForeignLocal -like '192.168.44.*')
    Check $r 'RU-маршрутов нет' ($r.Data.AllViaVpn.MarkedRoutes -le 5)
    Check $r 'подключение сохранилось' ($r.Data.AllViaVpn.State -eq 'Connected')
    $json.routingMode = 'RussiaDirect'; WriteJson $json $file
    & $cli settings set --file $file | Out-Null
    Start-Sleep -Seconds 6
    $r.Data.RussiaDirect = Snapshot
    Remove-Item $file -ErrorAction SilentlyContinue
    Check $r 'Россия напрямую: RU через Wi-Fi' ($r.Data.RussiaDirect.RussianLocal -like '192.168.1.*' -and $r.Data.RussiaDirect.ForeignLocal -like '192.168.44.*')
    Check $r 'RU-маршруты вернулись' ($r.Data.RussiaDirect.MarkedRoutes -gt 10000)
}

Run 'switch-profile' {
    param($r)
    $before = LastEventId
    & $cli profile set --name 'Копия' --from-dev-creds | Out-Null
    Start-Sleep -Seconds 4
    $r.Data.Copy = Snapshot
    $r.Data.CopyProfile = (Status).profileName
    Check $r 'активен профиль «Копия»' ((Status).profileName -eq 'Копия')
    Check $r 'тот же сервер — без переподключения' ((DialsSince $before) -eq 0 -and $r.Data.Copy.State -eq 'Connected')
    $file = Join-Path $env:TEMP 'kt4-settings.json'
    & $cli settings get --out $file | Out-Null
    $json = ReadJson $file
    $main = $json.profiles | Where-Object name -eq 'Основной'
    if (-not $main) { throw 'Профиль «Основной» не найден в настройках — сценарий остановлен, настройки не меняю.' }
    # Сначала вернуть активный профиль, затем отдельным сохранением удалить копию: активный удалять нельзя.
    $json.activeProfileId = $main.id; WriteJson $json $file
    $r.Data.Restore = (& $cli settings set --file $file 2>&1 | Out-String).Trim()
    $restoreCode = $LASTEXITCODE
    Start-Sleep -Seconds 3
    Check $r 'возврат к «Основной»' ((Status).profileName -eq 'Основной' -and $restoreCode -eq 0)
    $json.profiles = @($json.profiles | Where-Object name -ne 'Копия'); WriteJson $json $file
    $r.Data.Delete = (& $cli settings set --file $file 2>&1 | Out-String).Trim()
    $deleteCode = $LASTEXITCODE
    Remove-Item $file -ErrorAction SilentlyContinue
    Check $r 'копия удалена' ($deleteCode -eq 0 -and -not ((& $cli settings get | Out-String) -match 'Копия'))
    Check $r 'подключено' ((WaitState @('Connected') 60).state -eq 'Connected')
}

$passed = @($results | Where-Object Passed).Count
Log "Итог: пройдено $passed из $($results.Count); результаты: $resultsPath"
$global:LASTEXITCODE = if ($passed -eq $results.Count) { 0 } else { 1 }
