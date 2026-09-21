<#
.SYNOPSIS
    Полуавтоматические сценарии живой проверки AnyConnect (КТ6). Запускать в консоли PowerShell с правами администратора.

.DESCRIPTION
    Скрипт проверяет установленную службу SplitVpn и туннель AnyConnect (помощник SplitVpn.OpenConnect).
    Вход SSO, обрыв Wi-Fi и окно recover-network.cmd выполняет человек: в этих местах скрипт ждёт Enter.
    Поэтому запускать нужно в обычном окне «PowerShell (администратор)», а не через elevated.ps1:
    у elevated.ps1 свёрнутое окно, и отвечать на вопросы в нём неудобно.

    Сценарии (имена для -Scenario и -Skip):
      sso           вход SSO → туннель поднят; check <цель> — через туннель, интерфейс Wintun
      dtls          DTLS активен (status --json и tunnels)
      dns           внутреннее имя — запрос на DNS шлюза, публичное — нет (захват pktmon; без него — ручной шаг)
      routing       check <шлюз> — напрямую; check <публичный сайт> — не в AnyConnect
      wifi          обрыв Wi-Fi (ручной шаг) → переподключение без SSO
      kill-helper   kill SplitVpn.OpenConnect → сети шлюза сняты, запрос входа
      service-stop  остановка службы → сети сняты, помощника нет; старт → запрос входа
      role-off      роль «Выключено» (settings get/set) → нет процесса и адаптера
      recover       recover-network.cmd → нет процессов помощника, маршрутов с меткой 3917 и фильтров WFP

    Итог — таблица PASS/FAIL/SKIP и logs\kt-ac-results-<время>.json. Код выхода 0, если нет FAIL.

.EXAMPLE
    .\scripts\kt-ac-scenarios.ps1
.EXAMPLE
    .\scripts\kt-ac-scenarios.ps1 -ProfileName Офис -Skip wifi,recover
#>
param(
    [string]$ProfileName = 'Офис',
    [ValidateSet('sso', 'dtls', 'dns', 'routing', 'wifi', 'kill-helper', 'service-stop', 'role-off', 'recover')]
    [string[]]$Scenario = @('sso', 'dtls', 'dns', 'routing', 'wifi', 'kill-helper', 'service-stop', 'role-off', 'recover'),
    [ValidateSet('sso', 'dtls', 'dns', 'routing', 'wifi', 'kill-helper', 'service-stop', 'role-off', 'recover')]
    [string[]]$Skip = @(),
    [string]$Target = '10.0.16.21',
    [string]$TunnelDns = '10.0.16.21',
    [string]$InternalName = 'x.office.example.org',
    [string]$PublicName = 'ya.ru',
    [string]$GatewayName = 'avpn.example.org',
    [string]$PolicyName = 'www.example.org',
    [string]$Cli = '',
    [int]$FailsafeMinutes = 90,
    [int]$SignInTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = Split-Path -Parent $PSScriptRoot
$serviceName = 'SplitVpn'
$helperName = 'SplitVpn.OpenConnect'
$marker = 3917
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logs = Join-Path $root 'logs'
$work = Join-Path $logs "kt-ac-$stamp"
$resultsPath = Join-Path $logs "kt-ac-results-$stamp.json"
$results = New-Object System.Collections.Generic.List[object]

# ---------- Предварительные проверки ----------

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Нужны права администратора: остановка службы, pktmon и wfp-groups без них не работают.'
    Write-Host 'Откройте «PowerShell (администратор)» и запустите скрипт снова.'
    exit 1
}

if (-not $Cli) {
    $Cli = @(
        (Join-Path $root 'src\SplitVpn.Cli\bin\Release\net10.0-windows10.0.19041.0\win-x64\splitvpn-cli.exe'),
        (Join-Path $root 'src\SplitVpn.Cli\bin\Debug\net10.0-windows10.0.19041.0\win-x64\splitvpn-cli.exe'),
        (Join-Path $env:ProgramFiles 'SplitVpn.Dev\cli\splitvpn-cli.exe')
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Cli -or -not (Test-Path $Cli)) {
    Write-Host 'Не найден splitvpn-cli.exe: соберите решение или укажите путь в -Cli.'
    exit 1
}

New-Item -ItemType Directory -Force -Path $work | Out-Null
if ($FailsafeMinutes -gt 0) { & (Join-Path $PSScriptRoot 'failsafe.ps1') -Minutes $FailsafeMinutes }

# ---------- Вспомогательные функции ----------

function Log([string]$text) { Write-Host "$(Get-Date -Format 'HH:mm:ss') $text" }

# Запуск внешней программы: вывод строками и код. Ошибки stderr в PowerShell 5.1 не должны прерывать сценарий.
function Native([string]$file, [string[]]$arguments) {
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = 0
    $lines = @(& $file @arguments 2>&1 | ForEach-Object { "$_" })
    [pscustomobject]@{ Code = $LASTEXITCODE; Lines = $lines; Text = ($lines -join [Environment]::NewLine) }
}

function Cli([string[]]$arguments) { Native $Cli $arguments }

function Pause([string]$text) {
    Write-Host ''
    Write-Host ">>> $text" -ForegroundColor Yellow
    [void](Read-Host 'Нажмите Enter, чтобы продолжить')
}

# Вопрос человеку: $true — да, $false — нет, $null — пропустить проверку.
function Ask([string]$question) {
    while ($true) {
        Write-Host ''
        $answer = Read-Host ">>> $question [д — да, н — нет, п — пропустить]"
        if ($null -eq $answer) { $answer = '' }
        $answer = $answer.Trim().ToLowerInvariant()
        if ($answer -in 'д', 'да', 'y', 'yes') { return $true }
        if ($answer -in 'н', 'нет', 'n', 'no') { return $false }
        if ($answer -in 'п', 's', 'skip') { return $null }
    }
}

function Status {
    $r = Cli @('status', '--json')
    if ($r.Code -ne 0) { return $null }
    try { return ($r.Text | ConvertFrom-Json) } catch { return $null }
}

function Tunnel {
    $s = Status
    if (-not $s) { return $null }
    return (@($s.tunnels) | Where-Object { $_.name -eq $ProfileName } | Select-Object -First 1)
}

function WaitTunnel([scriptblock]$predicate, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        $t = Tunnel
        if ($t -and (& $predicate $t)) { return $t }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return (Tunnel)
}

function Settings {
    $r = Cli @('settings', 'get')
    if ($r.Code -ne 0) { throw "settings get: $($r.Text)" }
    return ($r.Text | ConvertFrom-Json)
}

function SaveSettings($settings) {
    $file = Join-Path $work "settings-$([guid]::NewGuid().ToString('N')).json"
    $settings | ConvertTo-Json -Depth 32 | Set-Content -Path $file -Encoding UTF8
    try { return (Cli @('settings', 'set', '--file', $file)) } finally { Remove-Item $file -ErrorAction SilentlyContinue }
}

function Helpers { @(Get-Process -Name $helperName -ErrorAction SilentlyContinue) }

function WaitNoHelpers([int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Helpers).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
    return (Helpers).Count
}

# Адаптер туннеля служба называет «SplitVpn AC <первые 8 символов id профиля>».
function AcAdapters {
    @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "SplitVpn AC $script:idPrefix*" })
}

function IsWintun([string]$name) {
    if (-not $name) { return $false }
    $a = Get-NetAdapter -IncludeHidden -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $a) { return $false }
    return ("$($a.InterfaceDescription) $($a.DriverDescription) $($a.ComponentID)" -match 'wintun')
}

function AcRoutes { @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -like "SplitVpn AC $script:idPrefix*" }).Count }
function MarkedRoutes { @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object RouteMetric -eq $marker).Count }

function RouteInterface([string]$ip) {
    try { (Find-NetRoute -RemoteIPAddress $ip -ErrorAction Stop | Where-Object { $_.InterfaceAlias } | Select-Object -First 1).InterfaceAlias } catch { $null }
}

function WfpTotal {
    $r = Cli @('wfp-groups')
    try { return [int](($r.Text | ConvertFrom-Json).total) } catch { return -1 }
}

function LastEventId {
    $line = (Cli @('events', '--last', '1')).Lines | Select-Object -Last 1
    if ($line -match '^\s*(\d+)') { [int]$Matches[1] } else { 0 }
}
function EventsSince([int]$id) { @((Cli @('events', '--since', "$id", '--last', '500')).Lines) }
function AcDialsSince([int]$id) { @(EventsSince $id | Where-Object { $_ -match [regex]::Escape("Подключение к «$ProfileName» (AnyConnect") }).Count }

# Разбор вывода «check»: «адрес: Decision (Source); ожидается X, маршрут Y[, заблокировано]».
function CheckAddress([string]$query) {
    $r = Cli @('check', $query)
    $items = @()
    foreach ($line in $r.Lines) {
        if ($line -match '^(\d{1,3}(?:\.\d{1,3}){3}): (\S+) \((\S+)\); ожидается (.+?), маршрут (.+?)(, заблокировано)?$') {
            $items += [pscustomobject]@{
                Address = $Matches[1]; Decision = $Matches[2]; Source = $Matches[3]
                Expected = $Matches[4]; Actual = $Matches[5]; Blocked = [bool]$Matches[6]
            }
        }
    }
    [pscustomobject]@{ Text = $r.Text; Items = $items }
}

function EnsureService {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) { throw "Служба $serviceName не установлена." }
    if ($service.Status -ne 'Running') {
        Log 'Служба не запущена — запускаю'
        Start-Service -Name $serviceName
    }
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Status) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    if (-not (Status)) { throw 'Служба не отвечает на status.' }
}

# Туннель AnyConnect поднят; иначе начать вход и попросить человека пройти SSO.
function EnsureTunnel($record) {
    EnsureService
    $t = Tunnel
    if ($t -and $t.state -eq 'Connected' -and $t.serverNetworks) { return $t }
    $s = Status
    if ($s.intent -ne 'Connected' -or $s.protectionSuspended) {
        Log 'Команда connect'
        Cli @('connect') | Out-Null
    }
    $t = Tunnel
    if (-not ($t -and $t.signIn -and $t.signIn.kind -ne 'Required')) {
        Log "Команда sign-in --profile $script:profileId"
        $r = Cli @('sign-in', '--profile', $script:profileId)
        if ($r.Code -ne 0) { throw "sign-in: $($r.Text)" }
    }
    Pause "Выполните вход в «$ProfileName» (SSO) в окне «Раздельный VPN». Если окно не открылось — запустите интерфейс и нажмите «Войти» на главной. После входа нажмите Enter."
    $t = WaitTunnel { param($x) $x.state -eq 'Connected' -and $x.serverNetworks } $SignInTimeoutSeconds
    if ($record) { $record.Data.SignInPerformed = $true }
    if (-not ($t -and $t.state -eq 'Connected' -and $t.serverNetworks)) {
        throw "Туннель «$ProfileName» не поднялся: состояние $($t.state), $($t.errorText)"
    }
    return $t
}

function Check($record, [string]$name, [bool]$condition) {
    $record.Checks[$name] = $condition
    if (-not $condition) { $record.Failed = $true }
    Log ("    " + $(if ($condition) { '[+]' } else { '[-]' }) + " $name")
}

# Ответ человека: $null — проверка пропущена и на итог не влияет.
function ManualCheck($record, [string]$name, $answer) {
    if ($null -eq $answer) {
        $record.Checks[$name] = 'пропущено'
        Log "    [?] $name — пропущено"
        return
    }
    Check $record $name ([bool]$answer)
}

function Run([string]$name, [string]$title, [bool]$needsTunnel, [scriptblock]$body) {
    if ($Scenario -notcontains $name) { return }
    $record = [ordered]@{
        Name = $name; Title = $title; Result = 'SKIP'; Failed = $false; Skipped = $false
        Checks = [ordered]@{}; Data = [ordered]@{}; Error = $null; Note = $null; Started = (Get-Date).ToString('o')
    }
    if ($Skip -contains $name) {
        $record.Note = 'пропущен параметром -Skip'
        $results.Add([pscustomobject]$record)
        Log "=== $name — пропущен"
        return
    }
    Log "=== $name : $title"
    try {
        if ($needsTunnel) { EnsureTunnel $record | Out-Null }
        & $body $record
    } catch {
        $record.Failed = $true
        $record.Error = "$_"
        Log "    ОШИБКА: $_"
    } finally {
        $record.Result = if ($record.Failed) { 'FAIL' } elseif ($record.Skipped -or $record.Checks.Count -eq 0) { 'SKIP' } else { 'PASS' }
        $record.Finished = (Get-Date).ToString('o')
        $results.Add([pscustomobject]$record)
        $results | ConvertTo-Json -Depth 8 | Set-Content -Path $resultsPath -Encoding UTF8
        Log "--- $name : $($record.Result)"
    }
}

# Захват DNS-запросов к DNS шлюза через pktmon: фильтр «IP DNS шлюза, порт 53», nslookup, разбор журнала.
# Внимание: pktmon filter remove снимает все фильтры pktmon на этом компьютере.
function CaptureDns([string]$name) {
    $id = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $etl = Join-Path $work "dns-$id.etl"
    $txt = Join-Path $work "dns-$id.txt"
    $fail = { param($text) [pscustomobject]@{ Ok = $false; Error = $text; LabelFound = $false; PortHits = 0; Lookup = '' } }
    Native 'pktmon' @('filter', 'remove') | Out-Null
    $add = Native 'pktmon' @('filter', 'add', 'KtAcDns', '-i', $TunnelDns, '-p', '53')
    if ($add.Code -ne 0) { return (& $fail "pktmon filter add: $($add.Text)") }
    $start = Native 'pktmon' @('start', '--capture', '--pkt-size', '0', '--file-name', $etl)
    if ($start.Code -ne 0) {
        Native 'pktmon' @('filter', 'remove') | Out-Null
        return (& $fail "pktmon start: $($start.Text)")
    }
    try {
        ipconfig /flushdns | Out-Null
        $lookup = Native 'nslookup' @("$name.")
        Start-Sleep -Seconds 2
    } finally {
        Native 'pktmon' @('stop') | Out-Null
        Native 'pktmon' @('filter', 'remove') | Out-Null
    }
    Native 'pktmon' @('etl2txt', $etl, '--out', $txt) | Out-Null
    if (-not (Test-Path $txt)) { return (& $fail 'pktmon etl2txt не создал текстовый журнал') }
    $text = [IO.File]::ReadAllText($txt) -replace "`0", ''
    $label = $name.Split('.')[0]
    # Строка пакета содержит «адрес.53» (адрес и порт); строки описания фильтра — нет.
    $portHits = ([regex]::Matches($text, [regex]::Escape($TunnelDns) + '\.53\b')).Count
    [pscustomobject]@{ Ok = $true; Error = $null; LabelFound = ($text -match [regex]::Escape($label)); PortHits = $portHits; Lookup = $lookup.Text }
}

# ---------- Подготовка ----------

EnsureService
$profileSetting = @((Settings).profiles) | Where-Object { $_.name -eq $ProfileName } | Select-Object -First 1
if (-not $profileSetting) { Write-Host "Профиль «$ProfileName» не найден в настройках службы."; exit 1 }
if ($profileSetting.protocol -ne 'AnyConnect') { Write-Host "Профиль «$ProfileName» не AnyConnect (протокол $($profileSetting.protocol))."; exit 1 }
$profileId = [string]$profileSetting.id
$idPrefix = $profileId.Replace('-', '').Substring(0, 8).ToLowerInvariant()
Log "Профиль «$ProfileName»: $profileId; адаптер «SplitVpn AC $idPrefix»; CLI: $Cli"

# ---------- Сценарии ----------

Run 'sso' 'Вход SSO → туннель поднят, цель через туннель и Wintun' $true {
    param($r)
    $t = Tunnel
    $r.Data.Tunnels = (Cli @('tunnels')).Text
    $r.Data.AdapterName = $t.adapterName
    Check $r 'туннель в состоянии Connected' ($t.state -eq 'Connected')
    Check $r 'шлюз прислал сети' (@($t.serverNetworks.networks).Count -gt 0)
    Check $r 'процесс помощника запущен' ((Helpers).Count -ge 1)
    Check $r "адаптер «SplitVpn AC $idPrefix» есть" ((AcAdapters).Count -ge 1)
    Check $r 'адаптер туннеля — Wintun' (IsWintun $t.adapterName)
    $c = CheckAddress $Target
    $r.Data.Check = $c.Text
    $item = $c.Items | Select-Object -First 1
    Check $r "check ${Target}: решение Vpn (сеть шлюза)" ($item -and $item.Decision -eq 'Vpn' -and $item.Source -in 'ServerNetwork', 'TunnelInfrastructure')
    Check $r "check ${Target}: ожидается адаптер «$($t.adapterName)»" ($item -and $item.Expected -eq $t.adapterName)
    Check $r "check ${Target}: фактический маршрут через туннель" ($item -and $item.Actual -eq $t.adapterName -and -not $item.Blocked)
    Check $r "Find-NetRoute ${Target} — интерфейс туннеля" ((RouteInterface $Target) -eq $t.adapterName)
}

Run 'dtls' 'DTLS активен' $true {
    param($r)
    $t = WaitTunnel { param($x) $x.serverNetworks -and $x.serverNetworks.dtlsActive } 30
    $r.Data.Tunnels = (Cli @('tunnels')).Text
    $r.Data.Mtu = $t.serverNetworks.mtu
    Check $r 'status --json: dtlsActive = true' ($t.serverNetworks.dtlsActive -eq $true)
    $line = @((Cli @('tunnels')).Lines | Where-Object { $_ -match '^\s*шлюз:' -and $_ -match 'DTLS' })
    Check $r 'tunnels: строка шлюза с DTLS' ($line.Count -ge 1)
}

Run 'dns' 'DNS: внутреннее имя через DNS шлюза, публичное — нет' $true {
    param($r)
    $t = Tunnel
    $s = Status
    $r.Data.GatewayDns = @($t.serverNetworks.dns)
    $r.Data.DnsSuffixes = @($t.serverNetworks.dnsSuffixes)
    Check $r "DNS шлюза содержит $TunnelDns" (@($t.serverNetworks.dns) -contains $TunnelDns)
    $servers = @()
    try { $servers = @((Get-DnsClientServerAddress -InterfaceAlias $s.primaryAdapterName -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses) } catch { }
    $r.Data.PrimaryAdapterDns = $servers
    Check $r "DNS основного адаптера «$($s.primaryAdapterName)» — посредник 127.0.0.1" ($servers -contains '127.0.0.1')
    $r.Data.InternalLookup = (Native 'nslookup' @($InternalName)).Text
    $r.Data.PublicLookup = (Native 'nslookup' @($PublicName)).Text

    # Случайные имена: мимо кэша посредника и клиента DNS.
    $suffix = $InternalName.Substring($InternalName.IndexOf('.') + 1)
    $tag = 'ktac' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $internal = CaptureDns "$tag.$suffix"
    $public = CaptureDns "$tag.$PublicName"
    $r.Data.Internal = $internal
    $r.Data.Public = $public
    if ($internal.Ok -and $public.Ok) {
        Check $r "запрос $tag.$suffix ушёл на $TunnelDns (pktmon)" ($internal.LabelFound -or $internal.PortHits -gt 0)
        # Если pktmon не расшифровал имя, публичный запрос проверяется по отсутствию пакетов на порт 53.
        $publicClean = if ($internal.LabelFound) { -not $public.LabelFound } else { $public.PortHits -eq 0 }
        Check $r "запрос $tag.$PublicName не уходил на $TunnelDns (pktmon)" $publicClean
    } else {
        $r.Data.PktmonError = "$($internal.Error) $($public.Error)".Trim()
        Log "    pktmon недоступен: $($r.Data.PktmonError) — ручная проверка"
        Pause "Проверьте вручную (Wireshark или pktmon с фильтром «-i $TunnelDns -p 53»): nslookup $InternalName должен идти на $TunnelDns, nslookup $PublicName — нет."
        ManualCheck $r "nslookup $InternalName идёт на $TunnelDns" (Ask "Запрос $InternalName ушёл на $TunnelDns?")
        ManualCheck $r "nslookup $PublicName не идёт на $TunnelDns" (Ask "Запрос $PublicName НЕ уходил на $TunnelDns?")
    }
}

Run 'routing' "check $GatewayName — напрямую; $PolicyName — не в AnyConnect" $true {
    param($r)
    $adapter = (Tunnel).adapterName
    $gateway = CheckAddress $GatewayName
    $r.Data.Gateway = $gateway.Text
    Check $r "check ${GatewayName}: адреса получены" ($gateway.Items.Count -gt 0)
    Check $r "check ${GatewayName}: решение Server/Direct" ($gateway.Items.Count -gt 0 -and @($gateway.Items | Where-Object { $_.Decision -notin 'Server', 'Direct' }).Count -eq 0)
    Check $r "check ${GatewayName}: маршрут не через туннель AnyConnect" (@($gateway.Items | Where-Object { $_.Actual -eq $adapter -or $_.Expected -eq $adapter }).Count -eq 0)
    $policy = CheckAddress $PolicyName
    $r.Data.Policy = $policy.Text
    Check $r "check ${PolicyName}: адреса получены" ($policy.Items.Count -gt 0)
    Check $r "check ${PolicyName}: не сеть шлюза" (@($policy.Items | Where-Object { $_.Source -eq 'ServerNetwork' }).Count -eq 0)
    Check $r "check ${PolicyName}: ни ожидаемый, ни фактический маршрут не через AnyConnect" (@($policy.Items | Where-Object { $_.Actual -eq $adapter -or $_.Expected -eq $adapter }).Count -eq 0)
}

Run 'wifi' 'Обрыв Wi-Fi → переподключение без SSO' $true {
    param($r)
    $before = LastEventId
    $pids = @(Helpers | ForEach-Object { $_.Id })
    $r.Data.HelperPidsBefore = $pids
    Pause 'Отключите Wi-Fi на 15–20 секунд и включите снова. Окно входа, если появится, НЕ заполняйте. Нажмите Enter, когда Wi-Fi снова включён.'
    $t = WaitTunnel { param($x) $x.state -eq 'Connected' -and $x.serverNetworks } 180
    $events = EventsSince $before
    $r.Data.Events = $events
    $r.Data.HelperPidsAfter = @(Helpers | ForEach-Object { $_.Id })
    Check $r 'туннель снова Connected' ($t.state -eq 'Connected' -and $t.serverNetworks)
    Check $r 'тот же процесс помощника (сеанс сохранён)' ($pids.Count -ge 1 -and @($r.Data.HelperPidsAfter | Where-Object { $pids -contains $_ }).Count -ge 1)
    Check $r 'новый запуск помощника не понадобился' ((AcDialsSince $before) -eq 0)
    Check $r 'в журнале: переподключение внутри помощника' (@($events | Where-Object { $_ -match 'связь со шлюзом прервалась' }).Count -ge 1)
    ManualCheck $r 'вход SSO не запрашивался' (Ask 'Окно входа SSO НЕ появлялось?')
}

Run 'kill-helper' 'Kill помощника → сети шлюза сняты, запрос входа' $true {
    param($r)
    $before = LastEventId
    Log '    Предупреждение: после kill интерфейс сам откроет окно входа — не входите, пока скрипт не попросит.'
    $r.Data.Killed = @(Helpers | ForEach-Object { $_.Id })
    Helpers | Stop-Process -Force -ErrorAction SilentlyContinue
    $t = WaitTunnel { param($x) -not $x.serverNetworks -and $x.signIn } 60
    $r.Data.Tunnel = $t
    $r.Data.Events = EventsSince $before
    Check $r 'сети шлюза сняты из статуса' (-not $t.serverNetworks)
    Check $r 'туннель не Connected' ($t.state -ne 'Connected')
    Check $r "запрос входа (signIn: $($t.signIn.kind))" ($t.signIn -and $t.signIn.kind -in 'Required', 'Browser', 'Form')
    Check $r 'маршрутов на адаптере туннеля нет' ((AcRoutes) -eq 0)
    Check $r "Find-NetRoute $Target — не через туннель" ((RouteInterface $Target) -notlike "SplitVpn AC $idPrefix*")
    $c = CheckAddress $Target
    $r.Data.Check = $c.Text
    Check $r "check ${Target}: больше не сеть шлюза" (@($c.Items | Where-Object { $_.Source -eq 'ServerNetwork' }).Count -eq 0)
    ManualCheck $r 'окно входа открылось само и один раз' (Ask 'Окно входа открылось само, ровно один раз?')
}

Run 'service-stop' 'Остановка службы → сети сняты, помощника нет; старт → запрос входа' $true {
    param($r)
    Stop-Service -Name $serviceName -Force
    (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    $r.Data.HelpersLeft = WaitNoHelpers 15
    Check $r 'служба остановлена' ((Get-Service -Name $serviceName).Status -eq 'Stopped')
    Check $r 'процессов помощника нет' ($r.Data.HelpersLeft -eq 0)
    Check $r 'адаптера туннеля нет' ((AcAdapters).Count -eq 0)
    Check $r 'маршрутов на адаптере туннеля нет' ((AcRoutes) -eq 0)
    Check $r "Find-NetRoute $Target — не через туннель" ((RouteInterface $Target) -notlike "SplitVpn AC $idPrefix*")

    Start-Service -Name $serviceName
    EnsureService
    $t = WaitTunnel { param($x) $x.signIn -and -not $x.serverNetworks } 60
    $r.Data.Tunnel = $t
    Check $r 'после старта туннель не Connected' ($t -and $t.state -ne 'Connected')
    Check $r "после старта запрос входа (signIn: $($t.signIn.kind))" ($t.signIn -and $t.signIn.kind -in 'Required', 'Browser', 'Form')
    Check $r 'после старта сетей шлюза нет' (-not $t.serverNetworks)
}

Run 'role-off' 'Роль «Выключено» → нет процесса и адаптера' $true {
    param($r)
    $settings = Settings
    $p = @($settings.profiles) | Where-Object { $_.id -eq $profileId } | Select-Object -First 1
    $oldRole = [string]$p.role
    $r.Data.OldRole = $oldRole
    $p.role = 'Off'
    $save = SaveSettings $settings
    $r.Data.SaveOff = $save.Text
    Check $r 'settings set с ролью Off принят' ($save.Code -eq 0 -and $save.Text -notmatch 'Ошибка')
    try {
        $r.Data.HelpersLeft = WaitNoHelpers 30
        $t = WaitTunnel { param($x) -not $x.serverNetworks } 10
        Check $r 'процессов помощника нет' ($r.Data.HelpersLeft -eq 0)
        Check $r 'адаптера туннеля нет' ((AcAdapters).Count -eq 0)
        Check $r 'туннель не поднят (нет в статусе или без сеанса)' (-not $t -or ($t.state -ne 'Connected' -and -not $t.serverNetworks))
        Check $r 'маршрутов на адаптере туннеля нет' ((AcRoutes) -eq 0)
    } finally {
        $settings = Settings
        $p = @($settings.profiles) | Where-Object { $_.id -eq $profileId } | Select-Object -First 1
        $p.role = if ($oldRole -and $oldRole -ne 'Off') { $oldRole } else { 'Secondary' }
        $restore = SaveSettings $settings
        $r.Data.Restore = $restore.Text
        if ($restore.Code -ne 0) { $r.Failed = $true; $r.Note = "Роль не восстановлена: $($restore.Text)" }
    }
}

Run 'recover' 'recover-network.cmd → нет помощника, маршрутов 3917 и фильтров' $true {
    param($r)
    $r.Data.Before = [ordered]@{ Helpers = (Helpers).Count; MarkedRoutes = MarkedRoutes; Wfp = WfpTotal }
    $cmd = @((Join-Path $env:ProgramFiles 'SplitVpn\scripts\recover-network.cmd'), (Join-Path $PSScriptRoot 'recover-network.cmd')) |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    $r.Data.Cmd = $cmd
    Log "    Запуск $cmd"
    Start-Process -FilePath $cmd | Out-Null
    Pause 'В открывшемся окне восстановления дождитесь «Готово» и нажмите там Enter. Затем нажмите Enter здесь.'
    $r.Data.HelpersLeft = WaitNoHelpers 15
    $r.Data.After = [ordered]@{
        Service = "$((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status)"
        MarkedRoutes = MarkedRoutes; Wfp = WfpTotal; AcAdapters = (AcAdapters).Count
    }
    Check $r 'процессов SplitVpn.OpenConnect нет' ($r.Data.HelpersLeft -eq 0)
    Check $r "маршрутов с метрикой $marker нет" ($r.Data.After.MarkedRoutes -eq 0)
    Check $r 'фильтров WFP продукта нет' ($r.Data.After.Wfp -eq 0)
    Check $r 'адаптера туннеля нет' ($r.Data.After.AcAdapters -eq 0)
    if ((Get-Service -Name $serviceName).Status -ne 'Running') {
        Start-Service -Name $serviceName
        Log '    Служба запущена снова; защита приостановлена — «Подключить», чтобы вернуть VPN.'
    }
}

# ---------- Итог ----------

if ($FailsafeMinutes -gt 0) { New-Item -ItemType File -Force -Path (Join-Path $logs 'failsafe.disarm') | Out-Null }

Write-Host ''
$results | Select-Object Name, Result, Title | Format-Table -AutoSize | Out-String | Write-Host
foreach ($record in $results | Where-Object { $_.Result -eq 'FAIL' }) {
    Write-Host "FAIL $($record.Name):"
    foreach ($key in $record.Checks.Keys) { if ($record.Checks[$key] -eq $false) { Write-Host "  - $key" } }
    if ($record.Error) { Write-Host "  ошибка: $($record.Error)" }
    if ($record.Note) { Write-Host "  $($record.Note)" }
}
$failed = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
Log "Итог: PASS $(@($results | Where-Object { $_.Result -eq 'PASS' }).Count), FAIL $failed, SKIP $(@($results | Where-Object { $_.Result -eq 'SKIP' }).Count); результаты: $resultsPath"
$global:LASTEXITCODE = if ($failed -eq 0) { 0 } else { 1 }
