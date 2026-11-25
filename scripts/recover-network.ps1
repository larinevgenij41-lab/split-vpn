<#
.SYNOPSIS
    Экстренное отключение «Раздельного VPN» и возврат обычной сети. recover-network.cmd запускает этот скрипт; права
    администратора скрипт запрашивает сам.

.DESCRIPTION
    1. Штатный путь: SplitVpn.Service.exe recover (то же, что emergency-off) установленной службы или dev-сборки:
       отметка отключения, ручной запуск службы, остановка службы, затем фильтры WFP, соединения RAS, маршруты, DNS,
       настройка Wi-Fi Windows и кеш DNS. Отчёт: %ProgramData%\SplitVpn.Recovery\last.json.
    2. Если штатный путь вернул не всё (или не запустился), выполняется каждый запасной шаг встроенными средствами
       Windows, независимо от исхода остальных: отметка отключения и ручной запуск, остановка службы, маршруты с
       меткой-метрикой 3917, DNS по копии программы и сброс нашего loopback, соединения RAS программы, кеш DNS.
    3. Фильтры WFP встроенными средствами не снимаются: служба в ручном запуске, и после перезагрузки BFE не загрузит
       постоянные фильтры провайдера, чья служба не в автозапуске.
    Включить программу снова: «Включить программу» в приложении или SplitVpn.Service.exe emergency-on от имени
    администратора.
#>
param([switch]$Elevated)
$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

function Wait-Enter {
    Write-Host 'Нажмите Enter, чтобы закрыть окно.'
    [void][Console]::ReadLine()
}

# Повышенные права — по группам маркера (whoami /groups, уровень High Mandatory Level S-1-16-12288), а не через
# WindowsPrincipal: в режиме ограниченного языка (CLM) создание этого объекта не работает, и скрипт перезапускал бы себя
# через UAC бесконечно.
function Test-Elevated {
    $groups = & "$env:SystemRoot\System32\whoami.exe" /groups 2>$null
    return [bool]($groups | Select-String -SimpleMatch 'S-1-16-12288')
}

# Права администратора: без них запрашиваются через UAC. Отказ в UAC — понятное сообщение, а не молча закрытое окно.
if (-not (Test-Elevated)) {
    if ($Elevated) {
        # Уже перезапущены с запросом прав, а повышения нет: второй перезапуск ничего не изменит.
        Write-Host 'Восстановление сети не запущено: окно открыто повторно, но права администратора так и не получены.' -ForegroundColor Yellow
        Write-Host 'Запустите recover-network.cmd правой кнопкой мыши -> «Запуск от имени администратора».'
        Wait-Enter
        exit 1
    }
    try {
        # Путь в кавычках: Start-Process в Windows PowerShell 5.1 не экранирует -ArgumentList, а установка лежит в «Program Files».
        Start-Process powershell.exe -Verb RunAs -ErrorAction Stop -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Elevated' -f $PSCommandPath)
        exit 0
    }
    catch {
        Write-Host 'Восстановление сети не запущено: нужны права администратора, а запрос прав отклонён или не удался.' -ForegroundColor Yellow
        Write-Host "Причина: $($_.Exception.Message)"
        Write-Host 'Запустите recover-network.cmd ещё раз и разрешите изменения в окне контроля учётных записей.'
        Wait-Enter
        exit 1
    }
}

# Слушатели UDP-порта 53 именно на 127.0.0.1 и на [::1]: так слушает локальный резолвер пользователя (AdGuard Home,
# dnscrypt-proxy), ради которого 127.0.0.1 вписан вручную. Слушатель только на 0.0.0.0 или [::] сброса не отменяет.
function Get-LoopbackResolvers {
    $result = @{ V4 = $false; V6 = $false }
    try {
        foreach ($endpoint in @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction Stop)) {
            if ($endpoint.LocalAddress -eq '127.0.0.1') { $result.V4 = $true }
            if ($endpoint.LocalAddress -eq '::1') { $result.V6 = $true }
        }
    } catch { }
    return $result
}

function Restore-SavedDns($adapter, $dns, $saved, $resolvers, $problems) {
    # Адаптер со статическим IPv4-адресом (DHCP выключен): «автоматически» оставило бы его совсем без DNS.
    $static = $false
    try {
        $ipv4 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
        $static = [string]$ipv4.Dhcp -eq 'Disabled'
    } catch { }
    $v4Ours = $false
    foreach ($family in $dns) {
        if ($family.AddressFamily -ne 23) {
            $servers = @($family.ServerAddresses)
            $v4Ours = ($servers.Count -eq 1 -and $servers[0] -eq '127.0.0.1') -or
                ($servers.Count -eq 2 -and $servers[1] -eq '127.0.0.1' -and $servers[0] -match '^\d+\.\d+\.\d+\.\d+$')
        }
    }
    foreach ($family in $dns) {
        $v6 = $family.AddressFamily -eq 23
        $loopback = if ($v6) { '::1' } else { '127.0.0.1' }
        # Наш набор: один loopback либо (IPv4, с 0.17.9) «адрес адаптера, 127.0.0.1».
        $servers = @($family.ServerAddresses)
        $ours = ($servers.Count -eq 1 -and $servers[0] -eq $loopback) -or
            (-not $v6 -and $servers.Count -eq 2 -and $servers[1] -eq $loopback -and $servers[0] -match '^\d+\.\d+\.\d+\.\d+$')
        if (-not $ours) { continue }
        $property = if ($v6) { 'NameServerV6' } else { 'NameServerV4' }
        $unknown = $v6 -and $saved -and $saved.PSObject.Properties['ipv6Unknown'] -and $saved.ipv6Unknown
        $addresses = @()
        if ($saved -and -not $unknown -and $saved.PSObject.Properties[$property]) {
            $addresses = @($saved.$property -split '[,;\s]+' | Where-Object { $_ -and $_ -ne $loopback })
        }
        if ($addresses.Count) {
            $family | Set-DnsClientServerAddress -ServerAddresses $addresses -ErrorAction Stop
            continue
        }
        # Без копии: резолвер пользователя именно на loopback — его DNS, не наш (IPv6 остаётся и вместе с таким IPv4).
        if (-not $saved) {
            if ($resolvers.V4 -and $v4Ours) { continue }
            if ($v6 -and $resolvers.V6) { continue }
        }
        if ($static) {
            $problems.Add("Адаптер $($adapter.Name) со статическим адресом: DNS программы не сброшен (без DHCP адаптер остался бы без DNS) - DNS укажите вручную.")
            return
        }
        # Копии нет, исходный список неизвестен или в нём только loopback — «автоматически» только для этого семейства:
        # служба остановлена, наш loopback без посредника не отвечает. Проверяется код netsh, а не его текст (он локализован).
        $netshFamily = if ($v6) { 'ipv6' } else { 'ipv4' }
        & "$env:SystemRoot\System32\netsh.exe" interface $netshFamily set dnsservers "name=$($adapter.ifIndex)" source=dhcp | Out-Null
        if ($LASTEXITCODE -ne 0) { $problems.Add("DNS $netshFamily адаптера $($adapter.Name) не сброшен (netsh, код $LASTEXITCODE).") }
    }
}

# Процессы службы из каталога программы, кроме команд восстановления (emergency-off, emergency-on, recover): они не служба.
function Get-ServiceHostProcesses($executables) {
    $found = @()
    try {
        foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='SplitVpn.Service.exe'" -ErrorAction Stop)) {
            if (-not $process.ExecutablePath) { continue }
            if (-not ($executables | Where-Object { $_ -ieq $process.ExecutablePath })) { continue }
            if ([string]$process.CommandLine -match '(?i)\.exe"?\s+"?(recover|emergency-off|emergency-on)\b') { continue }
            $found += $process
        }
    } catch { }
    return $found
}

function Stop-RecoveryServices($services, $problems) {
    foreach ($name in 'SplitVpn', 'SplitVpnDev') {
        try {
            $info = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
            if (-not $info) { continue }
            $services.Add($info)
            if ($info.State -eq 'Stopped') { continue }
            # Если процесс придётся завершить, диспетчер служб может поднять его снова (действия при сбое), но с отметкой
            # отключения служба запустится «пустой» и ничего не применит.
            Stop-Service -Name $name -Force -ErrorAction Stop
            (Get-Service -Name $name -ErrorAction Stop).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        } catch {
            $problems.Add("Остановка службы $name не подтверждена - $_")
            try {
                $info = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
                if ($info -and $info.ProcessId) {
                    Stop-Process -Id $info.ProcessId -Force -ErrorAction Stop
                    Write-Host "Процесс службы $name ($($info.ProcessId)) завершён принудительно."
                }
            } catch { $problems.Add("Процесс службы $name не завершён - $_") }
        }
    }
}

$marker = 3917
$dataRoot = Join-Path $env:ProgramData 'SplitVpn'
$candidates = @(
    (Join-Path $env:ProgramFiles 'SplitVpn\SplitVpn.Service.exe'),
    (Join-Path $env:ProgramFiles 'SplitVpn.Dev\service\SplitVpn.Service.exe')
) | Where-Object { Test-Path $_ }

$problems = [Collections.Generic.List[string]]::new()
$networkDone = $false
$serviceDone = $false
foreach ($exe in $candidates) {
    # «recover» — то же, что emergency-off; прежние сборки понимают его как восстановление сети.
    Write-Host "Экстренное отключение: $exe recover"
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        & $exe recover
        $code = $LASTEXITCODE
        if ($code -ne 5) { break }
        Write-Host 'Уже выполняется другое отключение или включение программы — повтор через 20 с.'
        Start-Sleep -Seconds 20
    }
    switch ($code) {
        0 { $networkDone = $true; $serviceDone = $true }
        2 {
            # Код 2 — «сеть возвращена, остановка не подтверждена». Живой процесс службы снова применит фильтры, маршруты
            # и DNS, поэтому код принимается, только если процессов службы нет (прежние сборки этого не проверяли).
            $alive = @(Get-ServiceHostProcesses $candidates)
            if ($alive.Count) {
                $problems.Add("Служба всё ещё работает (процессов: $($alive.Count)) - сеть может вернуться в прежнее состояние.")
            } else {
                $networkDone = $true
                $problems.Add('Сеть возвращена, но остановка службы не подтверждена.')
            }
        }
        3 { $problems.Add('Штатное отключение вернуло сеть не полностью (подробности - в отчёте выше).') }
        4 { $problems.Add('Штатное отключение: нет прав администратора.') }
        5 { $problems.Add('Штатное отключение занято другой командой.') }
        default { $problems.Add("Штатное отключение завершилось с кодом $code.") }
    }
    if ($networkDone -and $serviceDone) { break }
}

if (-not ($networkDone -and $serviceDone)) {
    Write-Host 'Штатный путь вернул не всё — запасные шаги встроенными средствами Windows.'
    $services = [Collections.Generic.List[object]]::new()

    # Отметка отключения: служба, запущенная кем угодно, будет «пустой» и ничего не применит.
    try {
        $key = 'HKLM:\Software\SplitVpn'
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -Path $key -Name 'EmergencyOffUtc' -Value ([DateTime]::UtcNow.ToString('o')) -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name 'EmergencyOff' -Value 1 -PropertyType DWord -Force | Out-Null
    } catch { $problems.Add("Отметка отключения не записана - $_") }

    # Ручной запуск: прежний тип (в том числе ручной или отключённый) запоминается для «Включить программу»
    # (emergency-on), если ещё не запомнен.
    foreach ($name in 'SplitVpn', 'SplitVpnDev') {
        try {
            $info = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
            if (-not $info) { continue }
            $previous = switch ($info.StartMode) {
                'Auto' { if ($info.DelayedAutoStart) { 'delayed-auto' } else { 'auto' } }
                'Disabled' { 'disabled' }
                default { 'demand' }
            }
            if ($name -eq 'SplitVpn') {
                $saved = Get-ItemProperty -Path 'HKLM:\Software\SplitVpn' -Name 'EmergencyOffPreviousStart' -ErrorAction SilentlyContinue
                if (-not $saved) { New-ItemProperty -Path 'HKLM:\Software\SplitVpn' -Name 'EmergencyOffPreviousStart' -Value $previous -PropertyType String -Force | Out-Null }
            }
            if ($previous -eq 'demand') { continue }
            & "$env:SystemRoot\System32\sc.exe" config $name start= demand | Out-Null
            if ($LASTEXITCODE -ne 0) { $problems.Add("Тип запуска службы $name не изменён (sc config, код $LASTEXITCODE).") }
            else { Write-Host "Служба $name переведена в ручной запуск (было: $previous)." }
        } catch { $problems.Add("Тип запуска службы $name - $_") }
    }

    if (-not $serviceDone) {
        try { Stop-RecoveryServices $services $problems } catch { $problems.Add("Остановка службы - $_") }
        # Процессы службы, которые остались и после остановки (кроме команд восстановления), завершаются по пути файла.
        foreach ($process in @(Get-ServiceHostProcesses $candidates)) {
            try {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                Write-Host "Процесс службы $($process.ProcessId) завершён принудительно."
            } catch { $problems.Add("Процесс службы $($process.ProcessId) не завершён - $_") }
        }
    }

    if (-not $networkDone) {
        try {
            foreach ($route in Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object RouteMetric -eq $marker) {
                try { $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
                catch { $problems.Add("Маршрут $($route.DestinationPrefix) - $_") }
            }
        } catch { $problems.Add("Чтение маршрутов - $_") }

        # DNS: по копии программы (dns-backup.json), а без копии — только наш набор (loopback или «адрес, 127.0.0.1»)
        # сбрасывается на «автоматически»: служба остановлена, и посредник на 127.0.0.1 не отвечает.
        $owned = @{}
        $backupFile = Join-Path $dataRoot 'dns-backup.json'
        if (Test-Path $backupFile) {
            try {
                $entries = Get-Content -Raw -Encoding UTF8 $backupFile | ConvertFrom-Json
                foreach ($item in $entries) {
                    foreach ($prop in $item.PSObject.Properties) {
                        if ($prop.Name -ieq 'InterfaceGuid') { $owned[([string]$prop.Value).Trim('{}').ToLowerInvariant()] = $item }
                    }
                }
            }
            catch { $problems.Add("Чтение резервной копии DNS - $_") }
        }
        try { $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) }
        catch { $adapters = @(); $problems.Add("Чтение списка адаптеров - $_") }
        $resolvers = Get-LoopbackResolvers
        foreach ($adapter in $adapters) {
            $saved = $owned[([string]$adapter.InterfaceGuid).Trim('{}').ToLowerInvariant()]
            try {
                $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
                Restore-SavedDns $adapter $dns $saved $resolvers $problems
            }
            catch { $problems.Add("DNS адаптера $($adapter.Name) - $_") }
        }

        # Соединения из телефонной книги программы: записи «Раздельный VPN <id>» (по одной на профиль) и прежние имена.
        try {
            $entries = @('SplitVpn Proto', 'Раздельный VPN')
            $pbk = Join-Path $dataRoot 'splitvpn.pbk'
            if (Test-Path $pbk) {
                foreach ($line in Get-Content -Encoding UTF8 $pbk) {
                    if ($line -match '^\[(.+)\]\s*$') {
                        $section = $Matches[1]
                        if ($section.StartsWith('Раздельный VPN') -or $section.StartsWith('SplitVpn Proto')) { $entries += $section }
                    }
                }
                foreach ($name in ($entries | Select-Object -Unique)) {
                    rasdial $name /disconnect "/PHONEBOOK:$pbk" 2>$null | Out-Null
                }
            }
        } catch { $problems.Add("Разрыв соединений RAS - $_") }

        ipconfig /flushdns | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning "Сброс кеша DNS, код $LASTEXITCODE" }
        Write-Host 'Если интернет не появился — перезагрузите компьютер: служба в ручном запуске, и фильтры защиты не загрузятся.'
    }
}

$last = Join-Path $env:ProgramData 'SplitVpn.Recovery\last.json'
if (Test-Path $last) { Write-Host "Отчёт штатного отключения: $last" }
foreach ($problem in $problems) { Write-Warning $problem }
if ($networkDone -and $serviceDone) {
    Write-Host 'Программа экстренно отключена: сеть возвращена, служба остановлена и сама не запустится.' -ForegroundColor Green
}
Write-Host 'Включить программу снова: «Включить программу» в приложении или SplitVpn.Service.exe emergency-on от имени администратора.'
Wait-Enter

if ($networkDone -and $serviceDone) { exit 0 }
exit 1
