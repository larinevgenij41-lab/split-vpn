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
    Скрипт работает и в режиме ограниченного языка PowerShell (CLM): запасной путь не создаёт объектов .NET и не
    вызывает их методов, кроме методов строк, дат и хеш-таблиц.
#>
param([switch]$Elevated)
$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

function Wait-Enter {
    Write-Host 'Нажмите Enter, чтобы закрыть окно.'
    # В режиме ограниченного языка [Console]::ReadLine недоступен: без замены окно закрылось бы, не показав итог.
    try { [void][Console]::ReadLine() } catch { try { [void](Read-Host) } catch { } }
}

# Повышенные права — по группам маркера (whoami /groups, уровень High Mandatory Level S-1-16-12288, а у SYSTEM — System
# Mandatory Level S-1-16-16384: так скрипт запускает установщик), а не через WindowsPrincipal: в режиме ограниченного
# языка (CLM) создание этого объекта не работает, и скрипт перезапускал бы себя через UAC бесконечно.
function Test-Elevated {
    $groups = & "$env:SystemRoot\System32\whoami.exe" /groups 2>$null
    return [bool]($groups | Select-String -SimpleMatch -Pattern 'S-1-16-12288', 'S-1-16-16384')
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

# Список того, что не получилось. Обычный массив, а не List<T>: в режиме ограниченного языка создать List нельзя, и
# без этого человек не увидел бы ни одного предупреждения.
function Add-Problem([string]$text) {
    $script:problems += $text
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

# Каждое семейство адаптера (IPv4 и IPv6) обрабатывается отдельно: отказ или сбой в одном не пропускает другое,
# а попадает в список проблем. Трогается только наш набор (как InterfaceDnsOps.IsProxySet у службы): один loopback
# либо (IPv4, с 0.17.9) «адрес адаптера, 127.0.0.1»; чужой DNS пользователя остаётся как есть.
function Restore-SavedDns($adapter, $dns, $saved, $resolvers) {
    # Статический IPv4-адрес (DHCP IPv4 выключен) у адаптера без копии: «автоматически» оставило бы адаптер без DNS IPv4 —
    # он не сбрасывается, а человеку говорится указать DNS вручную (как OrphanDns.Decide у службы: правило только для
    # адаптеров без копии). Копия с пустым списком IPv4 — исходно «автоматически», и он возвращается и на статическом
    # адресе (как RestoreAdapterDns у службы). Для IPv6 правила нет: поле Dhcp у IPv6 отражает флаги M/O объявлений
    # маршрутизатора, а не статический адрес (у большинства адаптеров оно выключено), а наш ::1 после остановки службы
    # никому не отвечает. Поэтому IPv6 без адресов в копии всегда сбрасывается на «автоматически».
    $staticV4 = $false
    if (-not $saved) {
        try {
            $interface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
            $staticV4 = [string]$interface.Dhcp -eq 'Disabled'
        } catch { }
    }
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
        $familyName = if ($v6) { 'IPv6' } else { 'IPv4' }
        if ($addresses.Count) {
            try { $family | Set-DnsClientServerAddress -ServerAddresses $addresses -ErrorAction Stop }
            catch { Add-Problem "DNS $familyName адаптера $($adapter.Name) по копии не восстановлен - $_" }
            continue
        }
        # Без копии: резолвер пользователя именно на loopback — его DNS, не наш (IPv6 остаётся и вместе с таким IPv4).
        if (-not $saved) {
            if ($resolvers.V4 -and $v4Ours) { continue }
            if ($v6 -and $resolvers.V6) { continue }
        }
        if (-not $v6 -and $staticV4 -and -not $saved) {
            Add-Problem "Адаптер $($adapter.Name) со статическим адресом IPv4: DNS программы не сброшен (без DHCP адаптер остался бы без DNS) - DNS укажите вручную."
            continue
        }
        # Копии нет, исходный список неизвестен, пуст («автоматически») или в нём только loopback — «автоматически»
        # только для этого семейства: служба остановлена, наш loopback без посредника не отвечает. Проверяется код netsh,
        # а не его текст (он локализован).
        $netshFamily = $familyName.ToLowerInvariant()
        try {
            & "$env:SystemRoot\System32\netsh.exe" interface $netshFamily set dnsservers "name=$($adapter.ifIndex)" source=dhcp | Out-Null
            if ($LASTEXITCODE -ne 0) { Add-Problem "DNS $familyName адаптера $($adapter.Name) не сброшен (netsh, код $LASTEXITCODE)." }
        } catch { Add-Problem "DNS $familyName адаптера $($adapter.Name) не сброшен - $_" }
    }
}

# DNS одного адаптера из Get-NetAdapter -IncludeHidden. У скрытых и отсутствующих адаптеров (WAN Miniport, Teredo, 6to4,
# отключённые) нет IP-интерфейса, и Get-DnsClientServerAddress отвечает ошибкой: DNS-настроек нет — сбрасывать нечего
# (как служба пропускает интерфейсы без DNS-настроек), и это не проблема. Ошибка на адаптере с IP-интерфейсом — проблема.
function Restore-AdapterDns($adapter, $saved, $resolvers) {
    try {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
    } catch {
        # Пропускается, только если и DNS, и IP-интерфейс «не найдены»; любой иной сбой (CIM, доступ) — проблема.
        $failure = $_
        $noInterface = $false
        if ([string]$failure.CategoryInfo.Category -eq 'ObjectNotFound') {
            try { $noInterface = -not @(Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -ErrorAction Stop).Count }
            catch { $noInterface = [string]$_.CategoryInfo.Category -eq 'ObjectNotFound' }
        }
        if ($noInterface) { return }
        Add-Problem "DNS адаптера $($adapter.Name) - $failure"
        return
    }
    try { Restore-SavedDns $adapter $dns $saved $resolvers }
    catch { Add-Problem "DNS адаптера $($adapter.Name) - $_" }
}

# Можно ли верить каталогу данных или копии DNS — те же правила, что у службы (DataRootTrust): не ссылка; владелец —
# SYSTEM, Administrators, TrustedInstaller или прямой член локальной группы Administrators; право записи (запись, дописывание,
# атрибуты, удаление, смена прав и владельца) есть только у SYSTEM, Administrators и TrustedInstaller (правило только для
# потомков и CREATOR OWNER не в счёт). Ответ — причина недоверия; пусто — верить можно. Любой сбой проверки — недоверие.
# Права читаются из текста SDDL (свойство Sddl у Get-Acl) регулярными выражениями, а не методами объекта .NET: так
# проверка одна и та же и в полном языке, и в режиме ограниченного языка (CLM), где методы вызвать нельзя. Она не мягче
# прежней проверки через GetAccessRules: в счёт идёт каждая запись, кроме запрещающих (D, OD, XD), в том числе
# унаследованные, объектные и условные; что не разобрано (неизвестный тип прав, владелец, чьё членство в Administrators не установлено, лишний текст) — недоверие.
function Get-UntrustedReason($path) {
    $admins = 'S-1-5-32-544'
    $trusted = @('S-1-5-18', $admins, 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # Псевдонимы SDDL нужных учётных записей; прочие псевдонимы (BU, AU, WD, IU…) остаются как есть — они не доверенные.
    $aliases = @{ SY = 'S-1-5-18'; BA = $admins; CO = 'S-1-3-0' }
    # WriteData, AppendData, WriteEA, DeleteChild, WriteAttributes, Delete, WriteDAC, WriteOwner, GENERIC_ALL, GENERIC_WRITE.
    $writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    # Двухбуквенные обозначения прав SDDL и их маски (для файлов Windows пишет и «DCLCRPCR»: это биты 0x2, 0x4, 0x10, 0x100).
    $rightNames = @{
        GA = 0x10000000; GR = 2147483648; GW = 0x40000000; GX = 0x20000000
        RC = 0x20000; SD = 0x10000; WD = 0x40000; WO = 0x80000
        CC = 0x1; DC = 0x2; LC = 0x4; SW = 0x8; RP = 0x10; WP = 0x20; DT = 0x40; LO = 0x80; CR = 0x100
        FA = 0x1F01FF; FR = 0x120089; FW = 0x120116; FX = 0x1200A0
        KA = 0xF003F; KR = 0x20019; KW = 0x20006; KX = 0x20019
    }
    try {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ("$($item.Attributes)" -match 'ReparsePoint') { return "$path - ссылка на другой путь" }
        $security = Get-Acl -LiteralPath $path -ErrorAction Stop
        $sddl = [string]$security.Sddl
        if ($sddl -notmatch '^O:(?<owner>[^:]+?)(G:[^:]+?)?D:(?<dacl>.*?)(S:.*)?$') { return "$path не проверяется: права не прочитаны" }
        $owner = $Matches['owner']
        $dacl = $Matches['dacl']
        if ($aliases.ContainsKey($owner)) { $owner = $aliases[$owner] }
        if ($trusted -notcontains $owner) {
            # Прямой член Administrators. Владелец в SDDL — SID или псевдоним; псевдоним бывает и у SID домена либо
            # компьютера (LA — встроенный Administrator, DA — Domain Admins), а SID за ним из текста не узнать. Тогда
            # сравнивается имя владельца (Owner у Get-Acl) с именами членов группы. Не удалось установить — недоверие.
            $ownerName = $null
            if ($owner -match '^[A-Z]{2}$') { $ownerName = [string]$security.Owner }
            $member = $false
            if ($owner -match '^S-1-[0-9-]+$' -or $ownerName) {
                try {
                    foreach ($m in @(Get-LocalGroupMember -SID $admins -ErrorAction Stop)) {
                        if ($ownerName) {
                            if ($m.Name -and [string]$m.Name -ieq $ownerName) { $member = $true }
                        } elseif ($m.SID -and [string]$m.SID.Value -eq $owner) { $member = $true }
                    }
                } catch { }
            }
            if (-not $member) { return "$path принадлежит посторонней учётной записи ($owner)" }
        }
        # Флаги списка (P, AI, AR) и записи в скобках, и больше ничего: пустой список (NO_ACCESS_CONTROL) даёт всё всем.
        if ($dacl -notmatch '^(?<flags>[A-Z_]*)(?<aces>(\([^()]*\))*)$') { return "$path не проверяется: права не разобраны" }
        $listFlags = $Matches['flags']
        $aces = $Matches['aces']
        if ($listFlags -match 'NO_ACCESS_CONTROL') { return "$path даёт право записи всем (список доступа пуст)" }
        # Пустой список записей — доступа нет ни у кого. Иначе «(…)(…)» делится по «)(» (только методы строк — для CLM).
        $entries = @()
        if ($aces) { $entries = @($aces.Substring(1, $aces.Length - 2) -split '\)\(') }
        foreach ($ace in $entries) {
            $fields = @($ace -split ';')
            if ($fields.Count -lt 6) { return "$path не проверяется: запись прав «$ace» не разобрана" }
            if (@('D', 'OD', 'XD') -contains $fields[0]) { continue }
            $flags = $fields[1]
            if ($flags.Length % 2) { return "$path не проверяется: запись прав «$ace» не разобрана" }
            $inheritOnly = $false
            for ($i = 0; $i -lt $flags.Length; $i += 2) { if ($flags.Substring($i, 2) -eq 'IO') { $inheritOnly = $true } }
            if ($inheritOnly) { continue }
            $sid = $fields[5]
            if ($aliases.ContainsKey($sid)) { $sid = $aliases[$sid] }
            if ($trusted -contains $sid -or $sid -eq 'S-1-3-0') { continue }
            $rights = $fields[2]
            $mask = [int64]0
            if ($rights -match '^0[xX][0-9A-Fa-f]{1,8}$' -or $rights -match '^[0-9]{1,10}$') {
                $mask = [int64]$rights
            } elseif ($rights -and $rights.Length % 2 -eq 0) {
                for ($i = 0; $i -lt $rights.Length; $i += 2) {
                    $token = $rights.Substring($i, 2)
                    if (-not $rightNames.ContainsKey($token)) { return "$path не проверяется: права «$rights» не разобраны" }
                    $mask = $mask -bor [int64]$rightNames[$token]
                }
            } else {
                return "$path не проверяется: права «$rights» не разобраны"
            }
            if (($mask -band $writeMask) -ne 0) { return "$path даёт право записи посторонней учётной записи ($sid)" }
        }
        return $null
    } catch {
        return "$path не проверяется - $($_.Exception.Message)"
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

function Stop-RecoveryServices {
    foreach ($name in 'SplitVpn', 'SplitVpnDev') {
        try {
            $info = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
            if (-not $info) { continue }
            if ($info.State -eq 'Stopped') { continue }
            # Если процесс придётся завершить, диспетчер служб может поднять его снова (действия при сбое), но с отметкой
            # отключения служба запустится «пустой» и ничего не применит.
            Stop-Service -Name $name -Force -ErrorAction Stop
            # Ожидание опросом, а не WaitForStatus: метод объекта недоступен в режиме ограниченного языка.
            $deadline = (Get-Date).AddSeconds(30)
            while ([string](Get-Service -Name $name -ErrorAction Stop).Status -ne 'Stopped') {
                if ((Get-Date) -gt $deadline) { throw 'служба не остановилась за 30 с' }
                Start-Sleep -Milliseconds 500
            }
        } catch {
            Add-Problem "Остановка службы $name не подтверждена - $_"
            try {
                $info = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
                if ($info -and $info.ProcessId) {
                    Stop-Process -Id $info.ProcessId -Force -ErrorAction Stop
                    Write-Host "Процесс службы $name ($($info.ProcessId)) завершён принудительно."
                }
            } catch { Add-Problem "Процесс службы $name не завершён - $_" }
        }
    }
}

# Запуск программы со сроком: зависшая служба RasMan не должна подвешивать всё восстановление. Вывод пишется во
# временный файл и читается как UTF-8, OEM и ANSI системы: кодировка вывода зависит от программы и кодовой страницы
# консоли, а неверно прочитанное кириллическое имя просто не совпадёт с именем программы. Только командлеты — работает и
# в режиме ограниченного языка. Ответ: @{ Code = код выхода (-1 — неизвестен); Texts = прочтения вывода }. Не уложилась
# в срок — процесс завершается, исключение.
function Invoke-Tool([string]$path, [string]$arguments, [int]$seconds) {
    $tempDir = $env:TEMP
    if (-not $tempDir -or -not (Test-Path -LiteralPath $tempDir)) { $tempDir = Join-Path $env:SystemRoot 'Temp' }
    $id = [guid]::NewGuid().ToString('N')
    $out = Join-Path $tempDir "splitvpn-recover-$id.out"
    $err = Join-Path $tempDir "splitvpn-recover-$id.err"
    try {
        $start = @{ FilePath = $path; NoNewWindow = $true; PassThru = $true; RedirectStandardOutput = $out; RedirectStandardError = $err; ErrorAction = 'Stop' }
        if ($arguments) { $start.ArgumentList = $arguments }
        $process = Start-Process @start
        # Без обращения к Handle сразу после запуска Windows PowerShell 5.1 может не узнать код выхода. Процесс, уже
        # успевший завершиться, может отказать в дескрипторе: это не сбой запуска, код выхода тогда неизвестен (-1).
        try { $null = $process.Handle } catch { }
        try { $process | Wait-Process -Timeout $seconds -ErrorAction Stop } catch { }
        if (-not $process.HasExited) {
            try { Stop-Process -Id $process.Id -Force -ErrorAction Stop } catch { }
            throw "$(Split-Path -Leaf $path) не ответил за $seconds с - процесс завершён"
        }
        try { $code = $process.ExitCode } catch { $code = $null }
        if ($null -eq $code) { $code = -1 }
        $texts = @()
        foreach ($encoding in 'UTF8', 'Oem', 'Default') {
            try { $text = Get-Content -LiteralPath $out -Raw -Encoding $encoding -ErrorAction Stop } catch { $text = $null }
            if ($text) { $texts += [string]$text }
        }
        return @{ Code = [int]$code; Texts = $texts }
    } finally {
        Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue
    }
}

# Служба RasMan остановлена, отключена или не запускается (ERROR_RASMAN_CANNOT_INITIALIZE, ERROR_SERVICE_DISABLED,
# ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_DEPENDENCY_FAIL — как RasClient.RasUnavailable у службы): соединений RAS нет.
function Test-RasUnavailable([int]$code) {
    return @(711, 1058, 1062, 1068) -contains $code
}

# Соединения программы — по имени записи: «Раздельный VPN <id>» (служба, по одной записи на профиль; прежние сборки —
# просто «Раздельный VPN») и «SplitVpn Proto[ N]» (прототип).
function Test-OwnRasName([string]$name) {
    return ($name -like 'Раздельный VPN*') -or ($name -like 'SplitVpn Proto*')
}

# Имя, которое можно передать в командной строке rasdial и задачи планировщика без экранирования: буквы, цифры, пробел,
# точка, дефис, подчёркивание, скобки. Кавычки, «\» и «%» (планировщик раскрывает переменные среды) не допускаются.
# Годится только для обычного rasdial от имени текущего администратора.
function Test-SafeRasName([string]$name) {
    # \z, а не $: «$» допускает перевод строки в конце имени.
    return $name -match '^[\p{L}\p{Nd} ._()-]+\z'
}

# Точно имя, которое строит сама программа: «Раздельный VPN» (прежние сборки) или «Раздельный VPN » + первые 8 знаков
# идентификатора профиля в формате N (строчные шестнадцатеричные, Coordinator.EntryNameFor), «SplitVpn Proto» или
# «SplitVpn Proto N» с N от 2 (ProtoContext.EntryNameFor). Только такое имя передаётся в задачу от имени SYSTEM: запись
# с похожим именем может завести себе и обычный пользователь в своей телефонной книге.
function Test-ProgramRasName([string]$name) {
    return $name -cmatch '^(Раздельный VPN( [0-9a-f]{8})?|SplitVpn Proto( ([2-9]|[1-9][0-9]{1,8}))?)\z'
}

# Имена соединений программы из прочтений вывода rasdial без аргументов. Текст локализован («Connected to» / «Подключено
# к», затем по имени на строке, последняя строка — итог команды; без соединений строк всего две), поэтому имена — это
# строки между первой и последней.
function Read-OwnRasNames([string[]]$texts) {
    $names = @()
    foreach ($text in $texts) {
        $lines = @([string]$text -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($lines.Count -lt 3) { continue }
        foreach ($line in $lines[1..($lines.Count - 2)]) {
            if ((Test-OwnRasName $line) -and ($names -notcontains $line)) { $names += $line }
        }
    }
    return ,$names
}

# rasdial не ответил за срок (зависла служба RasMan): каждый следующий вызов тоже ждал бы 15 с, и проверки разрыва
# растянулись бы на минуты. После первого такого случая rasdial больше не запускается, соединения проверяются только по
# сетевым интерфейсам, а проблема записывается один раз.
function Register-RasdialFailure($errorRecord) {
    if ("$errorRecord" -match 'не ответил за') { $script:rasdialHung = $true }
}

# Активные соединения программы по списку rasdial. Сбой или истёкший срок — исключение.
function Get-RasdialNames {
    $result = Invoke-Tool "$env:SystemRoot\System32\rasdial.exe" '' 15
    if (Test-RasUnavailable $result.Code) { return ,@() }
    if ($result.Code -ne 0) { throw "rasdial, код $($result.Code)" }
    return ,(Read-OwnRasNames $result.Texts)
}

# Подключённые сетевые интерфейсы соединений программы: имя интерфейса PPP совпадает с именем записи RAS. В отличие от
# rasdial, этот список видит и соединения, которые служба набрала от имени SYSTEM из своей телефонной книги. Через CIM
# (MSFT_NetIPInterface, ConnectionState 1 — подключён), а не Get-NetAdapter: адаптеров PPP там нет.
function Get-OwnRasInterfaces {
    $names = @()
    foreach ($interface in @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName MSFT_NetIPInterface -ErrorAction Stop)) {
        $alias = [string]$interface.InterfaceAlias
        if ([int]$interface.ConnectionState -eq 1 -and (Test-OwnRasName $alias) -and $names -notcontains $alias) { $names += $alias }
    }
    return ,$names
}

# Что из соединений программы ещё подключено — по rasdial и по интерфейсам вместе. Ответ: @{ Names; Failures }.
function Get-OwnRasActive {
    $names = @()
    $failures = @()
    if (-not $script:rasdialHung) {
        try { foreach ($name in (Get-RasdialNames)) { if ($names -notcontains $name) { $names += $name } } }
        catch {
            $failures += "список соединений rasdial не получен - $_"
            Register-RasdialFailure $_
        }
    }
    try { foreach ($name in (Get-OwnRasInterfaces)) { if ($names -notcontains $name) { $names += $name } } }
    catch { $failures += "сетевые интерфейсы не прочитаны - $_" }
    return @{ Names = $names; Failures = $failures }
}

# Разрыв завершается не мгновенно: до $checks проверок с паузой в 1 с.
function Wait-OwnRasGone([int]$checks) {
    for ($check = 1; $check -le $checks; $check++) {
        $state = Get-OwnRasActive
        if (-not $state.Names.Count) { return $state }
        if ($check -lt $checks) { Start-Sleep -Seconds 1 }
    }
    return $state
}

# Скрипт уже работает от имени SYSTEM (так его запускает установщик): обычный rasdial и был разрывом от SYSTEM.
function Test-RunningAsSystem {
    $user = & "$env:SystemRoot\System32\whoami.exe" /user 2>$null
    return [bool]($user | Select-String -SimpleMatch -Pattern 'S-1-5-18')
}

# Разрыв от имени SYSTEM через одноразовую задачу планировщика: соединение, набранное службой (SYSTEM) из своей
# телефонной книги, rasdial администратора может не видеть. Команда задачи — «"<rasdial.exe>" "<имя>" /disconnect»;
# внутри /tr кавычки экранируются «\"», а имя — точно имя программы (Test-ProgramRasName), поэтому других символов для
# экранирования нет.
# Задача удаляется в любом случае. Ответ — удалось ли запустить задачу.
function Disconnect-RasNameAsSystem([string]$name) {
    if (-not (Test-ProgramRasName $name)) { return $false }
    $schtasks = "$env:SystemRoot\System32\schtasks.exe"
    $rasdial = "$env:SystemRoot\System32\rasdial.exe"
    # Длина /tr ограничена 261 символом — считается то, что сохранит планировщик (кавычки без «\»).
    if (('"{0}" "{1}" /disconnect' -f $rasdial, $name).Length -gt 261) {
        Add-Problem "Соединение «$name» не разорвать от имени SYSTEM: слишком длинная команда для задачи планировщика."
        return $false
    }
    $action = '\"{0}\" \"{1}\" /disconnect' -f $rasdial, $name
    $task = 'SplitVpn-RasDisconnect-' + [guid]::NewGuid().ToString('N')
    $started = $false
    try {
        $created = Invoke-Tool $schtasks ('/create /tn {0} /ru SYSTEM /sc once /st 00:00 /tr "{1}" /f' -f $task, $action) 30
        if ($created.Code -ne 0) {
            Add-Problem "Задача планировщика для разрыва «$name» от имени SYSTEM не создана (schtasks, код $($created.Code))."
            return $false
        }
        # /I — запуск сразу, без условий задачи: созданная schtasks /create задача по умолчанию запускается только от сети,
        # и на ноутбуке от батареи /run без /I молча не выполнил бы разрыв.
        $run = Invoke-Tool $schtasks "/run /i /tn $task" 30
        if ($run.Code -ne 0) {
            Add-Problem "Задача планировщика для разрыва «$name» от имени SYSTEM не запущена (schtasks, код $($run.Code))."
            return $false
        }
        $started = $true
        # Задача удаляется только после разрыва (или 10 с ожидания): иначе удаление могло бы помешать её запуску.
        for ($check = 1; $check -le 10; $check++) {
            Start-Sleep -Seconds 1
            if ((Get-OwnRasActive).Names -notcontains $name) { break }
        }
        return $true
    } catch {
        Add-Problem "Разрыв «$name» от имени SYSTEM не выполнен - $_"
        return $started
    } finally {
        try {
            $deleted = Invoke-Tool $schtasks "/delete /tn $task /f" 30
            # Задачу могли и не создать: тогда и удалять нечего, и код ошибки ожидаем. Проверяем, осталась ли она.
            if ($deleted.Code -ne 0) {
                $left = Invoke-Tool $schtasks "/query /tn $task" 30
                if ($left.Code -eq 0) { Add-Problem "Задача планировщика $task не удалена - удалите её вручную (schtasks /delete /tn $task /f)." }
            }
        } catch { Add-Problem "Задача планировщика $task, возможно, не удалена - проверьте и удалите её вручную (schtasks /delete /tn $task /f): $_" }
    }
}

# Разрыв активных соединений программы. Список — по rasdial и по сетевым интерфейсам вместе: rasdial администратора
# может не видеть соединения службы. Сначала rasdial <имя> /disconnect (без /PHONEBOOK: вместе с /DISCONNECT rasdial его
# не принимает — печатает справку и выходит с кодом 0); его код ошибки не в счёт — соединение могло пропасть само,
# решает повторная проверка. Оставшиеся разрываются от имени SYSTEM через планировщик (если скрипт уже не SYSTEM и
# rasdial не зависал);
# всё, что осталось и после этого, и любой сбой попадают в список проблем.
function Disconnect-OwnRasConnections {
    $active = Get-OwnRasActive
    foreach ($failure in $active.Failures) { Add-Problem "Соединения RAS: $failure." }
    if (-not $active.Names.Count) { return }
    foreach ($name in $active.Names) {
        # Зависший rasdial завис бы и здесь, на каждом имени.
        if ($script:rasdialHung) { break }
        if (-not (Test-SafeRasName $name)) { continue }
        try {
            $result = Invoke-Tool "$env:SystemRoot\System32\rasdial.exe" ('"{0}" /disconnect' -f $name) 15
            if ($result.Code -eq 0) { Write-Host "Соединение «$name» разорвано." }
        } catch {
            Add-Problem "Разрыв «$name» (rasdial) - $_"
            Register-RasdialFailure $_
        }
    }
    $state = Wait-OwnRasGone 3
    # Зависший rasdial от имени SYSTEM завис бы так же и остался бы висеть в задаче — тогда только перезагрузка.
    if ($state.Names.Count -and -not $script:rasdialHung -and -not (Test-RunningAsSystem)) {
        $any = $false
        foreach ($name in $state.Names) {
            if (-not (Test-ProgramRasName $name)) { continue }
            Write-Host "Соединение «$name» не разорвано обычным rasdial — повтор от имени SYSTEM через планировщик заданий."
            if (Disconnect-RasNameAsSystem $name) { $any = $true }
        }
        if ($any) { $state = Wait-OwnRasGone 3 }
    }
    foreach ($failure in $state.Failures) {
        if ($active.Failures -notcontains $failure) { Add-Problem "Проверка разрыва RAS: $failure." }
    }
    foreach ($name in $state.Names) {
        if (-not (Test-ProgramRasName $name)) {
            # Имя похоже на имя программы, но программа так его не строит: это может быть чужая запись.
            Add-Problem ("Соединение «$name» осталось подключённым: имя похоже на имя программы, но не совпадает с её форматом, " +
                'поэтому от имени SYSTEM оно не разрывалось. Проверьте, чьё это соединение, и при необходимости разорвите его вручную.')
            continue
        }
        if ($script:rasdialHung) {
            Add-Problem ("Соединение «$name» программы осталось подключённым, а rasdial не отвечает (зависла служба RasMan): " +
                'разрыв от имени SYSTEM не запускался — он завис бы так же. Перезагрузите компьютер: служба в ручном запуске и ' +
                'с отметкой отключения, сама не подключится.')
            continue
        }
        Add-Problem ("Соединение «$name» программы осталось подключённым. Перезагрузите компьютер: служба в ручном запуске и " +
            "с отметкой отключения, сама не подключится. Или разорвите его от имени SYSTEM: rasdial `"$name`" /disconnect.")
    }
}

$marker = 3917
$dataRoot = Join-Path $env:ProgramData 'SplitVpn'
$candidates = @(
    (Join-Path $env:ProgramFiles 'SplitVpn\SplitVpn.Service.exe'),
    (Join-Path $env:ProgramFiles 'SplitVpn.Dev\service\SplitVpn.Service.exe')
) | Where-Object { Test-Path $_ }

$problems = @()
$rasdialHung = $false
if ([string]$ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host "PowerShell работает в режиме ограниченного языка ($($ExecutionContext.SessionState.LanguageMode)): часть проверок упрощена."
}
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
                Add-Problem "Служба всё ещё работает (процессов: $($alive.Count)) - сеть может вернуться в прежнее состояние."
            } else {
                $networkDone = $true
                Add-Problem 'Сеть возвращена, но остановка службы не подтверждена.'
            }
        }
        3 { Add-Problem 'Штатное отключение вернуло сеть не полностью (подробности - в отчёте выше).' }
        4 { Add-Problem 'Штатное отключение: нет прав администратора.' }
        5 { Add-Problem 'Штатное отключение занято другой командой.' }
        default { Add-Problem "Штатное отключение завершилось с кодом $code." }
    }
    if ($networkDone -and $serviceDone) { break }
}

if (-not ($networkDone -and $serviceDone)) {
    Write-Host 'Штатный путь вернул не всё — запасные шаги встроенными средствами Windows.'

    # Отметка отключения: служба, запущенная кем угодно, будет «пустой» и ничего не применит.
    try {
        $key = 'HKLM:\Software\SplitVpn'
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -Path $key -Name 'EmergencyOffUtc' -Value ([DateTime]::UtcNow.ToString('o')) -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name 'EmergencyOff' -Value 1 -PropertyType DWord -Force | Out-Null
    } catch { Add-Problem "Отметка отключения не записана - $_" }

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
            if ($LASTEXITCODE -ne 0) { Add-Problem "Тип запуска службы $name не изменён (sc config, код $LASTEXITCODE)." }
            else { Write-Host "Служба $name переведена в ручной запуск (было: $previous)." }
        } catch { Add-Problem "Тип запуска службы $name - $_" }
    }

    if (-not $serviceDone) {
        try { Stop-RecoveryServices } catch { Add-Problem "Остановка службы - $_" }
        # Процессы службы, которые остались и после остановки (кроме команд восстановления), завершаются по пути файла.
        foreach ($process in @(Get-ServiceHostProcesses $candidates)) {
            try {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                Write-Host "Процесс службы $($process.ProcessId) завершён принудительно."
            } catch { Add-Problem "Процесс службы $($process.ProcessId) не завершён - $_" }
        }
    }

    if (-not $networkDone) {
        try {
            foreach ($route in Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object RouteMetric -eq $marker) {
                try { $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
                catch { Add-Problem "Маршрут $($route.DestinationPrefix) - $_" }
            }
        } catch { Add-Problem "Чтение маршрутов - $_" }

        # DNS: по копии программы (dns-backup.json), а без копии — только наш набор (loopback или «адрес, 127.0.0.1»)
        # сбрасывается на «автоматически»: служба остановлена, и посредник на 127.0.0.1 не отвечает. Копии верим по тем же
        # правилам, что и служба (DataRootTrust): иначе её мог подложить пользователь, и DNS ушёл бы на его серверы.
        $owned = @{}
        $backupFile = Join-Path $dataRoot 'dns-backup.json'
        $untrusted = $null
        if (Test-Path -LiteralPath $backupFile) {
            $untrusted = Get-UntrustedReason $dataRoot
            if (-not $untrusted) { $untrusted = Get-UntrustedReason $backupFile }
            if ($untrusted) {
                Add-Problem ("Копия DNS не использована: $untrusted. DNS программы сброшен на «автоматически» по общим правилам - " +
                    'если DNS был задан вручную - задайте его снова.')
            }
        }
        if ((Test-Path -LiteralPath $backupFile) -and -not $untrusted) {
            try {
                $entries = Get-Content -Raw -Encoding UTF8 -LiteralPath $backupFile | ConvertFrom-Json
                foreach ($item in $entries) {
                    foreach ($prop in $item.PSObject.Properties) {
                        if ($prop.Name -ieq 'InterfaceGuid') { $owned[([string]$prop.Value).Trim('{}').ToLowerInvariant()] = $item }
                    }
                }
            }
            catch { Add-Problem "Чтение резервной копии DNS - $_" }
        }
        try { $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) }
        catch { $adapters = @(); Add-Problem "Чтение списка адаптеров - $_" }
        $resolvers = Get-LoopbackResolvers
        foreach ($adapter in $adapters) {
            $saved = $owned[([string]$adapter.InterfaceGuid).Trim('{}').ToLowerInvariant()]
            Restore-AdapterDns $adapter $saved $resolvers
        }

        # Активные соединения программы (SSTP, L2TP, IKEv2) — по списку rasdial и по сетевым интерфейсам.
        try { Disconnect-OwnRasConnections } catch { Add-Problem "Разрыв соединений RAS - $_" }

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
