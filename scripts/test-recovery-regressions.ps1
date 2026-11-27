# Извлечь функции без запуска административных сценариев, которые их содержат.
$ErrorActionPreference = 'Stop'
function Read-FunctionText([string]$scriptName, [string]$name) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $scriptName), [ref]$tokens, [ref]$errors)
    if ($errors) { throw "$scriptName содержит синтаксическую ошибку" }
    $fn = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if (-not $fn) { throw "В $scriptName нет функции $name" }
    return $fn.Extent.Text
}
function Read-Function([string]$scriptName, [string]$name) {
    return [scriptblock]::Create((Read-FunctionText $scriptName $name))
}

. (Read-Function 'install-dev-service.ps1' 'Test-DevServiceImage')
$expectedExe = 'C:\Program Files\SplitVpn.Dev\service\SplitVpn.Service.exe'
if (-not (Test-DevServiceImage ('"' + $expectedExe + '" --service') $expectedExe)) { throw 'Не распознана служба разработки' }
if (Test-DevServiceImage 'C:\Program Files\SplitVpn\SplitVpn.Service.exe' $expectedExe) { throw 'Служба MSI принята за dev-службу' }

# Функции recover-network.ps1 и проверки над ними. Проверки написаны без объектов .NET (только массивы, хеш-таблицы и
# ConvertFrom-Json) и выполняются дважды: здесь (FullLanguage) и в отдельном powershell.exe в режиме ограниченного
# языка (ConstrainedLanguage) — запасной путь скрипта должен работать и там.
$recoveryFunctions = (@(
    'Add-Problem', 'Restore-SavedDns', 'Restore-AdapterDns', 'Get-UntrustedReason', 'Stop-RecoveryServices', 'Invoke-Tool',
    'Test-RasUnavailable', 'Test-OwnRasName', 'Test-SafeRasName', 'Test-ProgramRasName', 'Register-RasdialFailure',
    'Read-OwnRasNames', 'Get-RasdialNames', 'Get-OwnRasInterfaces', 'Get-OwnRasActive', 'Wait-OwnRasGone', 'Test-RunningAsSystem',
    'Disconnect-RasNameAsSystem', 'Disconnect-OwnRasConnections'
) | ForEach-Object { Read-FunctionText 'recover-network.ps1' $_ }) -join "`r`n`r`n"

$harness = @'
function Assert-True($condition, [string]$message) { if (-not $condition) { throw $message } }
$clm = [string]$ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage'

# --- Настоящие вызовы (безвредные): запуск со сроком, чтение вывода в разных кодировках, rasdial без аргументов. ---
$cmd = "$env:SystemRoot\System32\cmd.exe"
# Процесс живёт около секунды: Start-Process в Windows PowerShell 5.1 открывает процесс по номеру уже после запуска, и
# мгновенно завершившийся «cmd /c exit 7» иногда (под нагрузкой) не отдаёт код выхода — Invoke-Tool тогда честно вернёт -1.
$exit = Invoke-Tool $cmd '/c ping -n 2 127.0.0.1 >nul & exit 7' 15
Assert-True ($exit.Code -eq 7) "Код выхода не получен: $($exit.Code)"
$started = Get-Date
$timedOut = $null
try { $null = Invoke-Tool "$env:SystemRoot\System32\PING.EXE" '-n 30 127.0.0.1' 1 } catch { $timedOut = [string]$_ }
Assert-True ($timedOut -match 'не ответил за 1 с') "Срок запуска не соблюдён: $timedOut"
Assert-True (((Get-Date) - $started).TotalSeconds -lt 10) 'Зависший процесс не завершён по сроку'
foreach ($fixture in @(Get-ChildItem -LiteralPath $fixtureDir -Filter '*.txt')) {
    $read = Invoke-Tool $cmd ('/c type "{0}"' -f $fixture.FullName) 15
    $found = Read-OwnRasNames $read.Texts
    $expected = if ($fixture.Name -like 'names-*') { 'SplitVpn Proto 2|Раздельный VPN 1a2b3c4d' } else { '' }
    Assert-True ((($found | Sort-Object) -join '|') -eq $expected) "Имена RAS ($($fixture.Name)) прочитаны неверно: $($found -join '|')"
}
# rasdial без аргументов и интерфейсы читаются по-настоящему: только проверка, что вызовы работают в этом режиме.
$null = Get-RasdialNames
$null = Get-OwnRasInterfaces
# Права настоящего каталога Windows читаются и разбираются в этом режиме: владелец TrustedInstaller, запись только у
# SYSTEM, Administrators и TrustedInstaller — доверие.
$windowsTrust = Get-UntrustedReason $env:SystemRoot
Assert-True (-not $windowsTrust) "Каталог Windows не принят: $windowsTrust"

Assert-True (Test-RasUnavailable 1058) 'RasMan отключена - не распознано'
Assert-True (-not (Test-RasUnavailable 623)) '623 принят за недоступность RasMan'
Assert-True (Test-SafeRasName 'Раздельный VPN b9327419') 'Обычное имя отклонено'
foreach ($bad in 'Раздельный VPN "x', 'Раздельный VPN %PATH%', 'Раздельный VPN a\', 'Раздельный VPN & calc', "Раздельный VPN b9327419`n",
    "Раздельный VPN`r`n") {
    Assert-True (-not (Test-SafeRasName $bad)) "Опасное имя принято: $bad"
}
# Задаче от имени SYSTEM — только имена точно в формате программы.
foreach ($good in 'Раздельный VPN', 'Раздельный VPN b9327419', 'SplitVpn Proto', 'SplitVpn Proto 2', 'SplitVpn Proto 12') {
    Assert-True (Test-ProgramRasName $good) "Имя программы отклонено: $good"
}
foreach ($bad in 'Раздельный VPN evil', 'Раздельный VPN B9327419', 'Раздельный VPN b932741', 'Раздельный VPN b93274190',
    'Раздельный VPN  b9327419', 'раздельный vpn b9327419', 'Раздельный VPN b9327419 x', 'SplitVpn Proto 1', 'SplitVpn Proto 02',
    'SplitVpn Proto x', 'SplitVpn Prototype', 'Раздельный VPN (1)', 'Раздельный VPN "x', 'Раздельный VPN b932741g',
    "Раздельный VPN b9327419`n", "Раздельный VPN`n", "SplitVpn Proto 2`r`n", 'Раздельный VPN b9327419 ', ' SplitVpn Proto') {
    Assert-True (-not (Test-ProgramRasName $bad)) "Чужое имя принято за имя программы: $bad"
}

# --- Доверие копии DNS по тексту SDDL (Get-Item, Get-Acl и Get-LocalGroupMember подменены). ---
$acl = @{ Attributes = 'Directory'; Sddl = ''; Owner = ''; Throw = $null; Members = @() }
function Get-Item($LiteralPath, [switch]$Force, $ErrorAction) { return @{ Attributes = $acl.Attributes } }
function Get-Acl($LiteralPath, $ErrorAction) { if ($acl.Throw) { throw $acl.Throw }; return @{ Sddl = $acl.Sddl; Owner = $acl.Owner } }
function Get-LocalGroupMember($SID, $ErrorAction) { return $acl.Members }
function Test-Sddl([string]$sddl) { $acl.Sddl = $sddl; return Get-UntrustedReason 'X:\data' }
$ti = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$base = 'O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
$trustedSamples = @(
    $base,
    'O:BAG:SYD:AI(A;ID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;OICIID;GRGX;;;AU)',
    "O:${ti}G:${ti}D:P(A;;FA;;;$ti)(A;;0x1301bf;;;SY)(A;;0x1301bf;;;BA)(A;;FR;;;WD)",
    ($base + '(D;;FA;;;BU)(D;OICI;GA;;;WD)(XD;;FA;;;IU)'),
    ($base + '(A;OICIIO;FA;;;BU)(A;CIIO;GA;;;AU)'),
    ($base + '(A;;0x80000000;;;BU)(A;;RCLOSW;;;IU)'),
    'O:SYG:SYD:P',
    # Настоящие права каталога службы и файла копии DNS.
    'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',
    'O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)',
    # Хвост SACL (аудит, метка целостности) на решение не влияет; пустой список записей — доступа нет ни у кого.
    ($base + 'S:AI(AU;SA;FA;;;WD)'),
    ($base + 'S:(ML;;NW;;;LW)'),
    'O:SYG:SYD:'
)
foreach ($sample in $trustedSamples) {
    $reason = Test-Sddl $sample
    Assert-True (-not $reason) "Доверенные права отклонены: $sample - $reason"
}
$untrustedSamples = @(
    @(($base + '(A;CI;DCLCRPCR;;;BU)'), 'записи посторонней учётной записи \(BU\)'),
    @(($base + '(A;OICIID;0x1301bf;;;AU)'), 'AU'),
    @(($base + '(A;;GW;;;WD)'), 'WD'),
    @(($base + '(A;;FW;;;IU)'), 'IU'),
    @(($base + '(A;;GA;;;S-1-5-32-545)'), 'S-1-5-32-545'),
    @(($base + '(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;BU)'), 'BU'),
    @(($base + '(A;ID;WDWO;;;S-1-5-21-1-2-3-1001)'), '1001'),
    @(($base + '(A;;SD;;;S-1-3-4)'), 'S-1-3-4'),
    @(($base + '(A;;0xFFFFFFFF;;;BU)'), 'BU'),
    @(($base + '(A;;ZZ;;;BU)'), 'не разобран'),
    @(($base + '(A;;;;;BU)'), 'не разобран'),
    @(($base + '(A;IOX;FA;;;BU)'), 'не разобран'),
    @(($base + '(A;;FA;;BU)'), 'не разобран'),
    @(($base + '(XA;;FA;;;WD;(Member_of {SID(BA)}))'), 'не разобран'),
    @(($base + 'junk'), 'не разобран'),
    @('O:SYG:SYD:NO_ACCESS_CONTROL', 'всем'),
    @('O:SYG:SY', 'не прочитаны'),
    @('', 'не прочитаны'),
    @(($base -replace '^O:SY', 'O:BU'), 'посторонней учётной записи \(BU\)'),
    @(($base -replace '^O:SY', 'O:S-1-5-21-1-2-3-1001'), 'посторонней учётной записи \(S-1-5-21-1-2-3-1001\)'),
    # Пакеты приложений (AppContainer): псевдоним AC и SID S-1-15-2-1.
    @(($base + '(A;;GW;;;AC)'), 'записи посторонней учётной записи \(AC\)'),
    @(($base + '(A;;0x1301BF;;;S-1-15-2-1)'), 'S-1-15-2-1'),
    # Права числом: GENERIC_WRITE, GENERIC_READ|GENERIC_WRITE, десятичное GENERIC_READ|WriteData, CR (0x100), Delete.
    @(($base + '(A;;0x40000000;;;BU)'), 'записи посторонней учётной записи \(BU\)'),
    @(($base + '(A;;0xC0000000;;;BU)'), 'записи посторонней учётной записи \(BU\)'),
    @(($base + '(A;;2147483650;;;BU)'), 'записи посторонней учётной записи \(BU\)'),
    @(($base + '(A;;0x100;;;BU)'), 'записи посторонней учётной записи \(BU\)'),
    @(($base + '(A;;0x10000;;;BU)'), 'записи посторонней учётной записи \(BU\)'),
    # Разрешающие записи редких типов (ZA — объектная с условием, AU — тип аудита не на своём месте) идут в счёт.
    @(($base + '(ZA;;FA;;;BU)'), 'записи посторонней учётной записи \(BU\)'),
    @(($base + '(AU;SA;FA;;;WD)'), 'записи посторонней учётной записи \(WD\)'),
    # Запрет перед разрешением для той же учётной записи не спасает: в счёт идёт каждая разрешающая запись.
    @(($base + '(D;;FA;;;BU)(A;;FA;;;BU)'), 'записи посторонней учётной записи \(BU\)'),
    # Владелец — псевдоним учётной записи домена или компьютера, членство не установлено.
    @(($base -replace '^O:SY', 'O:LA'), 'посторонней учётной записи \(LA\)'),
    @(($base -replace '^O:SY', 'O:DA'), 'посторонней учётной записи \(DA\)')
)
foreach ($sample in $untrustedSamples) {
    $reason = Test-Sddl $sample[0]
    Assert-True ($reason -match $sample[1]) "Недоверенные права приняты или причина неверна: $($sample[0]) - $reason"
}
# Владелец - прямой член Administrators: доверие (как и раньше). Ссылка и сбой чтения прав - недоверие.
$acl.Members = @('{"SID":{"Value":"S-1-5-21-1-2-3-1001"}}' | ConvertFrom-Json)
$reason = Test-Sddl ($base -replace '^O:SY', 'O:S-1-5-21-1-2-3-1001')
Assert-True (-not $reason) "Владелец из Administrators отклонён: $reason"
# Владелец-псевдоним (LA — встроенный Administrator, DA — Domain Admins): сверка по имени с прямыми членами группы.
$acl.Members = @(('{"Name":"PC\\Administrator","SID":{"Value":"S-1-5-21-1-2-3-500"}}' | ConvertFrom-Json),
    ('{"Name":"CORP\\Domain Admins","SID":{"Value":"S-1-5-21-4-5-6-512"}}' | ConvertFrom-Json))
foreach ($case in @(@('LA', 'pc\administrator'), @('DA', 'CORP\Domain Admins'))) {
    $acl.Owner = $case[1]
    $reason = Test-Sddl ($base -replace '^O:SY', "O:$($case[0])")
    Assert-True (-not $reason) "Владелец $($case[0]) из Administrators отклонён: $reason"
}
# Имя владельца не среди членов, не прочитано или совпадает лишь частью — недоверие; сбой чтения группы — тоже.
foreach ($name in 'PC\Guest', '', 'Administrator', 'CORP\Domain Admins2') {
    $acl.Owner = $name
    $reason = Test-Sddl ($base -replace '^O:SY', 'O:LA')
    Assert-True ($reason -match 'посторонней учётной записи \(LA\)') "Владелец LA ($name) принят без членства: $reason"
}
$acl.Owner = 'PC\Administrator'
function Get-LocalGroupMember($SID, $ErrorAction) { throw 'группа не прочитана' }
$reason = Test-Sddl ($base -replace '^O:SY', 'O:LA')
Assert-True ($reason -match 'посторонней учётной записи \(LA\)') "Сбой чтения группы принят за членство: $reason"
function Get-LocalGroupMember($SID, $ErrorAction) { return $acl.Members }
# Владелец BU — не член Administrators: отклоняется и при сверке по имени.
$acl.Owner = 'BUILTIN\Users'
Assert-True ((Test-Sddl ($base -replace '^O:SY', 'O:BU')) -match 'посторонней учётной записи \(BU\)') 'Владелец BU принят'
$acl.Owner = ''
$acl.Members = @()
$acl.Attributes = 'Directory, ReparsePoint'
Assert-True ((Test-Sddl $base) -match 'ссылка') 'Ссылка принята'
$acl.Attributes = 'Directory'
$acl.Throw = 'нет доступа'
Assert-True ((Test-Sddl $base) -match 'не проверяется - нет доступа') 'Сбой чтения прав принят за доверие'
$acl.Throw = $null
Remove-Item -LiteralPath 'function:Get-Item', 'function:Get-Acl', 'function:Get-LocalGroupMember'

# --- Остановка службы: сбой запроса первой не пропускает вторую. ---
$log = @{ Checked = @(); Changes = @() }
function Get-CimInstance($ClassName, $Filter, $ErrorAction) {
    $log.Checked += $Filter
    if ($Filter -match "='SplitVpn'") { throw 'сбой SCM' }
    return $null
}
$problems = @()
$output = Stop-RecoveryServices
Assert-True (-not $output) 'Неизвестное состояние службы принято за остановку'
# Сбой запроса SplitVpn даёт две записи: остановка не подтверждена и повторный запрос для принудительного завершения
# тоже не удался. Вторая служба при этом всё равно должна быть опрошена.
Assert-True ($log.Checked -match "='SplitVpnDev'") 'Запрос второй службы пропущен'
Assert-True ($log.Checked.Count -eq 3 -and $problems.Count -eq 2) "Сбой запроса службы учтён неверно: $($problems -join ' / ')"

# --- DNS. Сброс семейства на «автоматически» идёт через netsh по полному пути, состояние DHCP IPv4 - через
# Get-NetIPInterface: оба подменены, настоящий адаптер не трогается. ---
$failFamily = $null
function Set-DnsClientServerAddress {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Family, [string[]]$ServerAddresses, [switch]$ResetServerAddresses)
    process {
        if ($Family.AddressFamily -eq $failFamily) { throw 'сбой записи DNS' }
        $log.Changes += "$($Family.AddressFamily)|$ResetServerAddresses|$($ServerAddresses -join ',')"
    }
}
$dhcp = @{ IPv4 = 'Enabled'; IPv6 = 'Enabled' }
function Get-NetIPInterface($InterfaceIndex, $AddressFamily, $ErrorAction) { return @{ Dhcp = $dhcp[[string]$AddressFamily] } }
New-Item -Path "function:$env:SystemRoot\System32\netsh.exe" -Value {
    $log.Changes += "netsh|$($args -join ' ')"
    $global:LASTEXITCODE = 0
} | Out-Null
function New-Families([string]$json) { return @($json | ConvertFrom-Json) }
function Invoke-Dns($families, $saved, $resolvers) {
    $log.Changes = @()
    $script:problems = @()
    if (-not $resolvers) { $resolvers = @{ V4 = $false; V6 = $false } }
    Restore-SavedDns $adapter $families $saved $resolvers
    return ($log.Changes -join ';')
}
$adapter = '{"ifIndex":7,"Name":"Тестовый"}' | ConvertFrom-Json
$resetV4 = 'netsh|interface ipv4 set dnsservers name=7 source=dhcp'
$resetV6 = 'netsh|interface ipv6 set dnsservers name=7 source=dhcp'
$mixed = New-Families '[{"AddressFamily":2,"ServerAddresses":["127.0.0.1"]},{"AddressFamily":23,"ServerAddresses":["::1"]}]'
$onlyV6 = New-Families '[{"AddressFamily":2,"ServerAddresses":["192.0.2.42"]},{"AddressFamily":23,"ServerAddresses":["::1"]}]'
$savedEmptyV6 = '{"NameServerV4":"192.0.2.2,192.0.2.3","NameServerV6":""}' | ConvertFrom-Json

# По копии: IPv4 восстанавливается, пустой IPv6 («автоматически») сбрасывается; чужие списки не трогаются.
# С 0.17.9 набор посредника на основном адаптере - «адрес адаптера, 127.0.0.1»; обратный порядок - не наш.
$families = New-Families ('[{"AddressFamily":2,"ServerAddresses":["127.0.0.1"]},{"AddressFamily":23,"ServerAddresses":["::1"]},' +
    '{"AddressFamily":2,"ServerAddresses":["192.0.2.42"]},{"AddressFamily":2,"ServerAddresses":["192.168.1.100","127.0.0.1"]},' +
    '{"AddressFamily":2,"ServerAddresses":["127.0.0.1","192.168.1.100"]},{"AddressFamily":23,"ServerAddresses":["2001:db8::53"]}]')
$result = Invoke-Dns $families $savedEmptyV6
Assert-True ($result -eq "2|False|192.0.2.2,192.0.2.3;$resetV6;2|False|192.0.2.2,192.0.2.3") "Неверное восстановление DNS: $result"
Assert-True (-not $problems.Count) "Лишние проблемы при восстановлении DNS: $problems"

# DHCP IPv4 включён, у IPv6 поле Dhcp выключено (флаги M/O, так у большинства адаптеров), копии нет: наш ::1 сбрасывается.
$dhcp = @{ IPv4 = 'Enabled'; IPv6 = 'Disabled' }
$result = Invoke-Dns $mixed $null
Assert-True ($result -eq "$resetV4;$resetV6") "IPv6 с выключенным Dhcp не сброшен: $result"
Assert-True (-not $problems.Count) "Лишнее предупреждение о статическом IPv6: $problems"
$result = Invoke-Dns $onlyV6 $null
Assert-True ($result -eq $resetV6) "Наш ::1 рядом с чужим IPv4 не сброшен: $result"

# Копия с пустым NameServerV6 (исходно «автоматически») при выключенном Dhcp IPv6 - тоже сброс.
$result = Invoke-Dns $onlyV6 $savedEmptyV6
Assert-True ($result -eq $resetV6 -and -not $problems.Count) "IPv6 по копии с пустым списком не сброшен: $result / $problems"

# Копия с адресами IPv6 - они и возвращаются (loopback из копии отбрасывается).
$savedV6 = '{"NameServerV4":"","NameServerV6":"2001:db8::1, 2001:db8::2 ::1"}' | ConvertFrom-Json
$result = Invoke-Dns $onlyV6 $savedV6
Assert-True ($result -eq '23|False|2001:db8::1,2001:db8::2' -and -not $problems.Count) "IPv6 по копии не восстановлен: $result / $problems"

# Исходный IPv6-список неизвестен (ipv6Unknown) - адреса копии не используются, сброс.
$savedUnknown = '{"NameServerV4":"","NameServerV6":"2001:db8::1","ipv6Unknown":true}' | ConvertFrom-Json
$result = Invoke-Dns $onlyV6 $savedUnknown
Assert-True ($result -eq $resetV6) "IPv6 с неизвестным исходным списком не сброшен: $result"

# Статический IPv4 без копии: IPv4 не сбрасывается (предупреждение только про IPv4), наш ::1 - сбрасывается.
$dhcp = @{ IPv4 = 'Disabled'; IPv6 = 'Disabled' }
$result = Invoke-Dns $mixed $null
Assert-True ($result -eq $resetV6) "IPv6 пропущен рядом со статическим IPv4: $result"
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'IPv4' -and $problems[0] -notmatch 'IPv6') "Статический IPv4 учтён неверно: $problems"
$result = Invoke-Dns (New-Families '[{"AddressFamily":2,"ServerAddresses":["127.0.0.1"]}]') $null
Assert-True (-not $result -and $problems.Count -eq 1) "Статический адаптер сброшен: $result"
# Статический IPv4, но запись в копии есть: правило статического адреса не действует (как у службы). Пустой список
# IPv4 в копии - исходно «автоматически», он и возвращается; адреса в копии - возвращаются они.
$savedEmpty = '{"NameServerV4":"","NameServerV6":""}' | ConvertFrom-Json
$result = Invoke-Dns $mixed $savedEmpty
Assert-True ($result -eq "$resetV4;$resetV6" -and -not $problems.Count) "Копия с пустым IPv4 на статическом адресе не возвращена: $result / $problems"
$result = Invoke-Dns $mixed $savedEmptyV6
Assert-True ($result -eq "2|False|192.0.2.2,192.0.2.3;$resetV6" -and -not $problems.Count) "Копия на статическом адресе не возвращена: $result / $problems"

# --- Адаптеры без IP-интерфейса (WAN Miniport, Teredo, 6to4, отключённые): молча пропускаются; сбой на адаптере с
# IP-интерфейсом и любой иной сбой - проблема. ---
$noIp = @(14)
$ipFails = @()
$dnsFails = @{}
function Get-DnsClientServerAddress($InterfaceIndex, $ErrorAction) {
    if ($noIp -contains $InterfaceIndex) {
        Write-Error -Category ObjectNotFound -Message "Не найдены объекты MSFT_DNSClientServerAddress ($InterfaceIndex)" -ErrorAction Stop
    }
    if ($dnsFails.ContainsKey([string]$InterfaceIndex)) {
        Write-Error -Category $dnsFails[[string]$InterfaceIndex] -Message "сбой DNS ($InterfaceIndex)" -ErrorAction Stop
    }
    return $mixed
}
function Get-NetIPInterface($InterfaceIndex, $AddressFamily, $ErrorAction) {
    if ($ipFails -contains $InterfaceIndex) { throw 'сбой CIM' }
    if ($noIp -contains $InterfaceIndex) {
        Write-Error -Category ObjectNotFound -Message "Не найдены объекты MSFT_NetIPInterface ($InterfaceIndex)" -ErrorAction Stop
    }
    return @{ Dhcp = $dhcp[[string]$AddressFamily] }
}
function Invoke-AdapterDns([int]$index) {
    $log.Changes = @()
    $script:problems = @()
    Restore-AdapterDns (('{"ifIndex":' + $index + ',"Name":"Адаптер ' + $index + '"}') | ConvertFrom-Json) $null @{ V4 = $false; V6 = $false }
    return ($log.Changes -join ';')
}
$dhcp = @{ IPv4 = 'Enabled'; IPv6 = 'Disabled' }
$result = Invoke-AdapterDns 14
Assert-True (-not $result -and -not $problems.Count) "Адаптер без IP-интерфейса дал предупреждение: $result / $problems"
$dnsFails = @{ '7' = 'ObjectNotFound' }
$result = Invoke-AdapterDns 7
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'Адаптер 7' -and $problems[0] -match 'сбой DNS') "Сбой DNS на адаптере с IP-интерфейсом скрыт: $problems"
$dnsFails = @{ '7' = 'NotSpecified' }
$result = Invoke-AdapterDns 7
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'сбой DNS') "Иной сбой DNS скрыт: $problems"
$dnsFails = @{}
$noIp = @(7)
$ipFails = @(7)
$result = Invoke-AdapterDns 7
Assert-True ($problems.Count -eq 1) "Сбой чтения IP-интерфейса принят за его отсутствие: $problems"
$noIp = @()
$ipFails = @()
$result = Invoke-AdapterDns 7
Assert-True ($result -eq "$resetV4;$resetV6" -and -not $problems.Count) "Обычный адаптер не обработан: $result / $problems"
Remove-Item -LiteralPath 'function:Get-DnsClientServerAddress'
function Get-NetIPInterface($InterfaceIndex, $AddressFamily, $ErrorAction) { return @{ Dhcp = $dhcp[[string]$AddressFamily] } }

# Без копии, резолвер пользователя на [::1]:53 - его ::1 не трогается; на 127.0.0.1:53 при нашем IPv4 - не трогается ничего.
$dhcp = @{ IPv4 = 'Enabled'; IPv6 = 'Disabled' }
$result = Invoke-Dns $mixed $null @{ V4 = $false; V6 = $true }
Assert-True ($result -eq $resetV4) "Резолвер пользователя на [::1] не учтён: $result"
$result = Invoke-Dns $mixed $null @{ V4 = $true; V6 = $false }
Assert-True (-not $result) "Резолвер пользователя на 127.0.0.1 не учтён: $result"

# Сбой записи DNS по копии для IPv4 попадает в проблемы и не обрывает обработку IPv6.
$dhcp = @{ IPv4 = 'Enabled'; IPv6 = 'Enabled' }
$failFamily = 2
$result = Invoke-Dns $mixed $savedEmptyV6
$failFamily = $null
Assert-True ($result -eq $resetV6) "IPv6 пропущен после сбоя IPv4: $result"
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'сбой записи DNS') "Сбой записи DNS не учтён: $problems"

# --- Соединения RAS. rasdial, schtasks и список интерфейсов подменены моделью: Connected - подключённые соединения
# (их видят интерфейсы), RasdialSees - какие из них видит rasdial администратора. ---
function Start-Sleep { }
function New-Sim([string[]]$connected, [string[]]$sees) {
    return @{ Connected = @($connected); RasdialSees = @($sees); System = $false; SystemWorks = $true; Vanish = @()
        ListThrows = $null; ListCode = 0; CreateCode = 0; RunCode = 0; RunThrows = $null; IfaceThrows = $null; DisconnectThrows = $null
        Task = $false; Calls = @(); Create = $null }
}
function Remove-Connected([string]$name) { $sim.Connected = @($sim.Connected | Where-Object { $_ -ne $name }) }
function Invoke-Tool([string]$path, [string]$arguments, [int]$seconds) {
    $leaf = Split-Path -Leaf $path
    $sim.Calls += ("$leaf $arguments").Trim()
    if ($leaf -eq 'rasdial.exe' -and -not $arguments) {
        if ($sim.ListThrows) { throw $sim.ListThrows }
        if ($sim.ListCode) { return @{ Code = $sim.ListCode; Texts = @() } }
        $seen = @($sim.Connected | Where-Object { $sim.RasdialSees -contains $_ })
        $text = "Нет соединений`r`nКоманда успешно завершена.`r`n"
        if ($seen.Count) { $text = "Подключено к`r`n" + ($seen -join "`r`n") + "`r`nКоманда успешно завершена.`r`n" }
        return @{ Code = 0; Texts = @($text) }
    }
    if ($leaf -eq 'rasdial.exe') {
        if ($sim.DisconnectThrows) { throw $sim.DisconnectThrows }
        $name = ($arguments -split '"')[1]
        if ($sim.Vanish -contains $name) { Remove-Connected $name; return @{ Code = 1; Texts = @() } }
        if ($sim.RasdialSees -contains $name -and $sim.Connected -contains $name) { Remove-Connected $name; return @{ Code = 0; Texts = @() } }
        return @{ Code = 623; Texts = @() }
    }
    if ($leaf -eq 'schtasks.exe') {
        $verb = ($arguments -split ' ')[0]
        if ($verb -eq '/create') {
            $sim.Create = $arguments
            if ($sim.CreateCode -eq 0) { $sim.Task = $true }
            return @{ Code = $sim.CreateCode; Texts = @() }
        }
        if ($verb -eq '/run') {
            if ($sim.RunThrows) { throw $sim.RunThrows }
            if ($sim.RunCode -eq 0 -and $sim.SystemWorks) { Remove-Connected (($sim.Create -split '\\"')[3]) }
            return @{ Code = $sim.RunCode; Texts = @() }
        }
        if ($verb -eq '/delete') {
            $code = 1
            if ($sim.Task) { $code = 0 }
            $sim.Task = $false
            return @{ Code = $code; Texts = @() }
        }
        if ($verb -eq '/query') {
            $code = 1
            if ($sim.Task) { $code = 0 }
            return @{ Code = $code; Texts = @() }
        }
    }
    throw "Неожиданный запуск: $leaf $arguments"
}
function Get-OwnRasInterfaces {
    if ($sim.IfaceThrows) { throw $sim.IfaceThrows }
    return ,@($sim.Connected | Where-Object { Test-OwnRasName $_ })
}
function Test-RunningAsSystem { return $sim.System }
function Invoke-Disconnect {
    $script:problems = @()
    $script:rasdialHung = $false
    Disconnect-OwnRasConnections
    return ($sim.Calls | Where-Object { $_ -ne 'rasdial.exe' }) -join ';'
}
$r1 = 'Раздельный VPN 1a2b3c4d'
$p2 = 'SplitVpn Proto 2'

# rasdial видит оба соединения программы: разрыв без /PHONEBOOK, чужое не трогается, планировщик не нужен.
$sim = New-Sim @($r1, 'Office VPN', $p2) @($r1, 'Office VPN', $p2)
$calls = Invoke-Disconnect
Assert-True ($calls -eq "rasdial.exe `"$r1`" /disconnect;rasdial.exe `"$p2`" /disconnect") "Неверный разрыв RAS: $calls"
Assert-True (-not $problems.Count) "Лишние проблемы при разрыве RAS: $problems"

# rasdial администратора соединения службы не видит, а интерфейс подключён: обычный разрыв (его код не в счёт), затем
# одноразовая задача от имени SYSTEM, которая удаляется после выполнения.
$sim = New-Sim @($r1) @()
$calls = Invoke-Disconnect
Assert-True (-not $problems.Count) "Лишние проблемы при разрыве от имени SYSTEM: $problems"
Assert-True ($sim.Connected.Count -eq 0) 'Соединение, найденное по интерфейсу, не разорвано'
Assert-True ($calls -match "^rasdial\.exe `"$r1`" /disconnect;schtasks\.exe /create .*;schtasks\.exe /run /i /tn (SplitVpn-RasDisconnect-[0-9a-f]{32});schtasks\.exe /delete /tn \1 /f$") "Неверная последовательность задачи SYSTEM: $calls"
$expectedCreate = '/create /tn {0} /ru SYSTEM /sc once /st 00:00 /tr "\"{1}\System32\rasdial.exe\" \"{2}\" /disconnect" /f' -f ($sim.Create -split ' ')[2], $env:SystemRoot, $r1
Assert-True ($sim.Create -ceq $expectedCreate) "Неверная команда задачи: $($sim.Create)"
Assert-True (-not $sim.Task) 'Задача планировщика осталась'
$lastCreate = $sim.Create

# Скрипт уже работает от имени SYSTEM: планировщик не используется, оставшееся соединение - проблема с подсказкой.
$sim = New-Sim @($r1) @()
$sim.System = $true
$calls = Invoke-Disconnect
Assert-True ($calls -notmatch 'schtasks') "Планировщик вызван от имени SYSTEM: $calls"
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'осталось подключённым' -and $problems[0] -match 'Перезагрузите') "Оставшееся соединение не учтено: $problems"

# Задача выполнилась, а соединение осталось: проблема, задача всё равно удалена.
$sim = New-Sim @($r1) @()
$sim.SystemWorks = $false
$calls = Invoke-Disconnect
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'осталось подключённым') "Неразорванное соединение не учтено: $problems"
Assert-True ($calls -match 'schtasks\.exe /delete' -and -not $sim.Task) 'Задача не удалена после неудачного разрыва'

# Задача не создана: проблема, попытка удаления (и проверка, что задачи нет), соединение - в проблемах.
$sim = New-Sim @($r1) @()
$sim.CreateCode = 1
$calls = Invoke-Disconnect
Assert-True ($calls -match 'schtasks\.exe /delete' -and $calls -match 'schtasks\.exe /query' -and $calls -notmatch '/run') "Неверная обработка несозданной задачи: $calls"
Assert-True ($problems.Count -eq 2 -and $problems[0] -match 'не создана' -and $problems[1] -match 'осталось подключённым') "Несозданная задача не учтена: $problems"

# Запуск задачи завис (истёк срок): проблема, задача удалена.
$sim = New-Sim @($r1) @()
$sim.RunThrows = 'schtasks.exe не ответил за 30 с - процесс завершён'
$calls = Invoke-Disconnect
Assert-True (-not $sim.Task -and $calls -match 'schtasks\.exe /delete') 'Задача осталась после зависшего запуска'
Assert-True ($problems.Count -eq 2 -and $problems[0] -match 'не ответил' -and $problems[1] -match 'осталось подключённым') "Зависший запуск задачи не учтён: $problems"

# rasdial не ответил за срок: проблема, но проверка по интерфейсам и остальные шаги продолжаются.
$sim = New-Sim @() @()
$sim.ListThrows = 'rasdial.exe не ответил за 15 с - процесс завершён'
$calls = Invoke-Disconnect
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'не ответил') "Зависший rasdial не учтён: $problems"
$sim = New-Sim @($r1) @()
$sim.ListThrows = 'rasdial.exe не ответил за 15 с - процесс завершён'
$calls = Invoke-Disconnect
# После первого зависания rasdial больше не запускается: ни список, ни разрыв по имени (каждый ждал бы ещё 15 с), ни
# задача от имени SYSTEM (rasdial в ней завис бы так же и остался бы висеть). Оставшееся соединение - совет перезагрузить.
$rasdialRuns = @($sim.Calls | Where-Object { $_ -like 'rasdial.exe*' })
Assert-True ($rasdialRuns.Count -eq 1 -and $calls -notmatch 'schtasks') "После зависания rasdial запущен снова: $($sim.Calls -join ';')"
Assert-True ($sim.Connected.Count -eq 1 -and $problems.Count -eq 2 -and $problems[0] -match 'не ответил' -and
    $problems[1] -match 'осталось подключённым' -and $problems[1] -match 'Перезагрузите' -and $problems[1] -match 'не запускался') "Зависший rasdial учтён неверно: $problems"

# Список получен, но rasdial завис на разрыве: дальше - только интерфейсы, без задачи SYSTEM.
$sim = New-Sim @($r1, $p2) @($r1, $p2)
$sim.DisconnectThrows = 'rasdial.exe не ответил за 15 с - процесс завершён'
$calls = Invoke-Disconnect
$rasdialRuns = @($sim.Calls | Where-Object { $_ -like 'rasdial.exe*' })
Assert-True ($rasdialRuns.Count -eq 2 -and $rasdialRuns[1] -eq "rasdial.exe `"$r1`" /disconnect") "После зависшего разрыва rasdial запущен снова: $($sim.Calls -join ';')"
Assert-True ($calls -notmatch 'schtasks' -and $sim.Connected.Count -eq 2) "После зависшего разрыва запущена задача SYSTEM: $calls"
Assert-True ($problems.Count -eq 3 -and $problems[0] -match 'не ответил' -and ($problems[1..2] -match 'Перезагрузите').Count -eq 2) "Зависший разрыв учтён неверно: $problems"

# RasMan остановлена или отключена (1058 и др.): соединений нет, ложной тревоги нет.
$sim = New-Sim @() @()
$sim.ListCode = 1058
$calls = Invoke-Disconnect
Assert-True (-not $problems.Count -and -not $calls) "Остановленная RasMan дала тревогу: $problems / $calls"

# rasdial <имя> /disconnect вернул ошибку, потому что соединение уже пропало само: проблемы нет.
$sim = New-Sim @($r1) @($r1)
$sim.Vanish = @($r1)
$calls = Invoke-Disconnect
Assert-True (-not $problems.Count -and $calls -notmatch 'schtasks') "Пропавшее соединение учтено как сбой: $problems / $calls"

# Интерфейсы не прочитаны: проблема одна, без повторов на каждой проверке.
$sim = New-Sim @() @()
$sim.IfaceThrows = 'сбой CIM'
$calls = Invoke-Disconnect
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'интерфейсы не прочитаны') "Сбой чтения интерфейсов учтён неверно: $problems"

# Имя с кавычкой не передаётся ни в rasdial, ни в планировщик - только в проблемы.
$sim = New-Sim @('Раздельный VPN "x') @()
$calls = Invoke-Disconnect
Assert-True (-not $calls -and $problems.Count -eq 1 -and $problems[0] -match 'осталось подключённым') "Опасное имя передано в командную строку: $calls / $problems"

# Имя с префиксом программы, но не в её формате (такую запись может завести обычный пользователь): обычный rasdial -
# можно, задача от имени SYSTEM - нет; осталось подключённым - проблема с просьбой проверить владельца.
$foreign = 'Раздельный VPN evil'
$sim = New-Sim @($foreign) @()
$calls = Invoke-Disconnect
Assert-True ($calls -eq "rasdial.exe `"$foreign`" /disconnect") "Похожее имя передано задаче SYSTEM: $calls"
Assert-True ($problems.Count -eq 1 -and $problems[0] -match 'осталось подключённым' -and $problems[0] -match 'чьё это соединение') "Похожее имя учтено неверно: $problems"
$sim = New-Sim @($foreign) @($foreign)
$calls = Invoke-Disconnect
Assert-True (-not $problems.Count -and $sim.Connected.Count -eq 0) "Похожее имя не разорвано обычным rasdial: $calls / $problems"
'@

# Вывод rasdial на английском и русском языке в UTF-8, OEM и ANSI системы (кодовые страницы без кириллицы пропускаются).
try { [Text.Encoding]::RegisterProvider([Text.CodePagesEncodingProvider]::Instance) } catch { }
$temp = [IO.Directory]::CreateDirectory((Join-Path ([IO.Path]::GetTempPath()) ('splitvpn-recovery-test-' + [guid]::NewGuid())))
try {
    $fixtureDir = Join-Path $temp.FullName 'fixtures'
    [void][IO.Directory]::CreateDirectory($fixtureDir)
    $nls = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage'
    $samples = @{
        'names-en' = "Connected to`r`nРаздельный VPN 1a2b3c4d`r`nOffice VPN`r`nSplitVpn Proto 2`r`nCommand completed successfully.`r`n"
        'names-ru' = "Подключено к`r`nРаздельный VPN 1a2b3c4d`r`nOffice VPN`r`nSplitVpn Proto 2`r`nКоманда успешно завершена.`r`n"
        'none-en' = "No connections`r`nCommand completed successfully.`r`n"
        'none-ru' = "Нет соединений`r`nКоманда успешно завершена.`r`n"
    }
    $written = 0
    foreach ($page in @(65001, [int]$nls.OEMCP, [int]$nls.ACP) | Select-Object -Unique) {
        $encoding = [Text.Encoding]::GetEncoding($page)
        foreach ($key in $samples.Keys) {
            $bytes = $encoding.GetBytes($samples[$key])
            if ($encoding.GetString($bytes) -ne $samples[$key]) { continue }
            [IO.File]::WriteAllBytes((Join-Path $fixtureDir "$key-$page.txt"), $bytes)
            $written++
        }
    }
    if ($written -lt 4) { throw 'Не подготовлены образцы вывода rasdial' }

    . ([scriptblock]::Create($recoveryFunctions))
    . ([scriptblock]::Create($harness))

    # Команда задачи разбирается по правилам командной строки Windows (CommandLineToArgvW): /tr получает
    # «"<rasdial.exe>" "<имя с пробелом>" /disconnect» с кавычками и кириллицей без искажений.
    Add-Type -Namespace SplitVpnTest -Name Argv -MemberDefinition @'
[DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
private static extern IntPtr CommandLineToArgvW(string cmdLine, out int count);
[DllImport("kernel32.dll")]
private static extern IntPtr LocalFree(IntPtr mem);
public static string[] Split(string cmdLine) {
    int count;
    IntPtr argv = CommandLineToArgvW(cmdLine, out count);
    try {
        var result = new string[count];
        for (int i = 0; i < count; i++) result[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size));
        return result;
    } finally { LocalFree(argv); }
}
'@
    $argv = [SplitVpnTest.Argv]::Split('schtasks.exe ' + $lastCreate)
    $tr = $argv[[array]::IndexOf($argv, '/tr') + 1]
    if ($tr -cne ('"{0}\System32\rasdial.exe" "Раздельный VPN 1a2b3c4d" /disconnect' -f $env:SystemRoot)) { throw "Команда задачи разобрана неверно: $tr" }
    if ($tr.Length -gt 261) { throw 'Команда задачи длиннее 261 символа' }

    # Те же проверки в режиме ограниченного языка, в отдельном процессе.
    $clmScript = Join-Path $temp.FullName 'clm.ps1'
    $body = "`$ErrorActionPreference = 'Stop'`r`n`$fixtureDir = '$($fixtureDir -replace "'", "''")'`r`n" + $recoveryFunctions + "`r`n" + $harness +
        "`r`nif (-not `$clm) { throw 'Режим ограниченного языка не включён' }`r`n'CLM-OK'`r`n"
    [IO.File]::WriteAllText($clmScript, $body, (New-Object Text.UTF8Encoding($true)))
    $wrapper = Join-Path $temp.FullName 'clm-wrapper.ps1'
    [IO.File]::WriteAllText($wrapper, "`$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'`r`n. '$($clmScript -replace "'", "''")'`r`n", (New-Object Text.UTF8Encoding($true)))
    $clmOutput = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $wrapper 2>&1
    if ($LASTEXITCODE -ne 0 -or ($clmOutput -join "`n") -notmatch 'CLM-OK') { throw "Проверки в режиме ограниченного языка не пройдены: $($clmOutput -join ' | ')" }
} finally {
    $temp.Delete($true)
}
Write-Output 'Проверки восстановления DNS и разрыва соединений RAS (в том числе в режиме ограниченного языка) пройдены.'
