<#
.SYNOPSIS
    Аварийное восстановление сети «Раздельный VPN». Запускать с повышением (recover-network.cmd делает это сам).

.DESCRIPTION
    1. Штатный путь: команда recover установленной службы или dev-утилиты (снимает RAS, маршруты, DNS, WFP).
    2. Если штатный путь недоступен: встроенные средства Windows — удалить маршруты с меткой-метрикой 3917,
       сбросить DNS интерфейсов, для которых есть резервная копия программы, разорвать соединения приложения.
    3. Фильтры WFP встроенными средствами не снимаются: перевести службу в ручной запуск и перезагрузить —
       BFE не загрузит persistent-фильтры провайдера, чья служба не в автозапуске. Прежний тип запуска и
       команда его возврата печатаются: автозапуск возвращают вручную, когда сеть снова в порядке.
#>
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Restore-SavedDns($dns, $saved) {
    foreach ($family in $dns) {
        $v6 = $family.AddressFamily -eq 23
        $loopback = if ($v6) { '::1' } else { '127.0.0.1' }
        if (@($family.ServerAddresses).Count -ne 1 -or $family.ServerAddresses[0] -ne $loopback) { continue }
        $property = if ($v6) { 'NameServerV6' } else { 'NameServerV4' }
        if (-not $saved.PSObject.Properties[$property]) { throw "Нет поля $property в копии DNS" }
        $addresses = @($saved.$property -split '[,;\s]+' | Where-Object { $_ })
        if ($addresses.Count) {
            $family | Set-DnsClientServerAddress -ServerAddresses $addresses -ErrorAction Stop
        } else {
            $family | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop
        }
    }
}

$marker = 3917
$candidates = @(
    (Join-Path $env:ProgramFiles 'SplitVpn\SplitVpn.Service.exe'),
    (Join-Path $env:ProgramFiles 'SplitVpn.Dev\service\SplitVpn.Service.exe'),
    (Join-Path $env:ProgramFiles 'SplitVpn.Dev\cli\splitvpn-cli.exe')
) | Where-Object { Test-Path $_ }

$recovered = $false
foreach ($exe in $candidates) {
    Write-Host "Штатное восстановление: $exe recover"
    & $exe recover
    if ($LASTEXITCODE -eq 0) { $recovered = $true; break }
}

if (-not $recovered) {
    Write-Host 'Штатное восстановление недоступно — встроенные средства Windows.'
    $changed = @()
    foreach ($service in 'SplitVpn', 'SplitVpnDev') {
        $info = Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction SilentlyContinue
        if (-not $info) { continue }
        Stop-Service -Name $service -Force -ErrorAction Stop
        (Get-Service $service).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        if ($info.StartMode -ne 'Auto') { continue }
        $previous = if ($info.DelayedAutoStart) { 'delayed-auto' } else { 'auto' }
        sc.exe config $service start= demand | Out-Null
        if ($LASTEXITCODE -eq 0) { $changed += [pscustomobject]@{ Name = $service; Previous = $previous } }
        else { Write-Host "Тип запуска службы $service не изменён (sc config, код $LASTEXITCODE): после перезагрузки её фильтры могут загрузиться снова." }
    }
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object RouteMetric -eq $marker |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    # DNS: только интерфейсы, для которых у программы есть резервная копия (dns-backup.json). Без копии нельзя
    # отличить наш loopback от статического 127.0.0.1 пользователя (свой резолвер), поэтому такие не трогаем.
    $dataRoot = Join-Path $env:ProgramData 'SplitVpn'
    $backupFile = Join-Path $dataRoot 'dns-backup.json'
    $owned = @{}
    if (Test-Path $backupFile) {
        try {
            $entries = Get-Content -Raw -Encoding UTF8 $backupFile | ConvertFrom-Json
            foreach ($item in $entries) {
                foreach ($prop in $item.PSObject.Properties) {
                    if ($prop.Name -ieq 'InterfaceGuid') { $owned[([string]$prop.Value).Trim('{}').ToLowerInvariant()] = $item }
                }
            }
        }
        catch { Write-Host "Резервная копия DNS не прочитана: $($_.Exception.Message)" }
    }
    if ($owned.Count -eq 0) {
        Write-Host 'Резервной копии DNS нет — DNS не сбрасываю (нельзя отличить наш loopback от вашего). Если DNS не работает, задайте его вручную.'
    }
    else {
        foreach ($adapter in Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue) {
            if (-not $owned.ContainsKey(([string]$adapter.InterfaceGuid).Trim('{}').ToLowerInvariant())) { continue }
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
            $saved = $owned[([string]$adapter.InterfaceGuid).Trim('{}').ToLowerInvariant()]
            Restore-SavedDns $dns $saved
        }
    }

    # Соединения из телефонной книги программы: записи «Раздельный VPN <id>» (по одной на профиль) и прежние имена.
    $entries = @('SplitVpn Proto', 'Раздельный VPN')
    $pbk = Join-Path $dataRoot 'splitvpn.pbk'
    if (Test-Path $pbk) {
        foreach ($line in Get-Content -Encoding UTF8 $pbk) {
            if ($line -match '^\[(.+)\]\s*$') {
                $section = $Matches[1]
                if ($section.StartsWith('Раздельный VPN') -or $section.StartsWith('SplitVpn Proto')) { $entries += $section }
            }
        }
    }
    foreach ($name in ($entries | Select-Object -Unique)) {
        if (Test-Path $pbk) { rasdial $name /disconnect "/PHONEBOOK:$pbk" 2>$null | Out-Null }
    }

    # Ручной запуск нужен до перезагрузки и после неё: BFE не загружает persistent-фильтры провайдера, чья служба
    # не в автозапуске. Вернуть автозапуск сам скрипт не может — после следующей перезагрузки фильтры загрузились
    # бы снова, а снять их сможет только работающая служба. Поэтому смена явная: печатается прежний тип запуска и
    # точная команда возврата. Службы в ручном или отключённом запуске не меняются, отложенный автозапуск
    # запоминается как есть.
    ipconfig /flushdns | Out-Null
    Write-Host 'Маршруты и DNS сброшены. Если интернет не появился — перезагрузите компьютер: фильтры SplitVpn не загрузятся.'
    foreach ($item in $changed) {
        Write-Host ''
        Write-Host ("Служба {0} переведена в ручной запуск (было: {1}): сама она больше не запустится, VPN и защита не работают." -f $item.Name, $item.Previous)
        Write-Host ("Когда сеть восстановится, верните автозапуск в командной строке администратора: sc config {0} start= {1}" -f $item.Name, $item.Previous)
    }
}

Write-Host 'Готово. Нажмите Enter, чтобы закрыть окно.'
[void][Console]::ReadLine()
