<#
.SYNOPSIS
    Аварийное восстановление сети «Раздельный VPN». Запускать с повышением (recover-network.cmd делает это сам).

.DESCRIPTION
    1. Штатный путь: команда recover установленной службы или dev-утилиты (снимает RAS, маршруты, DNS, WFP).
    2. Если штатный путь недоступен: встроенные средства Windows — удалить маршруты с меткой-метрикой 3917,
       сбросить DNS интерфейсов, для которых есть резервная копия программы, разорвать соединения приложения.
    3. Фильтры WFP встроенными средствами не снимаются: перевести службу в ручной запуск и перезагрузить —
       BFE не загрузит persistent-фильтры провайдера, чья служба не в автозапуске.
#>
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
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
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object RouteMetric -eq $marker |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    # DNS: только интерфейсы, для которых у программы есть резервная копия (dns-backup.json). Без копии нельзя
    # отличить наш loopback от статического 127.0.0.1 пользователя (свой резолвер), поэтому такие не трогаем.
    $dataRoot = Join-Path $env:ProgramData 'SplitVpn'
    $backupFile = Join-Path $dataRoot 'dns-backup.json'
    $owned = @{}
    if (Test-Path $backupFile) {
        try {
            foreach ($item in @(Get-Content -Raw -Encoding UTF8 $backupFile | ConvertFrom-Json)) {
                foreach ($prop in $item.PSObject.Properties) {
                    if ($prop.Name -ieq 'InterfaceGuid') { $owned[([string]$prop.Value).Trim('{}').ToLowerInvariant()] = $true }
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
            if ($dns | Where-Object { $_.ServerAddresses -and (($_.ServerAddresses | Where-Object { $_ -notin '127.0.0.1', '::1' }).Count -eq 0) }) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
            }
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
        rasdial $name /disconnect 2>$null | Out-Null
    }

    foreach ($service in 'SplitVpn', 'SplitVpnDev') {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            sc.exe config $service start= demand | Out-Null
        }
    }
    ipconfig /flushdns | Out-Null
    Write-Host 'Маршруты и DNS сброшены. Если интернет не появился — перезагрузите компьютер: фильтры SplitVpn не загрузятся.'
}

Write-Host 'Готово. Нажмите Enter, чтобы закрыть окно.'
[void][Console]::ReadLine()
