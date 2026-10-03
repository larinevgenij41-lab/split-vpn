<#
.SYNOPSIS
    Аварийное восстановление сети «Раздельный VPN». Запускать с повышением (recover-network.cmd делает это сам).

.DESCRIPTION
    1. Штатный путь: команда recover установленной службы или dev-утилиты (снимает RAS, маршруты, DNS, WFP).
    2. Если штатный путь недоступен: встроенные средства Windows — удалить маршруты с меткой-метрикой 3917,
       сбросить DNS интерфейсов, где стоит loopback, разорвать соединения приложения.
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
    Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses -and (($_.ServerAddresses | Where-Object { $_ -notin '127.0.0.1', '::1' }).Count -eq 0) } |
        ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue }
    foreach ($name in 'SplitVpn Proto', 'Раздельный VPN') { rasdial $name /disconnect 2>$null | Out-Null }
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
