<#
.SYNOPSIS
    КТ6: удаление установленной программы в разных состояниях и проверка возврата к исходному снимку. Запускать с повышением.

.DESCRIPTION
    Для каждого состояния: привести систему к нему → msiexec /x → снимок (служба, WFP, маршруты, DNS, RAS, файлы,
    ярлыки, запись в «Программах», интернет напрямую) → переустановка MSI → профиль из учётных данных прототипа →
    подключение. Итог — logs\kt6-results-<время>.json. При любой неудаче в конце снимается защита.
#>
param(
    [string]$Msi = 'D:\VPN\artifacts\installer\SplitVpn-0.1.2.msi',
    [string[]]$States = @('connected', 'protected', 'disabled')
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = Split-Path -Parent $PSScriptRoot
$cli = Join-Path $env:ProgramFiles 'SplitVpn.Dev\cli\splitvpn-cli.exe'
$wifi = 'Беспроводная сеть'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$results = New-Object System.Collections.Generic.List[object]

function Log([string]$text) { Write-Host "$(Get-Date -Format 'HH:mm:ss') $text" }
function Status { try { (& $cli status --json | Out-String) | ConvertFrom-Json } catch { $null } }
function WaitState([string[]]$states, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do { $s = Status; if ($s -and $s.state -in $states) { return $s }; Start-Sleep -Seconds 2 } while ((Get-Date) -lt $deadline)
    return (Status)
}
function Probe([string]$ip) {
    $c = New-Object Net.Sockets.TcpClient
    try { if ($c.ConnectAsync($ip, 443).Wait(5000) -and $c.Connected) { $c.Client.LocalEndPoint.Address.ToString() } else { 'нет' } } catch { 'нет' } finally { $c.Dispose() }
}
function ProductCode {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -like 'Раздельный VPN*' | Select-Object -First 1).PSChildName
}
function Snapshot {
    $wfp = -1
    try { $wfp = ((& $cli wfp-groups | Out-String) | ConvertFrom-Json).total } catch { $wfp = -1 }
    $rasText = (rasdial 2>&1 | Out-String)
    $shortcuts = @(Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Раздельный VPN" -ErrorAction SilentlyContinue).Count + @(Get-ChildItem 'C:\Users\Public\Desktop' -Filter '*Раздельный*' -ErrorAction SilentlyContinue).Count
    [ordered]@{
        Service = [string](Get-Service SplitVpn -ErrorAction SilentlyContinue).Status
        Wfp = $wfp
        MarkedRoutes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object RouteMetric -eq 3917).Count
        WifiDns = ((Get-DnsClientServerAddress -InterfaceAlias $wifi -AddressFamily IPv4).ServerAddresses -join ',')
        Ras = -not ($rasText -match 'No connections|Нет подключений')
        ProgramFiles = Test-Path (Join-Path $env:ProgramFiles 'SplitVpn\SplitVpn.Service.exe')
        ProgramData = Test-Path (Join-Path $env:ProgramData 'SplitVpn')
        Shortcuts = $shortcuts
        Arp = [bool](ProductCode)
        ForeignLocal = Probe '1.1.1.1'
    }
}
function Install {
    Get-Process -Name 'SplitVpn' -ErrorAction SilentlyContinue | Stop-Process -Force
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /qn /norestart /l*v `"$root\logs\msi-reinstall-$stamp.log`"" -Wait -PassThru
    Log "установка: код $($p.ExitCode)"
    Start-Sleep -Seconds 5
    & $cli profile set --name 'Основной' --from-dev-creds | Out-Null
    & $cli connect | Out-Null
    $s = WaitState @('Connected') 90
    Log "после установки: $($s.state)"
    return $p.ExitCode
}

foreach ($state in $States) {
    Log "=== удаление в состоянии: $state"
    $r = [ordered]@{ State = $state; Passed = $true; Checks = [ordered]@{}; Before = $null; After = $null; Error = $null }
    try {
        $s = WaitState @('Connected') 90
        if ($s.state -ne 'Connected') { & $cli connect | Out-Null; $s = WaitState @('Connected') 90 }
        switch ($state) {
            'protected' { & $cli disconnect --keep-protection | Out-Null; Start-Sleep -Seconds 3 }
            'disabled' { Stop-Service SplitVpn -Force; sc.exe config SplitVpn start= disabled | Out-Null; Start-Sleep -Seconds 2 }
        }
        $r.Before = Snapshot
        $code = ProductCode
        if (-not $code) { throw 'Продукт не найден в реестре' }
        Get-Process -Name 'SplitVpn' -ErrorAction SilentlyContinue | Stop-Process -Force
        $p = Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart /l*v `"$root\logs\msi-uninstall-$state-$stamp.log`"" -Wait -PassThru
        $r.Checks['msiexec /x код 0'] = ($p.ExitCode -eq 0)
        Start-Sleep -Seconds 3
        $r.After = Snapshot
        $a = $r.After
        $r.Checks['службы нет'] = ($a.Service -eq '')
        $r.Checks['фильтров WFP нет'] = ($a.Wfp -eq 0)
        $r.Checks['маршрутов с меткой нет'] = ($a.MarkedRoutes -eq 0)
        $r.Checks['DNS Wi-Fi от DHCP'] = ($a.WifiDns -ne '127.0.0.1' -and $a.WifiDns -ne '')
        $r.Checks['соединения RAS нет'] = (-not $a.Ras)
        $r.Checks['файлы программы удалены'] = (-not $a.ProgramFiles)
        $r.Checks['данные службы удалены'] = (-not $a.ProgramData)
        $r.Checks['ярлыки удалены'] = ($a.Shortcuts -eq 0)
        $r.Checks['записи в «Программах» нет'] = (-not $a.Arp)
        $r.Checks['интернет напрямую'] = ($a.ForeignLocal -like '192.168.1.*')
        $r.Passed = -not ($r.Checks.Values -contains $false)
    } catch {
        $r.Passed = $false; $r.Error = "$_"; Log "ОШИБКА: $_"
    } finally {
        $r.ReinstallCode = Install
        $r.AfterReinstall = (Status).state
        $results.Add([pscustomobject]$r)
        Log ("--- $state : " + $(if ($r.Passed) { 'ПРОЙДЕН' } else { 'НЕ ПРОЙДЕН' }))
    }
}

$results | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $root "logs\kt6-results-$stamp.json") -Encoding UTF8
$passed = @($results | Where-Object Passed).Count
Log "Итог: пройдено $passed из $($results.Count)"
if ((Status).state -ne 'Connected') { Log 'не подключено — снимаю защиту'; & $cli disconnect | Out-Null }
$global:LASTEXITCODE = if ($passed -eq $results.Count) { 0 } else { 1 }
