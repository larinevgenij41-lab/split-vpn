# Извлечь функции без запуска административных сценариев, которые их содержат.
$ErrorActionPreference = 'Stop'
function Read-Function([string]$scriptName, [string]$name) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $scriptName), [ref]$tokens, [ref]$errors)
    if ($errors) { throw "$scriptName содержит синтаксическую ошибку" }
    $fn = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    return [scriptblock]::Create($fn.Extent.Text)
}

. (Read-Function 'recover-network.ps1' 'Restore-SavedDns')
. (Read-Function 'wizard-e2e.ps1' 'Backup-ServiceData')

. (Read-Function 'recover-network.ps1' 'Stop-RecoveryServices')
. (Read-Function 'install-dev-service.ps1' 'Test-DevServiceImage')
$expectedExe = 'C:\Program Files\SplitVpn.Dev\service\SplitVpn.Service.exe'
if (-not (Test-DevServiceImage ('"' + $expectedExe + '" --service') $expectedExe)) { throw 'Не распознана служба разработки' }
if (Test-DevServiceImage 'C:\Program Files\SplitVpn\SplitVpn.Service.exe' $expectedExe) { throw 'Служба MSI принята за dev-службу' }
$checkedServices = [Collections.Generic.List[string]]::new()
function Get-CimInstance($ClassName, $Filter, $ErrorAction) {
    $checkedServices.Add($Filter)
    if ($Filter -match "='SplitVpn'") { throw 'сбой SCM' }
    return $null
}
$problemList = [Collections.Generic.List[string]]::new()
if (Stop-RecoveryServices ([Collections.Generic.List[object]]::new()) $problemList) { throw 'Неизвестное состояние службы принято за остановку' }
# Сбой запроса SplitVpn даёт две записи: остановка не подтверждена и повторный запрос для принудительного завершения
# тоже не удался. Вторая служба при этом всё равно должна быть опрошена.
if (-not ($checkedServices | Where-Object { $_ -match "='SplitVpnDev'" })) { throw 'Запрос второй службы пропущен' }
if ($checkedServices.Count -ne 3 -or $problemList.Count -ne 2) { throw 'Сбой запроса службы учтён неверно' }

$changes = [Collections.Generic.List[string]]::new()
function Set-DnsClientServerAddress {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Family, [string[]]$ServerAddresses, [switch]$ResetServerAddresses)
    process { $changes.Add("$($Family.AddressFamily)|$ResetServerAddresses|$($ServerAddresses -join ',')") }
}
# Сброс семейства на «автоматически» идёт через netsh по полному пути, состояние DHCP - через Get-NetIPInterface:
# оба подменены, настоящий адаптер не трогается.
$dhcp = 'Enabled'
function Get-NetIPInterface($InterfaceIndex, $AddressFamily, $ErrorAction) { [pscustomobject]@{ Dhcp = $dhcp } }
New-Item -Path "function:$env:SystemRoot\System32\netsh.exe" -Value {
    $changes.Add("netsh|$($args -join ' ')")
    $global:LASTEXITCODE = 0
} | Out-Null
$adapter = [pscustomobject]@{ ifIndex = 7; Name = 'Тестовый' }
$resolvers = @{ V4 = $false; V6 = $false }
$dnsProblems = [Collections.Generic.List[string]]::new()
$saved = @{ NameServerV4 = '192.0.2.2,192.0.2.3'; NameServerV6 = '' }
$families = @(
    [pscustomobject]@{ AddressFamily = 2; ServerAddresses = @('127.0.0.1') }
    [pscustomobject]@{ AddressFamily = 23; ServerAddresses = @('::1') }
    [pscustomobject]@{ AddressFamily = 2; ServerAddresses = @('192.0.2.42') }
    # С 0.17.9 набор посредника на основном адаптере - «адрес адаптера, 127.0.0.1»; обратный порядок - не наш.
    [pscustomobject]@{ AddressFamily = 2; ServerAddresses = @('192.168.1.100', '127.0.0.1') }
    [pscustomobject]@{ AddressFamily = 2; ServerAddresses = @('127.0.0.1', '192.168.1.100') }
)
Restore-SavedDns $adapter $families ([pscustomobject]$saved) $resolvers $dnsProblems
if (($changes -join ';') -ne '2|False|192.0.2.2,192.0.2.3;netsh|interface ipv6 set dnsservers name=7 source=dhcp;2|False|192.0.2.2,192.0.2.3') { throw "Неверное восстановление DNS: $changes" }
if ($dnsProblems.Count) { throw "Лишние проблемы при восстановлении DNS: $dnsProblems" }

# Без копии у адаптера со статическим IPv4 DNS не сбрасывается: «автоматически» оставило бы его без DNS.
$changes.Clear()
$dhcp = 'Disabled'
Restore-SavedDns $adapter @([pscustomobject]@{ AddressFamily = 2; ServerAddresses = @('127.0.0.1') }) $null $resolvers $dnsProblems
if ($changes.Count -or $dnsProblems.Count -ne 1) { throw "Статический адаптер сброшен: $changes" }

$temp = [IO.Directory]::CreateDirectory((Join-Path ([IO.Path]::GetTempPath()) ('splitvpn-backup-test-' + [guid]::NewGuid())))
try {
    $source = New-Item -ItemType Directory -Path (Join-Path $temp.FullName 'source')
    foreach ($name in 'settings.json', 'secrets.bin', 'secrets.bin.sshkey', 'secrets.bin.ipsec.bak') {
        [IO.File]::WriteAllText((Join-Path $source.FullName $name), 'test')
    }

    $destination = Join-Path $temp.FullName 'backup'
    Backup-ServiceData $source.FullName $destination
    if ((@(Get-ChildItem -LiteralPath $destination).Name -join ',') -ne 'settings.json') { throw 'Неверный состав резервной копии' }

    function robocopy { $global:LASTEXITCODE = 8 }
    $failed = $false
    try { Backup-ServiceData $source.FullName (Join-Path $temp.FullName 'failed') } catch { $failed = $true }
    if (-not $failed) { throw 'Ошибка robocopy должна остановить сброс' }
} finally {
    $temp.Delete($true)
}
Write-Output 'Проверки резервного копирования и восстановления DNS пройдены.'
