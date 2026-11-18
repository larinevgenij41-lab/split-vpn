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
if ($checkedServices.Count -ne 2 -or $problemList.Count -ne 1) { throw 'Запрос второй службы пропущен' }

$changes = [Collections.Generic.List[string]]::new()
function Set-DnsClientServerAddress {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Family, [string[]]$ServerAddresses, [switch]$ResetServerAddresses)
    process { $changes.Add("$($Family.AddressFamily)|$ResetServerAddresses|$($ServerAddresses -join ',')") }
}
$saved = @{ NameServerV4 = '192.0.2.2,192.0.2.3'; NameServerV6 = '' }
$families = @(
    [pscustomobject]@{ AddressFamily = 2; ServerAddresses = @('127.0.0.1') }
    [pscustomobject]@{ AddressFamily = 23; ServerAddresses = @('::1') }
    [pscustomobject]@{ AddressFamily = 2; ServerAddresses = @('192.0.2.42') }
)
Restore-SavedDns $families ([pscustomobject]$saved)
if (($changes -join ';') -ne '2|False|192.0.2.2,192.0.2.3;23|True|') { throw "Неверное восстановление DNS: $changes" }

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
