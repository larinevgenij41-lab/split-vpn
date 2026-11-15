<#
.SYNOPSIS
    Собирает MSI: самодостаточная публикация службы и приложения в одну папку, затем WiX.

.DESCRIPTION
    Результат — artifacts\installer\SplitVpn-<версия>.msi. Повышение не требуется.
    Служба и приложение публикуются self-contained (win-x64) в artifacts\publish\install: общие файлы
    среды выполнения совпадают побайтно, поэтому вторая публикация их просто перезаписывает.
#>
param([string]$Configuration = 'Release', [string]$Version)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$publish = Join-Path $root 'artifacts\publish\install'
if (Test-Path $publish) { [IO.Directory]::Delete($publish, $true) }
$env:DOTNET_NOLOGO = '1'

# Нативные библиотеки AnyConnect собираются отдельно (MSYS2): без них установщик не собирается.
$openConnectBin = Join-Path $root 'third_party\openconnect\bin'
if (-not (Test-Path (Join-Path $openConnectBin 'libopenconnect-5.dll'))) {
    throw "Нет нативных библиотек AnyConnect в $openConnectBin. Соберите их: `$env:MSYSTEM='UCRT64'; C:\msys64\usr\bin\bash.exe -l /d/VPN/scripts/build-openconnect.sh"
}

# Ожидаемые SHA-256 DLL — в отслеживаемом third_party\openconnect\manifest.json (binaries), а не в
# SHA256SUMS.txt рядом с ними: файл в неотслеживаемом bin подменяется вместе с DLL, и сверка с ним ловила
# бы только ошибку копирования. Состав тоже свой: лишняя DLL в bin ушла бы в поставку (проект помощника
# берёт *.dll) и загрузилась бы рядом с libopenconnect.
$manifestPath = Join-Path $root 'third_party\openconnect\manifest.json'
$manifest = [IO.File]::ReadAllText($manifestPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
$expected = @{}
foreach ($property in $manifest.binaries.PSObject.Properties) { $expected[$property.Name] = ([string]$property.Value).ToLowerInvariant() }
$declared = @($manifest.openconnect.dlls) + @($manifest.ocshim.dlls) + @($manifest.wintun.dlls) + @($manifest.packages | ForEach-Object { $_.dlls })
$unhashed = @($declared | Where-Object { -not $expected.ContainsKey($_) })
$undeclared = @($expected.Keys | Where-Object { $declared -notcontains $_ })
if ($unhashed.Count -or $undeclared.Count) {
    throw "В $manifestPath списки dlls и binaries расходятся: без хеша — $($unhashed -join ', '); хеш без компонента — $($undeclared -join ', ')"
}

function Assert-OpenConnectBinaries([string]$directory, [switch]$Exact) {
    if ($Exact) {
        $extra = @(Get-ChildItem $directory -Filter *.dll | Where-Object { -not $expected.ContainsKey($_.Name) } | ForEach-Object Name)
        if ($extra.Count) { throw "В $directory есть DLL, которых нет в $manifestPath`: $($extra -join ', ')" }
    }

    foreach ($name in $expected.Keys) {
        $file = Join-Path $directory $name
        if (-not (Test-Path $file)) { throw "Нет $name в $directory" }
        $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected[$name]) {
            throw "SHA-256 $file ($actual) не совпадает с $manifestPath ($($expected[$name])). Пересобрали библиотеки намеренно — проверьте их и внесите новые хеши в binaries отдельным коммитом."
        }
    }
}

Assert-OpenConnectBinaries $openConnectBin -Exact

foreach ($project in 'SplitVpn.Service', 'SplitVpn.App', 'SplitVpn.OpenConnect') {
    dotnet publish (Join-Path $root "src\$project\$project.csproj") -c $Configuration -r win-x64 --self-contained -o $publish --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "Публикация $project завершилась с кодом $LASTEXITCODE" }
}

# Отладочные символы и документация в поставку не входят.
Get-ChildItem $publish -Include *.pdb, *.xml -Recurse | ForEach-Object { [IO.File]::Delete($_.FullName) }

# Поставка AnyConnect: DLL рядом с помощником совпадают с манифестом побайтно, помощник их загружает.
Assert-OpenConnectBinaries $publish
$helperVersion = & (Join-Path $publish 'SplitVpn.OpenConnect.exe') --version
if ($LASTEXITCODE -ne 0) { throw "Помощник AnyConnect не загрузил нативные библиотеки (код $LASTEXITCODE)" }
Write-Host "Помощник AnyConnect: $helperVersion"

# Лицензия проекта и перечень сторонних компонентов идут в поставку: получатель MSI должен видеть
# условия и предложение исходников LGPL-библиотек рядом с самими библиотеками.
$licenses = Join-Path $publish 'licenses'
New-Item -ItemType Directory -Force -Path $licenses | Out-Null
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $licenses 'LICENSE.txt') -Force
Copy-Item (Join-Path $root 'docs\THIRD-PARTY-NOTICES.txt') (Join-Path $licenses 'THIRD-PARTY-NOTICES.txt') -Force

# Файл службы — отдельно: у него свой компонент с ServiceInstall, а остальное собирает элемент Files целиком.
$serviceDir = Join-Path $root 'artifacts\publish\install-service'
New-Item -ItemType Directory -Force -Path $serviceDir | Out-Null
Move-Item (Join-Path $publish 'SplitVpn.Service.exe') (Join-Path $serviceDir 'SplitVpn.Service.exe') -Force

$version = if ($Version) { $Version } else { ([xml](Get-Content (Join-Path $root 'Directory.Build.props'))).Project.PropertyGroup.Version }
dotnet build (Join-Path $root 'installer\SplitVpn.Installer.wixproj') -c $Configuration -p:Version=$version --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "Сборка установщика завершилась с кодом $LASTEXITCODE" }

$msi = Get-ChildItem (Join-Path $root 'artifacts\installer\*.msi') | Sort-Object LastWriteTime | Select-Object -Last 1
Write-Host ("Установщик: {0} ({1:N1} МБ)" -f $msi.FullName, ($msi.Length / 1MB))
