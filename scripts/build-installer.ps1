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

foreach ($project in 'SplitVpn.Service', 'SplitVpn.App', 'SplitVpn.OpenConnect') {
    dotnet publish (Join-Path $root "src\$project\$project.csproj") -c $Configuration -r win-x64 --self-contained -o $publish --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "Публикация $project завершилась с кодом $LASTEXITCODE" }
}

# Отладочные символы и документация в поставку не входят.
Get-ChildItem $publish -Include *.pdb, *.xml -Recurse | ForEach-Object { [IO.File]::Delete($_.FullName) }

# Поставка AnyConnect: DLL рядом с помощником совпадают с собранными побайтно, помощник их загружает.
$sums = Get-Content (Join-Path $openConnectBin 'SHA256SUMS.txt') | ForEach-Object { $hash, $name = $_ -split '\s+\*?', 2; [pscustomobject]@{ Hash = $hash; Name = $name } }
foreach ($entry in $sums) {
    $actual = (Get-FileHash (Join-Path $publish $entry.Name) -Algorithm SHA256).Hash
    if ($actual -ne $entry.Hash) { throw "Хеш $($entry.Name) в публикации не совпадает с third_party\openconnect\bin" }
}
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
