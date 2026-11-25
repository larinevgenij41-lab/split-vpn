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

# Разрешения на запись корня репозитория для Everyone, Authenticated Users и BUILTIN\Users — по SID
# (имена локализованы). Копия функции из publish-release.ps1, где такое дерево — ошибка выпуска.
function Get-WritableTreeGrants([string]$path) {
    $broad = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-545' = 'BUILTIN\Users' }
    $writeMask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    foreach ($rule in (Get-Acl -LiteralPath $path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne 'Allow' -or -not $broad.ContainsKey($sid)) { continue }
        if (([long]$rule.FileSystemRights -band $writeMask) -eq 0) { continue }
        "$($broad[$sid]) ($sid): $($rule.FileSystemRights)"
    }
}

# Каталоги и файлы git (hooks, config, core.hooksPath): в git worktree общий каталог git лежит вне дерева.
# Копия функции из publish-release.ps1.
function Get-GitControlPaths([string]$path) {
    $ErrorActionPreference = 'Continue'
    $found = [Collections.Generic.List[string]]::new()
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return @() }
    function Resolve-GitPath([string]$value) {
        $value = $value.Trim()
        if (-not [IO.Path]::IsPathRooted($value)) { $value = Join-Path $path $value }
        return [IO.Path]::GetFullPath($value)
    }
    foreach ($option in '--git-common-dir', '--git-dir') {
        $dir = @(& git -C $path rev-parse $option 2>$null)
        if ($LASTEXITCODE -eq 0 -and $dir.Count -and $dir[0]) {
            $full = Resolve-GitPath $dir[0]
            $found.Add($full)
            foreach ($inner in 'hooks', 'config', 'config.worktree') { $found.Add((Join-Path $full $inner)) }
        }
    }
    $hooks = @(& git -C $path config --get core.hooksPath 2>$null)
    if ($LASTEXITCODE -eq 0 -and $hooks.Count -and $hooks[0]) {
        $value = [Environment]::ExpandEnvironmentVariables($hooks[0].Trim())
        if ($value.StartsWith('~')) { $value = Join-Path $HOME $value.Substring(1).TrimStart('/', '\') }
        $found.Add((Resolve-GitPath $value))
    }
    return @($found | Where-Object { Test-Path -LiteralPath $_ } | Sort-Object -Unique)
}

$writableGrants = @(foreach ($checked in @(@($root) + @(Get-GitControlPaths $root) | Select-Object -Unique)) {
    try { Get-WritableTreeGrants $checked | ForEach-Object { "${checked}: $_" } }
    catch { Write-Warning "Не удалось проверить разрешения ${checked}: $($_.Exception.Message)" }
})
if ($writableGrants.Count) {
    Write-Warning "Корень репозитория $root или его каталог git доступны на запись обычным пользователям — собранный MSI может содержать подменённый ими код (в git worktree каталог git лежит в основной копии):`n  $($writableGrants -join "`n  ")`nКак закрыть доступ — см. scripts\publish-release.ps1 (проверка ACL) или docs\RELEASE.md."
}

$publish =Join-Path $root 'artifacts\publish\install'
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

# Движок «VPN поверх SSH»: официальная сборка sing-box, побайтно совпадающая с манифестом. Кладётся рядом со службой.
$singBox = & (Join-Path $PSScriptRoot 'copy-sing-box.ps1') -Destination $publish
$singBoxVersion = & (Join-Path $publish $singBox.executable.name) version
if ($LASTEXITCODE -ne 0 -or -not (($singBoxVersion -join ' ') -match [regex]::Escape($singBox.version))) {
    throw "Движок «VPN поверх SSH» не запускается или его версия не $($singBox.version): $($singBoxVersion | Select-Object -First 1)"
}

Write-Host "Движок «VPN поверх SSH»: $($singBoxVersion | Select-Object -First 1)"

# Лицензия проекта и перечень сторонних компонентов идут в поставку: получатель MSI должен видеть
# условия и предложение исходников LGPL-библиотек рядом с самими библиотеками.
$licenses = Join-Path $publish 'licenses'
New-Item -ItemType Directory -Force -Path $licenses | Out-Null
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $licenses 'LICENSE.txt') -Force
Copy-Item (Join-Path $root 'docs\THIRD-PARTY-NOTICES.txt') (Join-Path $licenses 'THIRD-PARTY-NOTICES.txt') -Force

# Условия sing-box (GPL-3.0) - рядом с самой программой: текст лицензии из архива выпуска и адрес исходников.
$singBoxLicenses = Join-Path $licenses 'sing-box'
New-Item -ItemType Directory -Force -Path $singBoxLicenses | Out-Null
$singBoxLicense = Join-Path $root 'third_party\sing-box\bin\LICENSE.txt'
if (-not (Test-Path $singBoxLicense)) { throw "Нет ${singBoxLicense}: запустите scripts\fetch-sing-box.ps1" }
Copy-Item $singBoxLicense (Join-Path $singBoxLicenses 'LICENSE.txt') -Force
Copy-Item (Join-Path $root 'third_party\sing-box\README.txt') (Join-Path $singBoxLicenses 'README.txt') -Force

# Файл службы — отдельно: у него свой компонент с ServiceInstall, а остальное собирает элемент Files целиком.
$serviceDir = Join-Path $root 'artifacts\publish\install-service'
New-Item -ItemType Directory -Force -Path $serviceDir | Out-Null
Move-Item (Join-Path $publish 'SplitVpn.Service.exe') (Join-Path $serviceDir 'SplitVpn.Service.exe') -Force

$version = if ($Version) { $Version } else { ([xml](Get-Content (Join-Path $root 'Directory.Build.props'))).Project.PropertyGroup.Version }
dotnet build (Join-Path $root 'installer\SplitVpn.Installer.wixproj') -c $Configuration -p:Version=$version --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "Сборка установщика завершилась с кодом $LASTEXITCODE" }

$msi = Get-ChildItem (Join-Path $root 'artifacts\installer\*.msi') | Sort-Object LastWriteTime | Select-Object -Last 1
Write-Host ("Установщик: {0} ({1:N1} МБ)" -f $msi.FullName, ($msi.Length / 1MB))
