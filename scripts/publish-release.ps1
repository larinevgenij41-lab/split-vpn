<#
.SYNOPSIS
    Выпуск версии: сборка, манифест обновлений с подписью, чистый снимок исходников и релиз на GitHub.

.DESCRIPTION
    Кодифицирует ручной порядок выпуска, чтобы он не терялся вместе с настройками рабочей копии.
    Шаги: проверки → сборка и испытания → установщик → манифест update.json и подпись к нему →
    снимок дерева в ветку publish (один коммит без истории) → gh release create → проверка выложенного.

    Манифест кладётся и в активы релиза, и внутрь снимка (release\update.json): из дерева репозитория
    его раздают jsDelivr и raw.githubusercontent — запасные пути, когда github.com недоступен.
    Рабочее дерево при этом не меняется: файл попадает только во временный индекс снимка.

    Пароль ключа подписи: переменная SPLITVPN_SIGNING_KEY_PASSWORD или ввод в консоли.

.EXAMPLE
    scripts\publish-release.ps1 -NotesFile docs\notes-0.8.0.md
#>
param(
    [string]$Version,
    [Parameter(Mandatory = $true)][string]$NotesFile,
    [string]$KeyPath = (Join-Path $env:USERPROFILE '.splitvpn\release-signing.pem'),
    [string]$PasswordFile = (Join-Path $env:USERPROFILE '.splitvpn\release-signing.password.txt'),
    [string]$KeyId = 'sv-2026-09-2',
    [string]$MinUpgradableVersion,
    [switch]$SkipBuild,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$repository = 'larinevgenij41-lab/split-vpn'
$gh = 'C:\Program Files\GitHub CLI\gh.exe'
if (-not (Test-Path $gh)) { $gh = 'gh' }

function Step($text) { Write-Host "== $text" -ForegroundColor Cyan }
function Run($file, $arguments) {
    # Родные программы пишут ход работы в stderr — git делает это всегда. При $ErrorActionPreference
    # 'Stop' и перенаправленном выводе PowerShell принимает эти строки за ошибку и прерывает выпуск
    # после успешного шага. Судить можно только по коду завершения.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $file @arguments }
    finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "$file $($arguments -join ' ') — код $LASTEXITCODE" }
}

# ProductVersion из таблицы Property установщика. Обращение позднее связывание: у Execute параметр
# необязательный, у Fetch параметров нет, StringData — свойство с индексом. Каждый шаг назван, иначе
# COM сообщает только «Type mismatch» без указания, что именно не сошлось.
function MsiProductVersion([string]$path) {
    $step = 'создание объекта WindowsInstaller'
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $type = $installer.GetType()
        $step = 'открытие базы установщика'
        $database = $type.InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @([string]$path, [int]0))
        $step = 'запрос к таблице Property'
        $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database,
            @([string]"SELECT Value FROM Property WHERE Property='ProductVersion'"))
        $step = 'выполнение запроса'
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, @($null)) | Out-Null
        $step = 'чтение строки'
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, @())
        if (-not $record) { throw 'в таблице Property нет ProductVersion' }
        $step = 'чтение значения'
        return [string]$record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @([int]1))
    }
    catch {
        throw "Не удалось прочитать версию из $path ($step): $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------- проверки
Step 'проверки'
$declared = ([xml](Get-Content (Join-Path $root 'Directory.Build.props'))).Project.PropertyGroup.Version
if (-not $Version) { $Version = $declared }
if ($Version -ne $declared) { throw "Версия $Version не совпадает с Directory.Build.props ($declared)" }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Версия должна быть вида «0.8.0», а не «$Version»" }
if (-not (Test-Path $NotesFile)) { throw "Нет файла заметок: $NotesFile" }
if (-not (Test-Path $KeyPath)) { throw "Нет ключа выпуска: $KeyPath. Создайте его командой splitvpn-cli release-keygen." }

# Отслеживаемые правки блокируют выпуск: снимок берётся из HEAD, и выложенное не совпало бы с собранным.
# Неотслеживаемые файлы в снимок не попадают, но о них стоит знать: случайный .cs всё же попадёт в сборку.
$status = git -C $root status --porcelain --untracked-files=no
if ($status) { throw "Рабочее дерево не чистое: выпуск идёт только из зафиксированного состояния.`n$status" }
$untracked = git -C $root status --porcelain --untracked-files=all | Where-Object { $_.StartsWith('??') }
if ($untracked) { Write-Warning "В дереве есть неотслеживаемые файлы (в снимок не войдут):`n$($untracked -join "`n")" }

$tag = "v$Version"
if (git -C $root tag --list $tag) { throw "Тег $tag уже существует локально" }
Run $gh @('auth', 'status')

# ---------------------------------------------------------------- сборка
if (-not $SkipBuild) {
    Step 'сборка и испытания'
    $env:DOTNET_NOLOGO = '1'
    $env:NuGetAudit = 'false'
    Run 'dotnet' @('build', (Join-Path $root 'SplitVpn.slnx'), '-c', 'Release', '--nologo', '-v', 'q')
    foreach ($project in 'SplitVpn.Core.Tests', 'SplitVpn.Service.Tests') {
        $exe = Get-ChildItem (Join-Path $root "tests\$project\bin\Release") -Recurse -Filter "$project.exe" | Select-Object -First 1
        if (-not $exe) { throw "Не найден тестовый исполняемый файл $project" }
        Run $exe.FullName @()
    }

    Step 'установщик'
    & (Join-Path $root 'scripts\build-installer.ps1') -Version $Version
    if ($LASTEXITCODE -ne 0) { throw "Сборка установщика завершилась с кодом $LASTEXITCODE" }
}

$msi = Join-Path $root "artifacts\installer\SplitVpn-$Version.msi"
if (-not (Test-Path $msi)) { throw "Нет установщика $msi" }

# Версия внутри пакета: ловит случай «выложили MSI от прошлой сборки».
$productVersion = MsiProductVersion $msi
if ($productVersion -ne $Version) { throw "ProductVersion установщика — $productVersion, а выпускается $Version" }

# ---------------------------------------------------------------- манифест
Step 'манифест и подпись'
$releaseDir = Join-Path $root 'artifacts\release'
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
$manifestPath = Join-Path $releaseDir 'update.json'
$signaturePath = "$manifestPath.sig"

$hash = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant()
$size = (Get-Item $msi).Length
# Читать строго как UTF-8: Get-Content в Windows PowerShell берёт файл без BOM за ANSI,
# и кириллица заметок превратилась бы в «кракозябру» и в манифесте, и на странице выпуска.
$notes = [IO.File]::ReadAllText($NotesFile, [Text.Encoding]::UTF8).Trim()

# В манифест идёт только первый абзац: его показывает карточка «О программе», где весь текст
# заметок не нужен и не помещается. Полные заметки уходят на страницу выпуска.
$summary = ($notes -split "(`r?`n){2,}")[0].Trim()
if ($summary.Length -gt 600) { $summary = $summary.Substring(0, 597).TrimEnd() + '…' }
$minimum = ''
if ($MinUpgradableVersion) { $minimum = "`n  ""minUpgradableVersion"": ""$MinUpgradableVersion""," }

# Манифест собирается строкой, а не ConvertTo-Json: подпись считается по точным байтам, поэтому
# порядок полей, отступы и перевод строки должны быть предсказуемы. Файл — UTF-8 без BOM с LF.
$json = @"
{
  "schema": 1,
  "product": "SplitVpn",
  "version": "$Version",
  "tag": "$tag",
  "releasedUtc": "$([DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",$minimum
  "package": {
    "fileName": "SplitVpn-$Version.msi",
    "size": $size,
    "sha256": "$hash",
    "urls": [
      "https://github.com/$repository/releases/download/$tag/SplitVpn-$Version.msi",
      "https://github.com/$repository/releases/latest/download/SplitVpn-$Version.msi"
    ]
  },
  "notes": $($summary | ConvertTo-Json),
  "notesUrl": "https://github.com/$repository/releases/tag/$tag",
  "kid": "$KeyId"
}
"@
[IO.File]::WriteAllBytes($manifestPath, [Text.UTF8Encoding]::new($false).GetBytes(($json -replace "`r`n", "`n")))

$cli = Get-ChildItem (Join-Path $root 'src\SplitVpn.Cli\bin\Release') -Recurse -Filter 'splitvpn-cli.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $cli) { throw 'Не найден splitvpn-cli.exe: соберите решение в конфигурации Release.' }
$signArguments = @('release-sign', '--manifest', $manifestPath, '--key', $KeyPath)
if (Test-Path $PasswordFile) { $signArguments += @('--password-file', $PasswordFile) }
Run $cli.FullName $signArguments
# Самопроверка тем же кодом, что и в службе: с неработающей подписью релиз не выкладывается.
Run $cli.FullName @('release-verify', '--manifest', $manifestPath, '--signature', $signaturePath, '--package', $msi)

# ---------------------------------------------------------------- заметки
$notesForRelease = Join-Path $releaseDir "notes-$Version.md"
$releaseText = @"
$notes

---

SHA-256 установщика ``SplitVpn-$Version.msi``:

``````
$hash
``````

Проверить: ``Get-FileHash SplitVpn-$Version.msi -Algorithm SHA256``

Установщик не подписан Authenticode — Windows покажет «Неизвестный издатель». Сверьте контрольную сумму.
Установка поверх: закройте «Раздельный VPN», затем ``msiexec /i SplitVpn-$Version.msi``.
Начиная с 0.8.0 программа проверяет обновления сама: «О программе» → «Обновление».
"@
# Без BOM: gh показал бы его первым символом заметок.
[IO.File]::WriteAllText($notesForRelease, $releaseText, [Text.UTF8Encoding]::new($false))

# ---------------------------------------------------------------- снимок
Step 'снимок исходников в ветку publish'
# Манифест добавляется только во временный индекс: рабочее дерево и история main не меняются.
$env:GIT_INDEX_FILE = Join-Path $env:TEMP "splitvpn-publish-$Version.index"
try {
    Run 'git' @('-C', $root, 'read-tree', 'HEAD')
    # --no-filters обязателен: подпись считается по точным байтам манифеста, а git привёл бы
    # переводы строк к CRLF (core.autocrlf) и подпись перестала бы сходиться у тех, кто берёт
    # манифест с зеркал raw.githubusercontent и jsDelivr.
    $manifestBlob = (git -C $root hash-object -w --no-filters $manifestPath).Trim()
    $signatureBlob = (git -C $root hash-object -w --no-filters $signaturePath).Trim()
    Run 'git' @('-C', $root, 'update-index', '--add', '--cacheinfo', "100644,$manifestBlob,release/update.json")
    Run 'git' @('-C', $root, 'update-index', '--add', '--cacheinfo', "100644,$signatureBlob,release/update.json.sig")
    $tree = (git -C $root write-tree).Trim()
}
finally {
    Remove-Item $env:GIT_INDEX_FILE -ErrorAction SilentlyContinue
    Remove-Item Env:\GIT_INDEX_FILE -ErrorAction SilentlyContinue
}

# Авторство берётся из локальной настройки репозитория: в глобальной — корпоративная почта.
$env:GIT_AUTHOR_NAME = git -C $root config user.name
$env:GIT_AUTHOR_EMAIL = git -C $root config user.email
$env:GIT_COMMITTER_NAME = $env:GIT_AUTHOR_NAME
$env:GIT_COMMITTER_EMAIL = $env:GIT_AUTHOR_EMAIL
if (-not $env:GIT_AUTHOR_EMAIL) { throw 'В репозитории не задано user.email: снимок ушёл бы с чужим авторством.' }

$message = @"
Раздельный VPN $Version

Разделение трафика для Windows: российские адреса напрямую, остальные через VPN.
Служба, интерфейс WPF, SSTP/L2TP/IKEv2/PPTP и Cisco AnyConnect, kill switch на WFP,
DNS-посредник, автообновляемые списки адресов, обновление программы через GitHub Releases.
"@
$commit = (git -C $root commit-tree $tree -m $message).Trim()
Run 'git' @('-C', $root, 'branch', '-f', 'publish', $commit)
Write-Host "Снимок: $commit"

if ($DryRun) {
    Write-Host "Пробный прогон: снимок не отправлен, релиз не создан. Манифест: $manifestPath" -ForegroundColor Yellow
    return
}

Run 'git' @('-C', $root, 'push', '--force-with-lease', 'origin', 'publish:refs/heads/main')

# ---------------------------------------------------------------- релиз
Step 'релиз на GitHub'
Run $gh @('release', 'create', $tag, $msi, $manifestPath, $signaturePath,
    '--repo', $repository, '--title', "Раздельный VPN $Version", '--notes-file', $notesForRelease, '--target', 'main')

# ---------------------------------------------------------------- проверка выложенного
Step 'проверка выложенного'
$checkDir = Join-Path $releaseDir 'published'
New-Item -ItemType Directory -Force -Path $checkDir | Out-Null
$published = Join-Path $checkDir 'update.json'
Invoke-WebRequest "https://github.com/$repository/releases/latest/download/update.json" -OutFile $published -UseBasicParsing
Invoke-WebRequest "https://github.com/$repository/releases/latest/download/update.json.sig" -OutFile "$published.sig" -UseBasicParsing
Run $cli.FullName @('release-verify', '--manifest', $published, '--signature', "$published.sig")
if (((Get-Content $published -Raw) | ConvertFrom-Json).version -ne $Version) { throw 'Выложенный манифест указывает на другую версию' }

$head = Invoke-WebRequest "https://github.com/$repository/releases/download/$tag/SplitVpn-$Version.msi" -Method Head -UseBasicParsing
if ([long]$head.Headers['Content-Length'] -ne $size) { throw 'Размер выложенного установщика не совпал с манифестом' }

Write-Host "Готово: https://github.com/$repository/releases/tag/$tag" -ForegroundColor Green
