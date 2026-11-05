<#
.SYNOPSIS
    Однократный перевод пароля ключа подписи выпусков из открытого файла в DPAPI текущего пользователя.

.DESCRIPTION
    Читает пароль из текстового файла (по умолчанию %USERPROFILE%\.splitvpn\release-signing.password.txt;
    нет файла — спрашивает в консоли) и пишет release-signing.password.dpapi рядом: формат
    ConvertFrom-SecureString без ключа, то есть DPAPI с областью текущего пользователя — расшифровать его
    может только эта учётная запись на этом компьютере. Его по умолчанию читает scripts\publish-release.ps1.

    Записанный файл сразу проверяется расшифровкой. Открытый файл удаляется только с -RemovePlainText.
    Существующий .dpapi без -Force не перезаписывается.

.EXAMPLE
    scripts\protect-signing-password.ps1 -RemovePlainText
#>
param(
    [string]$PlainTextFile = (Join-Path $env:USERPROFILE '.splitvpn\release-signing.password.txt'),
    [string]$OutFile = (Join-Path $env:USERPROFILE '.splitvpn\release-signing.password.dpapi'),
    [switch]$RemovePlainText,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function PlainText([Security.SecureString]$secure) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if ((Test-Path $OutFile) -and -not $Force) { throw "Файл $OutFile уже есть. Перезаписать: -Force." }

if (Test-Path $PlainTextFile) {
    # Так же, как splitvpn-cli release-sign читал --password-file: UTF-8, без пробелов по краям.
    $secure = ConvertTo-SecureString ([IO.File]::ReadAllText($PlainTextFile, [Text.Encoding]::UTF8).Trim()) -AsPlainText -Force
}
else {
    Write-Host "Файла $PlainTextFile нет: пароль вводится в консоли."
    $secure = Read-Host -AsSecureString 'Пароль ключа выпуска'
}

if ((PlainText $secure).Length -eq 0) { throw 'Пустой пароль не сохраняется.' }

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) | Out-Null
[IO.File]::WriteAllText($OutFile, ($secure | ConvertFrom-SecureString), [Text.Encoding]::ASCII)

# Проверка: файл расшифровывается в тот же пароль.
$check = PlainText ((Get-Content -Raw $OutFile).Trim() | ConvertTo-SecureString)
if ($check -ne (PlainText $secure)) { throw "Проверка $OutFile не прошла: файл не записан как нужно." }
Write-Host "Пароль сохранён в DPAPI текущего пользователя: $OutFile"

if ($RemovePlainText -and (Test-Path $PlainTextFile)) {
    Remove-Item $PlainTextFile
    Write-Host "Открытый файл удалён: $PlainTextFile"
}
elseif (Test-Path $PlainTextFile) {
    Write-Warning "Открытый файл остался: $PlainTextFile. Удалите его после проверки выпуска (или повторите с -RemovePlainText -Force)."
}
