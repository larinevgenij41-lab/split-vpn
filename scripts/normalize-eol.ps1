<#
.SYNOPSIS
    Приводит изменённые и новые текстовые файлы репозитория к CRLF с сохранением BOM.

.DESCRIPTION
    В глобальной настройке git включены core.autocrlf=true и core.safecrlf=true: файл с LF
    отклоняется при git add. Скрипт запускать перед коммитом.
#>
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$extensions = '.cs', '.csproj', '.props', '.targets', '.json', '.txt', '.md', '.ps1', '.cmd', '.slnx', '.xml', '.xaml', '.wxs', '.wixproj', '.resx', '.manifest',
    '.kt', '.kts', '.toml', '.pro', '.yaml', '.yml', '.c', '.h', '.cmake', '.java', '.properties', '.gradle', '.bat', '.mk'
$files = git ls-files --others --modified --exclude-standard |
    Where-Object { ($extensions -contains [IO.Path]::GetExtension($_) -or (Split-Path $_ -Leaf) -in '.gitignore', '.gitattributes', '.gitmodules') -and (Split-Path $_ -Leaf) -ne 'gradlew' }

$changed = 0
foreach ($file in $files) {
    # Полный путь: методы .NET берут текущий каталог процесса, а не расположение PowerShell (важно в worktree).
    $file = Join-Path (Get-Location) $file
    $bytes = [IO.File]::ReadAllBytes($file)
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $offset = if ($bom) { 3 } else { 0 }
    $text = [Text.Encoding]::UTF8.GetString($bytes, $offset, $bytes.Length - $offset)
    $normalized = ($text -replace "`r`n", "`n") -replace "`n", "`r`n"
    if ($normalized -ne $text) {
        [IO.File]::WriteAllText((Resolve-Path $file), $normalized, (New-Object Text.UTF8Encoding $bom))
        $changed++
    }
}

Write-Host "Приведено к CRLF: $changed из $($files.Count)"
