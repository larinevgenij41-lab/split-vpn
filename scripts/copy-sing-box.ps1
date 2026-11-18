param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$singBoxManifestPath = Join-Path $root 'third_party\sing-box\manifest.json'
$singBox = Get-Content $singBoxManifestPath -Raw -Encoding utf8 | ConvertFrom-Json
$singBoxExe = Join-Path $root "third_party\sing-box\bin\$($singBox.executable.name)"
if (-not $singBox.executable.sha256) { throw "В $singBoxManifestPath не закреплён SHA-256 движка: scripts\fetch-sing-box.ps1 -Pin" }
if (-not (Test-Path $singBoxExe)) { throw "Нет ${singBoxExe}: запустите scripts\fetch-sing-box.ps1" }
$singBoxHash = (Get-FileHash $singBoxExe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($singBoxHash -ne $singBox.executable.sha256.ToLowerInvariant()) {
    throw "SHA-256 $singBoxExe ($singBoxHash) не совпадает с $singBoxManifestPath ($($singBox.executable.sha256))"
}

Copy-Item $singBoxExe (Join-Path $Destination $singBox.executable.name) -Force
return $singBox
