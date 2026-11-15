<#
.SYNOPSIS
    Мастер первого запуска на пустом %ProgramData%\SplitVpn — три варианта получения RU-базы (КТ4). Запускать с повышением.

.DESCRIPTION
    Для каждого варианта: VPN отключается со снятием защиты, служба останавливается, данные службы удаляются
    (резервная копия без секретов — artifacts\backup), служба стартует пустой, запускается интерфейс, мастер
    проходится через UI Automation. Итог каждого варианта проверяется по состоянию службы и адресам выхода.
    Любая неудача завершается снятием защиты («Отключить и восстановить обычный интернет»).
    Пароль берётся из DPAPI-хранилища прототипа через одноразовый файл, который удаляется сразу после чтения.
#>
param(
    [string[]]$Variants = @('download', 'tunnel', 'import'),
    [int]$FailsafeMinutes = 30
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Drawing, UIAutomationClient, UIAutomationTypes, System.Windows.Forms
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class WizShot {
    [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr v);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; } }
'@
[WizShot]::SetProcessDpiAwarenessContext([IntPtr]-4) | Out-Null

$root = Split-Path -Parent $PSScriptRoot
$cli = Join-Path $env:ProgramFiles 'SplitVpn.Dev\cli\splitvpn-cli.exe'
$app = Join-Path $env:ProgramFiles 'SplitVpn.Dev\app\SplitVpn.exe'
$data = Join-Path $env:ProgramData 'SplitVpn'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$shots = Join-Path $root "logs\wizard-$stamp"
New-Item -ItemType Directory -Force -Path $shots | Out-Null
$results = New-Object System.Collections.Generic.List[object]
$AE = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]

& (Join-Path $PSScriptRoot 'failsafe.ps1') -Minutes $FailsafeMinutes

function Log([string]$text) { Write-Host "$(Get-Date -Format 'HH:mm:ss') $text" }
function Status { try { (& $cli status --json | Out-String) | ConvertFrom-Json } catch { $null } }
function WaitState([string[]]$states, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do { $s = Status; if ($s -and $s.state -in $states) { return $s }; Start-Sleep -Seconds 2 } while ((Get-Date) -lt $deadline)
    return (Status)
}
function Probe([string]$ip) {
    $c = New-Object Net.Sockets.TcpClient
    try { if ($c.ConnectAsync($ip, 443).Wait(5000) -and $c.Connected) { $c.Client.LocalEndPoint.Address.ToString() } else { $null } } catch { $null } finally { $c.Dispose() }
}

# --- учётные данные прототипа: сервер и пользователь из proto.json, пароль из одноразового файла ---
$proto = Get-Content (Join-Path $env:ProgramData 'SplitVpn.Dev\proto.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$secretFile = Join-Path $env:ProgramData "SplitVpn.Dev\wizard-$([guid]::NewGuid().ToString('N')).tmp"
& $cli creds export --file $secretFile | Out-Null
$password = (Get-Content $secretFile -Raw -Encoding UTF8)
[IO.File]::Delete($secretFile)
if (-not $password) { throw 'Пароль прототипа не получен.' }

# --- RU-база для варианта «импорт»: список активной ревизии до очистки ---
$importFile = Join-Path $env:TEMP 'wizard-ru.txt'
$geoState = Get-Content (Join-Path $data 'geo\state.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Copy-Item (Join-Path $data "geo\revisions\$($geoState.active)\list.txt") $importFile -Force

function ResetService {
    Log 'сброс: отключение с восстановлением интернета, остановка службы, очистка данных'
    & $cli disconnect | Out-Null
    Start-Sleep -Seconds 2
    Get-Process -Name 'SplitVpn' -ErrorAction SilentlyContinue | Stop-Process -Force
    Stop-Service SplitVpn -Force
    (Get-Service SplitVpn).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    $backup = Join-Path $root "artifacts\backup\programdata-$stamp"
    if (-not (Test-Path $backup)) {
        New-Item -ItemType Directory -Force -Path $backup | Out-Null
        robocopy $data $backup /E /XF secrets.bin /XD logs /NFL /NDL /NJH /NJS /NP | Out-Null
    }
    Get-ChildItem $data -Force | Where-Object Name -ne 'logs' | ForEach-Object {
        if ($_.PSIsContainer) { [IO.Directory]::Delete($_.FullName, $true) } else { [IO.File]::Delete($_.FullName) }
    }
    Start-Service SplitVpn
    (Get-Service SplitVpn).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 4
    $s = Status
    if (-not $s -or $s.intent -ne 'Off' -or $s.profileName) { throw "Служба после очистки не пустая: $($s | ConvertTo-Json -Compress)" }
}

function Find($root, $name, $type = $null, [int]$seconds = 15) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        $cond = New-Object System.Windows.Automation.PropertyCondition ($AE::NameProperty), $name
        if ($type) { $cond = New-Object System.Windows.Automation.AndCondition $cond, (New-Object System.Windows.Automation.PropertyCondition ($AE::ControlTypeProperty), $type) }
        $e = $root.FindFirst($TS::Descendants, $cond)
        if ($e) { return $e }
        Start-Sleep -Milliseconds 400
    } while ((Get-Date) -lt $deadline)
    throw "Элемент «$name» не найден"
}
function SetText($root, $name, $value) {
    $e = Find $root $name ([System.Windows.Automation.ControlType]::Edit)
    $e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($value)
}
function Click($root, $name) { (Find $root $name ([System.Windows.Automation.ControlType]::Button)).GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
function Choose($root, $name) { (Find $root $name ([System.Windows.Automation.ControlType]::RadioButton)).GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select() }
function TextExists($root, [string]$pattern) {
    $cond = New-Object System.Windows.Automation.PropertyCondition ($AE::ControlTypeProperty), ([System.Windows.Automation.ControlType]::Text)
    foreach ($t in $root.FindAll($TS::Descendants, $cond)) { if ($t.Current.Name -match $pattern) { return $t.Current.Name } }
    return $null
}
function Shot($process, [string]$name) {
    $h = $process.MainWindowHandle; if ($h -eq [IntPtr]::Zero) { return }
    $r = New-Object WizShot+RECT; [WizShot]::GetWindowRect($h, [ref]$r) | Out-Null; $w = $r.R - $r.L; $hh = $r.B - $r.T
    if ($w -le 0) { return }
    $bmp = New-Object System.Drawing.Bitmap $w, $hh; $g = [System.Drawing.Graphics]::FromImage($bmp); $hdc = $g.GetHdc(); [WizShot]::PrintWindow($h, $hdc, 2) | Out-Null; $g.ReleaseHdc($hdc); $g.Dispose()
    $small = New-Object System.Drawing.Bitmap $bmp, ([int]($w / 2)), ([int]($hh / 2)); $small.Save((Join-Path $shots "$name.png")); $small.Dispose(); $bmp.Dispose()
}

function RunVariant([string]$variant) {
    $record = [ordered]@{ Variant = $variant; Passed = $true; Checks = [ordered]@{}; Error = $null; Started = (Get-Date).ToString('o') }
    try {
        ResetService
        $process = Start-Process $app -PassThru
        $deadline = (Get-Date).AddSeconds(30)
        while ($process.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500; $process.Refresh() }
        $win = $AE::FromHandle($process.MainWindowHandle)
        Start-Sleep -Seconds 3
        $record.Checks['мастер показан сам'] = [bool](TextExists $win '^Шаг 1 из 5')
        if (-not $record.Checks['мастер показан сам']) { Click $win 'Запустить мастер настройки' }
        Shot $process "$variant-1"

        SetText $win 'Название' 'Основной'
        SetText $win 'Сервер' $proto.server
        SetText $win 'Имя пользователя' $proto.userName
        SetText $win 'Пароль' $password
        Click $win 'Далее'; Start-Sleep -Seconds 1
        if (TextExists $win 'Введите пароль') {
            # ValuePattern не дошёл до поля пароля — ввод клавиатурой.
            (New-Object -ComObject WScript.Shell).AppActivate($process.Id) | Out-Null
            (Find $win 'Пароль' ([System.Windows.Automation.ControlType]::Edit)).SetFocus(); Start-Sleep -Milliseconds 300
            [System.Windows.Forms.SendKeys]::SendWait(($password -replace '([+^%~(){}\[\]])', '{$1}'))
            Click $win 'Далее'; Start-Sleep -Seconds 1
        }
        $record.Checks['шаг 2 открыт'] = [bool](TextExists $win '^Шаг 2 из 5')
        Shot $process "$variant-2"
        Click $win 'Далее'; Start-Sleep -Seconds 1
        Choose $win 'Россия напрямую, остальное через VPN'
        Click $win 'Далее'; Start-Sleep -Seconds 1
        switch ($variant) {
            'download' { Choose $win 'Скачать сейчас через обычное подключение' }
            'tunnel' { Choose $win 'Подключиться в режиме «весь через VPN» и скачать через туннель' }
            'import' {
                Choose $win 'Импортировать файл'
                SetText $win 'Файл базы' $importFile
            }
        }
        Shot $process "$variant-4"
        Click $win 'Готово: подключить'
        $deadline = (Get-Date).AddSeconds(150); $progress = $null
        do { Start-Sleep -Seconds 3; $progress = TextExists $win '^(Готово\.|Подключение не завершено)' } while (-not $progress -and (Get-Date) -lt $deadline)
        $record.Checks['мастер сообщил результат'] = [bool]$progress
        $record.Progress = $progress
        Shot $process "$variant-5"
        Click $win 'Закрыть'; Start-Sleep -Seconds 2
        Shot $process "$variant-6"

        $s = WaitState @('Connected') 60
        $foreign = Probe '1.1.1.1'; $russian = Probe '77.88.55.242'
        $record.Checks['подключено'] = ($s.state -eq 'Connected')
        $record.Checks['профиль «Основной»'] = ($s.profileName -eq 'Основной')
        $record.Checks['RU-база загружена'] = ($s.geoV4Count -gt 10000)
        $record.Checks['режим «Россия напрямую»'] = ($s.routingMode -eq 'RussiaDirect')
        $record.Checks['иностранный адрес через туннель'] = ($foreign -like '192.168.44.*')
        $record.Checks['RU напрямую'] = ($russian -like '192.168.1.*')
        $record.Checks['мастер закрыт'] = -not (TextExists $win '^Шаг \d из 5')
        $record.Passed = -not ($record.Checks.Values -contains $false)
        $process | Stop-Process -Force
    } catch {
        $record.Passed = $false; $record.Error = "$_"
        Log "ОШИБКА варианта $variant : $_"
        Get-Process -Name 'SplitVpn' -ErrorAction SilentlyContinue | Stop-Process -Force
    } finally {
        if (-not $record.Passed) { Log 'вариант не пройден — снимаю защиту'; & $cli disconnect | Out-Null }
        $record.Finished = (Get-Date).ToString('o')
        $results.Add([pscustomobject]$record)
        Log ("--- $variant : " + $(if ($record.Passed) { 'ПРОЙДЕН' } else { 'НЕ ПРОЙДЕН' }))
    }
}

foreach ($v in $Variants) { Log "=== $v"; RunVariant $v }
$password = $null
[IO.File]::Delete($importFile)
$results | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $root "logs\wizard-results-$stamp.json") -Encoding UTF8
$passed = @($results | Where-Object Passed).Count
Log "Итог: пройдено $passed из $($results.Count); снимки: $shots"
if ($passed -ne $results.Count) { & $cli disconnect | Out-Null; Log 'защита снята, интернет напрямую' }
New-Item (Join-Path $root 'logs\failsafe.disarm') -ItemType File -Force | Out-Null
$global:LASTEXITCODE = if ($passed -eq $results.Count) { 0 } else { 1 }
