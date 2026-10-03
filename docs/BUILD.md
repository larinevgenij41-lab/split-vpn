# Сборка и разработка

## Требования

- Windows 11 x64, .NET SDK 10.0.4xx (`global.json`), git.
- Для протокола AnyConnect — MSYS2 (`winget install MSYS2.MSYS2`, `C:\msys64`). Нативные библиотеки собираются отдельно и в git не хранятся:
  ```
  $env:MSYSTEM='UCRT64'; C:\msys64\usr\bin\bash.exe -l /d/VPN/scripts/build-openconnect.sh
  ```
  Скрипт ставит закреплённые в `third_party\openconnect\manifest.json` пакеты, проверяет SHA-256, собирает libopenconnect 9.21 и `native\ocshim` и выкладывает DLL, лицензии и `SHA256SUMS.txt` в `third_party\openconnect\bin`. Без этого каталога решение собирается, а установщик — нет. Архивы кэшируются в `third_party\openconnect\work\cache`. Новая версия пакета — сначала правка манифеста (версия, хеш), затем сборка: скрипт сам сверит замыкание DLL с манифестом. Если `bin` скопирован с другого компьютера, сверьте его с `SHA256SUMS.txt`.
- `scripts\build-installer.ps1` публикует помощник `SplitVpn.OpenConnect` рядом со службой, сверяет DLL в публикации с `third_party\openconnect\bin\SHA256SUMS.txt` и запускает `SplitVpn.OpenConnect.exe --version`: несовпадение хеша или незагрузившаяся библиотека останавливают сборку.
- Для установщика — WiX Toolset 7 (пакет `WixToolset.Sdk`, ставится через NuGet при сборке `installer\`). WiX 7 требует принять EULA OSMF: в `installer\SplitVpn.Installer.wixproj` стоит `<AcceptEula>wix7</AcceptEula>` (принято пользователем 2026-09-13, личное использование). Сборка: `scripts\build-installer.ps1`.

## Команды

```
dotnet build SplitVpn.slnx -c Release      # без предупреждений (TreatWarningsAsErrors)
dotnet test --solution SplitVpn.slnx -c Release
dotnet publish src\SplitVpn.Service\SplitVpn.Service.csproj -c Release -o artifacts\publish\service
dotnet publish src\SplitVpn.Cli\SplitVpn.Cli.csproj -c Release -o artifacts\publish\cli
dotnet publish src\SplitVpn.App\SplitVpn.App.csproj -c Release -o artifacts\publish\app
```

Нет доступа к api.nuget.org — сборка падает на `NU1900` (проверка уязвимостей пакетов). Для локальной сборки добавьте `-p:NuGetAudit=false` к `dotnet build`/`test`/`publish`; скрипт установщика параметра не принимает — задайте перед ним `$env:NuGetAudit='false'` (MSBuild читает переменные среды как свойства). Пакеты при этом должны уже быть в кэше NuGet.

Перед `git add` — `scripts\normalize-eol.ps1` (в git включён `core.safecrlf`).

Выпуск версии — `scripts\publish-release.ps1`, порядок и ключ подписи описаны в [RELEASE.md](RELEASE.md).
## Состав решения

| Проект | Назначение |
|---|---|
| `SplitVpn.Core` | политика разделения, RU-база, DNS-сообщения, настройки, состояния, контракт IPC |
| `SplitVpn.Windows` | RAS, IP Helper, WFP, DNS интерфейсов, DPAPI, восстановление (CsWin32) |
| `SplitVpn.Service` | служба: координатор «намерение → сверка», IPC-сервер, DNS-посредник, обновление базы |
| `SplitVpn.OpenConnect` | процесс-помощник AnyConnect: libopenconnect, Wintun; служба запускает его по анонимным трубам |
| `SplitVpn.App` | WPF-интерфейс и трей; только IPC |
| `SplitVpn.Cli` | утилита разработки: диагностика, сценарии КТ1, управление службой через IPC |
| `tests\*` | модульные тесты ядра и координатора на фейках Windows-слоя |

## Испытания на этом компьютере

- `scripts\elevated.ps1 -Command '…'` — запуск с повышением (UAC), вывод в `logs\`.
- `scripts\install-dev-service.ps1` — публикация и установка dev-службы в `%ProgramFiles%\SplitVpn.Dev` со сторожевой задачей.
- `scripts\kt2-scenarios.ps1 [-Scenario …]` — сценарии сбоев; при неудаче снимают защиту.
- `scripts\wizard-e2e.ps1` — мастер первого запуска на пустом `ProgramData` через UI Automation.
- `scripts\failsafe.ps1 -Minutes N` — предохранитель: recover по сроку или при загрузке, если нет связи.
- `scripts\cleanup-dev.ps1 [-Service] [-All]` — уборка dev-окружения перед КТ5/КТ6.

Правила: пароли только через DPAPI и одноразовые файлы, никогда в командной строке и журналах; любой сценарий заканчивается либо проверенным «Подключено», либо снятой защитой.
