# AnyConnect: где остановились и как продолжить

Обновлено: 2026-09-14. Файл нужен, чтобы продолжить работу на другом компьютере или в новом сеансе Claude Code с того же места.

Полный план и таблица КТ — `docs\ANYCONNECT-PLAN.md`. Факты стенда КТ0 — `docs\PROTOTYPE-REPORT.md`, раздел «AnyConnect КТ0».

## 1. Состояние

- Репозиторий `D:\VPN`, ветка `feature/anyconnect`.
- Теги закрытых КТ: `kt-ac0` … `kt-ac5`.
- Версия продукта — `0.5.0` (`Directory.Build.props`). На компьютере workstation установлена более ранняя версия службы; для живой проверки исправлений 0.5.0 её нужно переустановить.
- Проверки: сборка Release без ошибок и предупреждений, 458 тестов .NET зелёные.
- Аудит Windows-версии и исправления 0.5.0 — `docs\WINDOWS-AUDIT.md` (что сделано и что осталось проверить на стенде).
- **Удалённого репозитория (`git remote`) нет.** На другой компьютер переносится вся папка репозитория: копией или после `git remote add` и `git push --all --tags`.

| КТ | Статус |
|---|---|
| КТ0 Стенд | пройдена |
| КТ1 Native (сборка libopenconnect, манифест, лицензии) | пройдена |
| КТ2 Ядро (модель, политика, WFP, IPC v4, контракт помощника) | пройдена |
| КТ3 Помощник `SplitVpn.OpenConnect` | пройдена |
| КТ4 Служба | пройдена |
| КТ5 Интерфейс | пройдена |
| **КТ6 Живая проверка** | **в работе: SSO → туннель поднят, остальные сценарии раздела 3 не пройдены** |
| КТ7 Поставка (MSI, обновление, удаление, документы) | документы готовы (aa501f4), MSI-сценарии не начаты |

## 2. Итог первой живой проверки (2026-09-14, 0.3.1 → 0.3.3)

Сбой «Шлюз недоступен (код -5)» до окна SSO. Причины и исправления:
1. **Служба не разрешала имя шлюза.** В журнале помощника: `getaddrinfo failed for host 'avpn.example.org'`. Аудит WFP (события 5152/5157) показал, что запрос службы к DNS роутера режет `[Base] DNS-страж UDP`. Разрешение `[Runtime] DNS службы` не срабатывало: дескриптор условия ALE_USER_ID был `O:SYD:(A;;GA;;;SY)`, а WFP сверяет право `FWP_ACTRL_MATCH_FILTER` (0x1, `CC`) и общие права в ACE не раскрывает. Исправлено на `(A;;CC;;;SY)` (`WfpOps.SystemOnlySddl`). На прежнем компьютере не проявлялось: DNS шёл через SSTP-туннель, адреса серверов брались из кэша.
2. **Без опорного туннеля DNS-посредник уходил в Offline** (SERVFAIL на всё, страница IdP — `ERR_NAME_NOT_RESOLVED`). При «остальном интернете» напрямую теперь режим `DirectAllowed` (`BuildProxyConfiguration`, тест `AnyConnect_OnlyTunnelWithDirectInternet_KeepsDnsDirectBeforeSignIn`).
3. **Чужие VPN Windows** («IKEv2 VPN 203.0.113.10» с маршрутами 0/1 и 128/1, «HomeSSTP» с 192.168.1.0/24 метрикой 1) под защитой роняют весь интернет: фильтр «Не основной адаптер». Это поведение по замыслу, на время проверок их отключать.

Проверено на 0.3.3 (профили: только «Офис», «остальной интернет» напрямую):
- SSO → «Подключено», адрес 10.0.7.204, 69 сетей шлюза, DNS 10.0.16.21, MTU 1278, DTLS активен;
- `check 10.0.16.21` → Vpn (TunnelInfrastructure) через `SplitVpn AC …`; `check avpn.example.org` → Server, Wi-Fi; `1.1.1.1` → напрямую;
- `jira.example.org` → 10.0.64.20, `confluence.example.net` → 10.0.21.13, `ya.ru` разрешается;
- `www.example.org` (198.51.100.20) идёт в AnyConnect: этот /32 шлюз сам присылает в Split Include, как и 162.159.0.0/16 и 172.66.0.0/16 (Cloudflare). Split DNS: `example.net, local, example.org, office.example.org` (в `status --json` — поле `dnsSuffixes`), PAC — `https://nexus.example.net/repository/repo/proxy.pac`.

Дальше в тот же день (0.3.4–0.3.6):
4. **Короткие имена** (`ws-001`) не разрешались: суффиксы split DNS направлялись в DNS шлюза, но в список поиска Windows не попадали. Суффикс на адаптере Wintun Windows не использует (у него нет DNS-серверов), поэтому служба добавляет суффиксы установленных сеансов в SearchList основного адаптера (`EnsureSearchList`); исходный список хранится в `dns-backup.json` и возвращается в `InterfaceDnsOps.Restore`. Проверено: `ws-001` → `ws-001.office.example.org` 10.0.3.70, ping и RDP.
5. **Повторный вход падал** с «Could not open Wintun adapter … Элемент не найден»: после завершения сеанса в `Control\Network\{4D36E972…}` остаётся запись подключения с именем адаптера без устройства (и LUID в NSI). libopenconnect находит её по имени и не создаёт новый адаптер. Помощник перед `setup_tun_device` удаляет такие записи, если `CM_Locate_DevNodeW` не находит устройство (`TunnelInterfaceConfig.RemoveStaleWintunEntries`). Проверено обновлением 0.3.5 → 0.3.6 поверх призрака: вход прошёл, SSO без ввода (ADFS помнит сеанс).

Мелочи, найденные по пути:
- `check` писал «Адреса нет ни в одном правиле» для сетей шлюза и «Адрес SSTP-сервера» для шлюза — исправлено (4db3fc7).
- При сбое разрешения имени помощник всё ещё пишет «Шлюз недоступен (код -5)»; понятнее было бы «не удалось разрешить имя шлюза».
- `scripts\elevated.ps1` возвращает код 1 даже при успешной команде, если в ней нет явного `exit`.
- В PowerShell 5.1 `Get-Content -Raw` + `Set-Content -Encoding UTF8` портит кириллицу в файлах без BOM — править версии через `sed`.

### Следующие шаги

1. Пройти оставшиеся сценарии раздела 3: `scripts\kt-ac-scenarios.ps1` (из PowerShell администратора, ещё ни разу не запускался) или вручную.
2. Затем КТ7: MSI поверх в подключённом состоянии, удаление, `kt6-uninstall.ps1`.
## 3. Сценарии КТ6

Вход в SSO выполняет пользователь.

- SSO → туннель поднят; `check 10.0.16.21` показывает цель «через Офис» и интерфейс Wintun.
- DTLS активен под фильтрами WFP (строка туннеля на главной и «Диагностика»).
- `nslookup x.office.example.org` идёт через посредник на 10.0.16.21, `nslookup ya.ru` — нет.
- `check avpn.example.org` показывает «напрямую»; публичный `www.example.org` идёт по политике, не в AnyConnect.
- Обрыв Wi-Fi → переподключение внутри помощника без SSO.
- Kill помощника → сети шлюза сняты, запрос входа, окно открывается само один раз.
- Остановка службы → сети сняты, помощник завершён. Старт службы → запрос входа.
- Роль «Выключено» → Stop (BYE), адаптера и процесса нет.
- PAC (если включён в профиле) ставится при подключении и снимается при отключении и выходе интерфейса.
- `recover-network.cmd` → нет процессов `SplitVpn.OpenConnect`, маршрутов и фильтров.
- Повтор сценариев SSTP: ничего не сломано.

КТ7:
- MSI поверх рабочей версии в подключённом состоянии;
- удаление → снимок сети совпадает с исходным;
- документы: `README`, `LIMITATIONS` (Cisco vpnagent одновременно не поддерживается; PAC без запущенного интерфейса не ставится и не снимается; при аварии службы сети шлюза не защищены до её рестарта), `VPN-PROTOCOLS.md`, `BUILD.md`, оговорка в `VPN-PROTOCOLS-PLAN.md`.

## 4. Окружение на новом компьютере

- **Нужно:** .NET 10 SDK, Windows 11, права администратора для службы и установщика, WebView2 Runtime (в Windows 11 есть). WiX собирается через `dotnet build` проекта `installer\SplitVpn.Installer.wixproj`.
- **Нативные библиотеки AnyConnect** (`third_party\openconnect\bin`, 22 DLL) в git не хранятся. Варианты:
  - скопировать папку `bin` с этого компьютера;
  - пересобрать скриптом (проверяет SHA-256 по `third_party\openconnect\manifest.json`). Нужен MSYS2 (UCRT64). Команда: `$env:MSYSTEM='UCRT64'; C:\msys64\usr\bin\bash.exe -l /d/VPN/scripts/build-openconnect.sh`.
- **Проверки:**
  - `dotnet build SplitVpn.slnx -c Release`;
  - `dotnet test --solution SplitVpn.slnx -c Release`;
  - самопроверка интерфейса: `SplitVpn.exe --selftest`, журнал в `%TEMP%\splitvpn-selftest.log`. Снимки страниц — переменные `SPLITVPN_SELFTEST_THEME=Light|Dark` и `SPLITVPN_SELFTEST_SHOTS=<папка>`.
- **Прочие ветки и копии:**
  - `D:\VPN-uifix` (ветка `fix/ui-critical`, уже слита в `feature/anyconnect`);
  - `D:\VPN-multi` (ветка `feature/multi-tunnel`, пауза — ждём второй сервер).

## 5. Правила работы (из памяти Claude на этом компьютере)

- Коммиты делать самому, без вопросов. Тег `kt-ac-N` ставить только на закрытой КТ; в таблице `ANYCONNECT-PLAN.md` отмечать итог.
- Никаких строк соавторства в коммитах (`Co-Authored-By`, ссылок на сеанс).
- Перед `git add` запускать `scripts\normalize-eol.ps1`: `safecrlf` требует CRLF, а `.sh` хранятся с LF.
- Поднимать версию самому: исправления — патч, новая функция — минор. Перед сборкой MSI номер должен быть больше установленного.
- Тексты интерфейса, журнала, комментарии и документы — на русском.

## 6. Ключевые решения, которые легко забыть

- **Сеанс ASA не переносится между процессами** (CONNECT по cookie из нового процесса даёт 401). Любой перезапуск помощника или службы требует нового входа; ADFS в постоянном профиле WebView2 может пропустить ввод.
- **Помощник запускается только по действию пользователя:** «Подключить» или «Войти» (`Facts.SignInApproved`). После завершения сеанса туннель ждёт входа (`SignInKind.Required`).
- **Интерфейс сам начинает вход** (`SignInCoordinator`) один раз до следующего подключения. Закрытое пользователем окно повторно не открывается до кнопки «Войти».
- **Пароль AnyConnect в v1 не сохраняется** — вводится в форме шлюза. Клиентский сертификат — только хранилище LocalMachine.
- **Сети шлюза и DNS туннелей** участвуют в политике только при установленном сеансе.
- **Суффиксы split DNS** (без однословных вроде `local`) и хост PAC разрешаются через DNS шлюза без закрепления адресов (`DomainRoute.PinAddresses = false`). Адрес VPN-сервера доменные правила не закрепляют.
- **PAC-прокси ставит интерфейс** (WinINet, резервная копия `%LOCALAPPDATA%\SplitVpn\proxy-backup.json`). По умолчанию выключен.
- **ConflictDetector** уже игнорирует маршруты /32: широковещательные и на собственный адрес туннеля.
- **В редакторе у поля «Способ входа» `IsAsync=True`.** Без этого после смены профиля WPF не находил значение в новом списке и поле пустело.

## 7. Карта кода AnyConnect

| Что | Где |
|---|---|
| Модель, разбор шлюза, валидатор | `src\SplitVpn.Core\Settings\` (`AnyConnectGateway.cs`, `VpnProtocol.cs`, `SettingsValidator.cs`) |
| Политика: сети шлюза, инфраструктура туннелей | `src\SplitVpn.Core\Policy\PolicyCompiler.cs`, `PolicyTypes.cs` |
| Контракт службы и помощника | `src\SplitVpn.Core\OpenConnect\HelperContract.cs` |
| IPC (вход, сети шлюза) | `src\SplitVpn.Core\Ipc\Messages.cs` |
| Откат PAC-прокси | `src\SplitVpn.Core\Diagnostics\ProxyApplier.cs` |
| Помощник | `src\SplitVpn.OpenConnect\` (`OcSession.cs`, `NativeOcLib.cs`, `HelperHost.cs`) |
| C-прослойка | `native\ocshim\ocshim.c` |
| Запуск помощника, Job | `src\SplitVpn.Windows\OpenConnect\SystemAnyConnectOps.cs` |
| Служба | `src\SplitVpn.Service\Coordination\Coordinator.AnyConnect.cs`, `TunnelFacts.cs` |
| Интерфейс | `src\SplitVpn.App\Services\SignInCoordinator.cs`, `ProxyService.cs`, `Views\SignInWindow.xaml`, `Views\SignInFormWindow.cs` |
| Тесты | `tests\SplitVpn.Service.Tests\CoordinatorAnyConnectTests.cs`, `OpenConnect\OcSessionTests.cs`, `tests\SplitVpn.Core.Tests\Diagnostics\ProxyApplierTests.cs` |
| Сборка нативных библиотек и установщика | `scripts\build-openconnect.sh`, `scripts\build-installer.ps1` |

## 8. Грабли среды

- **PowerShell 5.1:** `Start-Process -ArgumentList` не экранирует пробелы — передавать одной строкой с кавычками.
- **MSYS bash:**
  - срезает литеральный CR в скриптах;
  - `jq` из UCRT64 выводит CRLF — пропускать через `tr -d '\015'`.
- **Длинные правки через Python:** в heredoc bash они ломаются. Надёжнее записать скрипт в файл и запустить `py -3 файл.py` (`python` в PATH нет).
- **Самопроверка интерфейса:** до создания окон вызывается `ThemeService.Apply`, иначе основные кнопки падают без ресурса `SystemAccentColorPrimary`.
- **Помощник под службой** работает от LocalSystem; `wintun.dll` грузится только из каталога exe.
