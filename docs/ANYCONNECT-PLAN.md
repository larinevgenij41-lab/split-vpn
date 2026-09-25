# План: протокол Cisco AnyConnect со входом через SSO (Windows)

Статус: утверждён пользователем 2026-09-14. Ветка `feature/anyconnect`.

| КТ | Статус | Дата | Итог |
|---|---|---|---|
| КТ0 Стенд | пройдена | 2026-09-14 | SSO, CSTP, DTLS, трафик, DNS и PAC на реальном ASA работают; подъём по cookie из нового процесса невозможен — план изменён, отчёт в PROTOTYPE-REPORT.md |
| КТ1 Native | пройдена | 2026-09-14 | манифест с SHA-256, воспроизводимая сборка 22 DLL (scripts\build-openconnect.sh), лицензии, помощник SplitVpn.OpenConnect --version из макета MSI 0.3.0; версия продукта 0.3.0 |
| КТ2 Ядро | пройдена | 2026-09-14 | VpnProtocol.AnyConnect, AuthMethod.GatewayForm, AnyConnectSettings, разбор шлюза, валидатор; слои ServerNetwork и TunnelInfrastructure в политике; транспорт WFP; IPC v4 (вход, сети шлюза); HelperContract; 307 тестов .NET. DomainRoute.PinAddresses перенесён в КТ4 (слой Windows) |
| КТ3 Помощник | пройдена | 2026-09-14 | SplitVpn.OpenConnect: OcSession (SSO, формы, запрос адреса шлюза у службы, CSTP, DTLS, Wintun, mainloop, остановка), HelperHost на анонимных трубах, адрес /32 и MTU через IP Helper, сертификат компьютера для GnuTLS (вживую не проверен — шлюз его не требует); 20 тестов на фейке; живой прогон через трубы: SSO → туннель → Stop → Cancelled, адаптер удалён. Windows добавляет /32 на адрес туннеля (m256) — учесть в ConflictDetector |
| КТ4 Служба | пройдена | 2026-09-14 | Coordinator.AnyConnect.cs: помощник только по «Подключить»/«Войти» (SignInApproved), события в очереди актора с поколением, вход SSO/форма через IPC, ResolveHost открывает шлюз до ответа; IsUp/HasSession вместо Connection; сети шлюза и DNS туннелей в политике только при установленном сеансе; суффиксы split DNS (без однословных) и хост PAC — DomainRoute без закрепления на DNS шлюза; адрес VPN-сервера не закрепляется доменными правилами; остановка службы снимает сети и шлёт Stop; SystemAnyConnectOps (трубы, Job KILL_ON_JOB_CLOSE); NetworkRecovery завершает помощников. ConflictDetector правок не потребовал: /32 он уже не считает чужими. 367 тестов, RAS-тесты без правок |
| КТ5 Интерфейс | пройдена | 2026-09-14 | Редактор: протокол Cisco AnyConnect (группа, сертификат LocalMachine, DTLS, PAC, User-Agent), роль без «Опорного», мастер AnyConnect не предлагает; главная: карточка «Требуется вход» и кнопка «Войти», строка туннеля с DTLS/TLS и числом сетей; SignInCoordinator открывает окно SSO (WebView2, cookie только хоста шлюза) или форму шлюза и закрывает их по состоянию службы, сам начинает вход один раз до следующего подключения; доска: карточка «Сети шлюза» (не в группу, «Остальной интернет» и RU-база не в AnyConnect); PAC ставит интерфейс через WinINet с резервной копией и откатом (ProxyApplier в Core, тесты); диагностика: сеансы шлюза; CLI: tunnels показывает вход и сети, команда sign-in. Пароль AnyConnect в v1 не сохраняется — вводится в форме шлюза. Самопроверка снимает страницы в обеих темах (SPLITVPN_SELFTEST_THEME/SHOTS); по снимкам исправлено пустое поле «Способ входа» после смены профиля (давний порядок привязок WPF). 372 теста |
| КТ6 Живая проверка | в работе | 2026-09-14 | Сбой -5 до формы входа: служба не разрешала шлюз — DNS-страж резал её же запросы (дескриптор ALE_USER_ID с GA вместо CC), а без опорного туннеля DNS-посредник уходил в Offline. Исправлено в 0.3.3 (71c4057). На 0.3.3 SSO → туннель поднят: 69 сетей, DTLS, DNS 10.0.16.21, `check` 10.0.16.21 через Wintun, шлюз напрямую, внутренние имена разрешаются. Остальные сценарии — docs\ANYCONNECT-HANDOFF.md |
| КТ7 Поставка | не начата | | |

## Изменения после КТ0 (2026-09-14)

Факты стенда — `docs\PROTOTYPE-REPORT.md`, раздел «AnyConnect КТ0». Текст плана ниже уже исправлен.

1. **Сеанс ASA не переносится между процессами.** CONNECT по сохранённому cookie из нового экземпляра libopenconnect получает 401: проверено со STRAP и без, с разными значениями Host. Внутри процесса переподключение работает. Поэтому исключены хранение cookie (`SecretKind.SessionCookie`), `Stop(Detach)` и «подъём без SSO после рестарта службы». Рестарт службы, обновление и падение помощника требуют нового входа. Если ADFS помнит сессию, это 3–6 с без ввода.
2. **Остановка — всегда `CANCEL` (BYE)**, чтобы сессия на ASA не висела до таймаута.
3. **Автоматический повторный вход.** Если у туннеля намерение «подключено» и появился запрос входа, App сам открывает окно SSO — при старте и при появлении запроса. Если пользователь закрыл окно, App не повторяет запрос до кнопки «Войти». Пока App не запущен, туннель ждёт входа.
4. **Сборка.** Пакета OpenConnect в MSYS2 больше нет. libopenconnect 9.21 собирается из официального архива в UCRT64 (`scripts\build-openconnect.sh`, правка `compat.c`), зависимости — пакеты UCRT64 с хешами в манифесте.
5. **Параметры сеанса:**
   - MTU берётся из `ip_info` (1230);
   - суффиксы — из `split_dns` (`domain` пуст);
   - срок сеанса — из `X-CSTP-Session-Timeout` (`get_auth_expiration` возвращает 0);
   - ASA запрашивает клиентский сертификат необязательно, вход без него проходит.
6. **Wintun.** Адаптер исчезает при завершении процесса, поэтому кода удаления в `NetworkRecovery` нет. `wintun.dll` лежит рядом с exe помощника.
7. **Маршруты.** Windows добавляет на туннель /32 широковещательных адресов on-link-сетей с метрикой 256. `ConflictDetector` не должен считать их чужими.
8. **Не проверено на стенде:** DTLS и DNS под фильтрами WFP — переносится в КТ6.

## Контекст

Корпоративный VPN на Cisco ASA, шлюз `avpn.example.org` (в примерах — профиль «Офис»). Штатный Cisco-клиент плохо уживается с «Раздельным VPN»: его агент сам управляет маршрутами, DNS («Tunnel all DNS») и фильтрами.

Цель — подключаться к ASA из нашего приложения как **дополнительное подключение**, без Cisco-клиента. Маршруты, DNS и защита остаются за нашей службой.

Что известно о сервере из журнала Cisco-клиента на этой машине:
- **Вход:** SAML SSO во встроенном браузере. Внешний браузер невозможен: он появился только в ASA 9.17.1.
- **Сети:** Split Include 69 сетей (10.0.0.0/8 и адреса /32).
- **DNS:** сервер 10.0.16.21, суффиксы `office.example.org, example.org, local, example.net`.
- **Прокси:** PAC `https://nexus.example.net/.../proxy.pac`.
- **Транспорт:** DTLS (UDP 443).
- **Таймауты:** Session Timeout 36000 с, Idle Timeout 3600 с.

Решения пользователя:
- роль только «Дополнительное»;
- карточка «Сети сервера» на доске маршрутизации;
- libopenconnect в отдельном процессе-помощнике;
- в v1: SSO, DTLS, PAC-прокси, логин/пароль (формы ASA), клиентский сертификат.

Реализация — **libopenconnect** (OpenConnect ≥ 9.10, LGPL-2.1): SAML SSO через webview-колбэк (API 5.7+), DTLS, Wintun на Windows. Это осознанное расширение правила «только RAS» из `docs\VPN-PROTOCOLS-PLAN.md`; оговорку внести туда.

Ветка `feature/anyconnect`. План переносится в `docs\ANYCONNECT-PLAN.md` с таблицей КТ; теги `kt-ac0…kt-ac7`.

План прошёл критику: опровержение, полнота, KISS. Учтено:
- **блокер** с фильтром «туннель недоступен» на кэше 10/8;
- доменные суффиксы без закрепления адресов и исключение адреса шлюза;
- kill switch при остановке службы;
- cookie вместе с хостом и хэшем сертификата;
- сертификат CurrentUser отложен в v2;
- PAC применяет App и по умолчанию выключен;
- без повышения схемы настроек;
- `Luid` через `IsUp`;
- vpnc-скрипт `NULL`;
- `getaddrinfo` в C-прослойке;
- ряд упрощений.

## Что в коде мешает (проверено)

1. `src\SplitVpn.Core\Policy\PolicyCompiler.cs:89`. `SpecialRanges.Local` окрашивается после пользовательских правил, поэтому 10.0.0.0/8 от сервера в туннель не попадёт.
2. `src\SplitVpn.Service\Coordination\Coordinator.cs:154-157`. `DnsAnchor` в запасной ветке берёт любой поднятый туннель.
3. `Coordinator.Apply.cs:655`. `TunnelDnsRoute` предпочитает `UpstreamDns` DNS-серверу туннеля.
4. `src\SplitVpn.Core\Protection\FilterPlan.cs:287` (`Transports`, `_ => throw`) и `switch` в `VpnProtocol.cs`.
5. `TunnelFacts.cs:67`: `Luid => Connection is null ? null : Adapter?.Luid`. От него зависят маршруты, `TunnelLuids()`, `OnLinkPrefixes()`, `TunnelInputs`.
6. Доменные правила закрепляют адреса /32 за целью (`Coordinator.Pinned.cs`, `Apply.cs:357-394`). Суффикс `example.org` закрепил бы в туннеле и адрес шлюза, и публичный сайт.
7. Фильтры состояния «туннель поднят» не блокируют диапазоны туннеля (`FilterPlan.cs:26-33`). Если служба выйдет, трафик к сетям сервера пойдёт мимо.
9. RAS-специфика: `IRasOps`, `AttachTunnel` (адаптер по адресу проекции), `MonitorConnection` (журнал RasClient 20226), `AdoptConnectionsAsync`, `SaveEntry`/`CleanupEntries`, `NetworkRecovery` (phonebook).

## Архитектура

### 1. Бэкенд туннеля в службе (без переписывания RAS)

- **`TunnelFacts.cs`:**
  - добавить `AnyConnect: AnyConnectLink?` (сеанс помощника, Generation, Established), `ServerNetworks` (IpInfo) и `SignIn` (текущий запрос входа);
  - `IsUp => Connection is not null || AnyConnect is {Established: true}`;
  - **`Luid => IsUp ? Adapter?.Luid : null`**;
  - проверки «туннель поднят» (13 мест `Connection is (not) null` в `Coordinator*.cs`) перевести на `IsUp`; вызовы RAS API не трогать.
- **`IAnyConnectOps`** (`src\SplitVpn.Windows\Operations\Abstractions.cs`):
  - `Start(AnyConnectStart, Action<HelperEvent>) → IAnyConnectSession` (`Send`, `HasExited`, `Dispose`);
  - поле `ServiceDependencies.AnyConnect`;
  - реализация `SystemAnyConnectOps` в `src\SplitVpn.Windows\OpenConnect\`.
- **`Coordinator.AnyConnect.cs`** — ветки по `Protocol == AnyConnect`:

  | Точка | Поведение |
  |---|---|
  | `SyncTunnelsAsync` | Off или удаление → `Stop(Logout)` |
  | `PrepareEntry`/`SaveEntry`/`CleanupEntries` | телефонная книга не используется |
  | `AdoptConnectionsAsync` | пропуск: после рестарта службы — новый вход |
  | `CanStartDial`/`StartDial` | `StartAnyConnect` |
  | `MonitorConnection` | события помощника и `HasExited` |
  | `HangUpAsync`/`TeardownAsync` | `Stop(Logout)` |
  | `BeginProfileTest` | «для AnyConnect — используйте Подключить» |

  События помощника ставятся в очередь актора с отбрасыванием устаревших поколений (образец `OnDialFinishedAsync`). Адаптер находится по LUID из события `Established`.
- **Обрывы:**
  - `NetworkError` или падение помощника → `OnConnectionLost`, диапазоны блокируются, запрос нового входа (при запомненном ADFS — без ввода);
  - `AuthRejected` или `SessionExpired` → запрос входа, без повторов;
  - `CertificateRejected` или `HostScanRequired` → `BlockingError`.
- **Реконнект внутри сеанса** выполняет `openconnect_mainloop`: LUID сохраняется, маршруты остаются на туннеле.
- **Остановка службы (kill switch):**
  1. AnyConnect-туннели помечаются опущенными, применяются фильтры состояния «туннель недоступен» — диапазоны сетей сервера блокируются.
  2. Помощнику отправляется `Stop` (`CANCEL`, BYE на ASA).
  3. Служба выходит.

  Новая служба поднимает сеанс после нового входа. Если служба упала аварийно, Job убивает помощника, а трафик к сетям сервера до рестарта службы не защищён — записать в `LIMITATIONS.md`.

### 2. Процесс-помощник `src\SplitVpn.OpenConnect` (exe, net10.0-windows)

- **Процесс.** Один на AnyConnect-профиль, запускается службой от LocalSystem только из её каталога. Служба при старте помещает **себя** в Job с `KILL_ON_JOB_CLOSE`, дочерние процессы наследуют его без гонок.
- **Канал.** Пара анонимных труб (наследуемые дескрипторы), кадры — существующий `FrameCodec` и полиморфный JSON. Контракт `src\SplitVpn.Core\OpenConnect\HelperContract.cs` (`Version = 1`).
  - **Служба → помощник:** `Start{Host, Port, Group, UserName, Password?, CertThumbprint?, Dtls, UserAgent, IfName}`, `WebviewLoad{RequestId, Uri, Cookies}`, `WebviewClosed`, `FormReply{RequestId, Values, Cancel}`, `ResolveReply`, `Stop`.
  - **Помощник → служба:** `Hello{Contract, OcVersion}`, `SsoOpen{RequestId, Uri}`, `SsoResult{RequestId, Done|Continue|Failed}`, `AuthForm{RequestId, Title, Message, Fields[]}`, `ResolveHost`, `SessionObtained{ExpiresUtc}`, `Established{Luid, IpInfo}`, `IpInfoChanged`, `Stats{Rx, Tx}`, `Reconnecting`, `Log` (cookie вырезаются), `Terminated{Kind, Text}`.
  - `IpInfo = {Address, Netmask, Mtu, Dns[], Domains[], SplitDns[], SplitIncludes[], SplitExcludes[], ProxyPac}`.
- **`OcSession`** — поток помощника за интерфейсом `IOcLib` (для тестов `FakeOcLib`), `Native\LibOpenConnect.cs` (`LibraryImport`). Порядок вызовов:
  1. `obtain_cookie`;
  2. `make_cstp_connection`;
  3. `setup_dtls`;
  4. **`setup_tun_device(vpninfo, NULL, ifname)`** — без vpnc-скрипта;
  5. назначение адреса;
  6. `mainloop`.

  Смена `ip_info` ловится через `set_reconnected_handler` + `get_ip_info` → `IpInfoChanged`. Отмена идёт через `openconnect_setup_cmd_pipe` (на Windows это SOCKET — писать через `send`).
- **Сертификат сервера.** `validate_peer_cert` доверяет только системному хранилищу, TOFU нет.- **Webview-колбэк синхронный.** Поток библиотеки отправляет `SsoOpen` и в цикле получает `WebviewLoad`, вызывая `openconnect_webview_load_changed`: `-EAGAIN` значит продолжать, 0 — готово, иначе ошибка. Результат уходит в UI через `SsoResult`. Таймаут 5 мин, закрытие окна — `WebviewClosed`. `process_auth_form` устроен так же.
- **C-прослойка `native\ocshim\ocshim.c`** (MSYS2, около 150 строк):
  - вариативный колбэк прогресса (`vsnprintf`);
  - `override_getaddrinfo`: спросить у службы адрес через колбэк и вызвать настоящий `getaddrinfo(ip, AI_NUMERICHOST)`, чтобы библиотека освобождала свою память.

  Служба разрешает имя сама и до ответа открывает WFP и маршрут /32 к адресу шлюза.
- **Адрес и MTU** назначает помощник общим кодом `src\SplitVpn.Windows\Net\TunnelInterfaceConfig.cs`:
  - `CreateUnicastIpAddressEntry` **/32** (без подсетевого маршрута в обход маркера 3917);
  - `NlMtu` из `ip_info`;
  - IPv6 на интерфейсе выключен;
  - DNS на адаптере не прописывается.

### 3. Вход: SSO, формы, сертификат

- **Цепочка SSO:**
  1. Помощник отправляет `SsoOpen`, служба записывает `tunnel.SignIn`.
  2. Состояние остаётся `ConnectionState.PasswordRequired` (новое значение не вводится), признак SSO — `TunnelStatusDto.SignIn != null`.
  3. UI при опросе открывает `SignInWindow` (WebView2).
  4. На каждое `NavigationCompleted` главного фрейма UI отправляет `SsoNavigationRequest(ProfileId, RequestId, Uri, Cookies)` (секрет). Cookie берутся через `CoreWebView2CookieManager.GetCookiesAsync(<uri шлюза>)`, включая HttpOnly, — **только для хоста шлюза**.
  5. Служба пересылает `WebviewLoad` помощнику.
  6. Окно закрывается по `SsoResult` (`Done` или `Failed`, с текстом ошибки).
- **Помощник запускается**, только когда App может показать вход: по «Подключить», «Войти» (`BeginSignInRequest`) или по автоматическому запросу App (см. «Изменения после КТ0», п. 3). Без App туннель ждёт входа и не мешает остальным.
- **Cookie сеанса** не сохраняется: живёт только в памяти помощника (КТ0: перенос между процессами невозможен).
- **WebView2:** пакет `Microsoft.Web.WebView2`, данные в `%LOCALAPPDATA%\SplitVpn\WebView2` (постоянный профиль), только https. Нет Runtime — понятная ошибка.
- **Формы ASA** (группа, логин, пароль, второй фактор) — обобщённый WPF-диалог `SignInFormDialog` по `AuthForm.Fields{Name, Label, Kind: Text|Password|Select, Options}`.
  - Служба сначала заполняет форму сама: группа из профиля, `UserName`, пароль из секретов при `SavePassword`.
  - Ответ — `SubmitAuthFormRequest` (секрет).
- **Клиентский сертификат (v1)** — только хранилище **LocalMachine**. Отпечаток выбирается в редакторе, помощник от SYSTEM берёт ключ через GnuTLS `system:`-URL. Подсказка: «импортируйте PFX в хранилище компьютера». CurrentUser — v2: олицетворение на долгоживущем TLS с реконнектами ненадёжно.

### 4. PAC-прокси (применяет App)

- Флаг профиля `ApplyServerProxy`, **по умолчанию выключен**: PAC уводит браузерный трафик на корпоративный прокси мимо политики маршрутизации.
- **Применение.** App в сессии пользователя ставит WinINet `AUTO_PROXY_URL`, когда туннель поднят и `TunnelStatusDto.ServerNetworks.ProxyPac` задан, и оповещает систему `INTERNET_OPTION_SETTINGS_CHANGED`/`REFRESH`. Исходные значения сохраняются в `%LOCALAPPDATA%\SplitVpn\proxy-backup.json`.
- **Откат:** при статусе туннеля ≠ поднят, при выходе и при старте App. Если пользователь сам изменил прокси, не трогать. `recover-network.cmd` (сессия пользователя) снимает прокси из резервной копии.
- **Маршрутизация.** Хост PAC и хосты `PROXY` из скрипта должны попадать в сети сервера; иначе предупреждение в диагностике.
- **Ограничения** (записать в `LIMITATIONS.md`): App не запущен — прокси не ставится и не снимается до его запуска; Firefox и WinHTTP-приложения прокси не получают.

### 5. Политика, DNS, WFP

- **Политика.**
  - `PolicyInput.ServerNetworks[(RouteTarget, Cidrs)]` и `DecisionSource.ServerNetwork` — только пока туннель `Established`, без кэша. До входа 10.x остаётся `Local`, частные адреса в интернет не уходят.
  - Окрашивание после `SpecialRanges.Local`, до `OnLinkSet`.
  - Следом новый слой **`TunnelInfrastructure`**: адреса `VpnDns` и проекции всех туннелей, чтобы 10/8 AnyConnect не перехватил DNS или пир другого туннеля.
  - Итоговый приоритет: пользовательские правила < сети сервера < LAN on-link, loopback, инфраструктура туннелей, служебный DNS и серверы.
  - Пустой `SplitIncludes` значит сетей сервера нет: предупреждение в карточке, Default не захватывается. Split Exclude в v1 игнорируется.
- **DNS.**
  - В `BuildDomainRoutes` добавляются правила на время работы (в настройки не пишутся): суффиксы из `SplitDns`, иначе из `Domains` (без однословных вроде `local`) плюс хост PAC. Цель — цель карточки; явное пользовательское доменное правило побеждает.
  - **Эти правила только выбирают DNS-сервер** (флаг `PinAddresses = false` у `DomainRoute`): адреса не закрепляются, трафик идёт по политике.
  - `PinnedCidrs` всегда исключает `AllServerAddresses()`.
  - Для AnyConnect `TunnelDnsRoute`/`DomainDnsRoute` берут `tunnel.VpnDns = IpInfo.Dns` и игнорируют `UpstreamDns`.
  - `DnsAnchor` исключает AnyConnect.
  - Адреса `VpnDns` получают маршрут /32 на свой LUID.
  - «Tunnel all DNS» сознательно игнорируется — записать в `LIMITATIONS.md`.
- **WFP.** `FilterPlanBuilder.Transports`: `AnyConnect => TCP + UDP ServerPort`. Трафик туннеля проходит существующим фильтром по LUID; DNS-посредник через `IP_UNICAST_IF` (вес 12 выше DNS-стража).

### 6. Модель, IPC, UI, CLI

- **Модель (схема остаётся v3, изменения аддитивные):**
  - `VpnProtocol.AnyConnect` («Cisco AnyConnect»), `AuthMethod.GatewayForm`; ветки в `Name`/`Supports`/`TryParseServer` (`host[:port][/group]`)/`ConnectionKey`;
  - `ConnectionProfile.AnyConnect: AnyConnectSettings {Group, CertThumbprint, UseDtls = true, ApplyServerProxy = false, UserAgent, ServerNetworksTarget: RouteTarget?}`;
  - `SettingsValidator`: роль не Primary, не участник групп, не цель Default/Geo, `ServerNetworksTarget` не группа.
- **IPC** (`Messages.cs`): `ContractVersion = 4`; `BeginSignInRequest`, `CancelSignInRequest`, `SsoNavigationRequest`, `SubmitAuthFormRequest`; `TunnelStatusDto.SignIn`, `TunnelStatusDto.ServerNetworks` (сети, DNS, суффиксы, PAC, MTU, срок сеанса).
- **UI:**
  - `ConnectionSecurityViewModel`, редактор и `WizardViewModel`: протокол, группа, сертификат (LocalMachine), DTLS, прокси; роль без «Опорного»;
  - `HomeViewModel`: «Войти» у туннеля с `SignIn` или без cookie;
  - `SignInWindow`, `SignInFormDialog`, `ProxyApplier`;
  - `RoutingViewModel`: `CardKind.ServerNetworks`, неудаляемая, со сводкой; колонка AnyConnect не принимает Default и Geo;
  - `DiagnosticsViewModel` и отчёт: версии OpenConnect и Wintun, DTLS или TLS, MTU, срок сеанса; cookie никогда не выводится.
- **CLI:** `status`/`tunnels` показывают запрос входа.
- **NetworkRecovery:** новый шаг «завершить `SplitVpn.OpenConnect.exe`»; адаптер Wintun исчезает сам (КТ0).
- **LIMITATIONS.md:** одновременная работа с Cisco `vpnagent` не поддерживается.

### 7. Native-зависимости и лицензии

- **Манифест** `third_party\openconnect\manifest.json` (в git): архив OpenConnect 9.21 с SHA-256, пакеты-зависимости MSYS2 UCRT64, Wintun 0.14.1 — URL, SHA-256, версии, лицензии, ссылки на исходники.
- **Скрипт** `scripts\build-openconnect.sh` (черновик из КТ0): зависимости, проверка хеша архива, правка `compat.c`, сборка libopenconnect и `ocshim.dll`, замыкание DLL, результат в `third_party\openconnect\bin\` (в `.gitignore`). Архивы прикладываются к релизу.
- **Сборка установщика.** `scripts\build-installer.ps1` публикует `SplitVpn.OpenConnect`, DLL кладёт в `openconnect\`. Загрузка через `NativeLibrary.SetDllImportResolver`; WiX соберёт их автоматически (`Package.wxs:89`).
- **LGPL-2.1:** динамическая компоновка, заменяемые DLL, `licenses\` с полными текстами, ссылки на исходники и предложение исходников в `docs\THIRD-PARTY-NOTICES.txt`. Wintun — Prebuilt Binaries License. WebView2 Runtime уже есть в Windows 11.

## Переиспользуем

- `FrameCodec` и полиморфный JSON (`src\SplitVpn.Core\Ipc`).
- `SecretStore`/`ISecretOps`.
- Паттерн `PasswordRequired` → `ConnectWithPasswordAsync` → `SetPassword` (`Coordinator.Dial.cs`, `HomeViewModel.cs`, `Coordinator.Requests.cs`).
- `OnDialFinishedAsync` и поколения, `Backoff`, образец `RasErrorClassifier`.
- Фильтры «туннель недоступен» (`FilterPlan.cs:311-332`).
- `RouteOps.MarkerMetric` 3917, `DnsRestoreOutcome.ChangedByUser` (образец отката прокси).
- `FakeWorld`/`FakeInventory`.
- `scripts\elevated.ps1`, `failsafe.ps1`, `kt2-scenarios.ps1`.

## Порядок работ

| КТ | Содержание | Готово |
|---|---|---|
| **КТ0 Стенд** | Факт: `scripts\build-openconnect.sh`, `ocshim`, стенд `tools\OcSpike` (с правами администратора, окно WebView2 в том же процессе). Сначала сверить с исходниками OpenConnect: семантику webview (`-EAGAIN`, `acSamlv2Token`), `script_config_tun` при `NULL`, назначает ли `wintun.c` адрес сам, SOCKET у cmd pipe, `override_getaddrinfo`, `get_auth_expiration`. Затем на avpn.example.org: 1) SSO (**входит пользователь**); 2) нужен ли HostScan/CSD; 3) запрашивает ли ASA клиентский сертификат; 4) нет чужих маршрутов и DNS, адрес /32, трафик к 10.x по нашему маршруту; 5) DTLS при WFP-фильтрах dev-службы; 6) DNS 10.0.16.21, суффиксы, куда разрешается `avpn.example.org` и IdP; 7) адаптер Wintun после kill процесса; 8) `DETACH` и подъём по `{cookie, host}` из нового процесса. | Отчёт в `docs\PROTOTYPE-REPORT.md`: SSO пройден, ресурс 10.x открыт, DTLS активен, cookie переиспользован. **Стоп:** обязательный HostScan с проверками DAP (подделывать не будем); ASA не пускает OpenConnect; MinGW-сборка не работает с Wintun. **Запасной путь** при неудобном колбэке: свой aggregate-auth на C# (`sso-v2-login` → `acSamlv2Token` → webvpn-cookie → `set_cookie` + `make_cstp_connection`). |
| **КТ1 Native** | Манифест, хеши, `ocshim`, лицензии, NOTICES, публикация | Скрипт с нуля воспроизводит `bin\` по хешам; помощник из MSI-макета печатает `openconnect_get_version` |
| **КТ2 Ядро** | Модель, валидатор, политика (сети сервера, инфраструктура туннелей), `DomainRoute.PinAddresses`, `FilterPlan`, IPC v4, `HelperContract` | Тесты Core зелёные |
| **КТ3 Помощник** | `OcSession`, трубы, `TunnelInterfaceConfig`, `FakeOcLib` | Тесты помощника зелёные; dev-команда поднимает туннель через трубу |
| **КТ4 Служба** | `Coordinator.AnyConnect.cs`, `IsUp`/`Luid`, Job, `SystemAnyConnectOps`, DNS (якорь, суффиксы, исключение шлюза), остановка с блокировкой, `NetworkRecovery` | Тесты Service зелёные, **существующие RAS-тесты без правок** |
| **КТ5 Интерфейс** | Редактор, мастер, главная, `SignInWindow`, форма, `ProxyApplier`, карточка «Сети сервера», диагностика | `SplitVpn.exe --selftest` без ошибок привязок; UIA-снимки в обеих темах |
| **КТ6 Живая проверка** | `scripts\kt-ac-scenarios.ps1` плюс повтор сценариев SSTP | SSO → поднят; обрыв Wi-Fi → реконнект без SSO; kill помощника → 10.x заблокирован, повторный вход без ввода; стоп службы → 10.x заблокирован, старт → повторный вход; DTLS и DNS под WFP; Off → logout; PAC ставится и снимается; `recover` → нет процессов, маршрутов, прокси. **SSO проходит пользователь.** |
| **КТ7 Поставка** | MSI, обновление в подключённом состоянии, удаление, документы (`README`, `LIMITATIONS`, `VPN-PROTOCOLS.md`, `BUILD.md`, оговорка в `VPN-PROTOCOLS-PLAN.md`) | Обновление восстанавливает сеанс после повторного входа (без ввода при запомненном ADFS); `kt6-uninstall.ps1` возвращает исходный снимок сети |

Коммиты — локально на каждой КТ, тег `kt-ac-N` только на закрытой КТ. Перед `git add` — `scripts\normalize-eol.ps1`; в `.gitattributes` добавить `*.dll binary`.

## Тесты

- **Core.Tests:**
  - сети сервера перекрывают `Local` 10/8, но не on-link, инфраструктуру туннелей (DNS опорного в 10.x), служебный DNS и серверы;
  - пустой `SplitIncludes`;
  - транспорты AnyConnect в `FilterPlan`;
  - валидатор;
  - IPC v4 с редактированием секретов;
  - кадры `HelperContract`;
  - `TryParseServer` с `/group`;
  - настройки v3 с AnyConnect читаются и сохраняются.
- **Service.Tests:** `FakeAnyConnect : IAnyConnectOps` (сценарии `RequireSso`, `RequireForm`, `Establish`, `Drop`, `Crash`, `RejectCookie`, `Expire`). Проверки:
  - без запроса входа от App процесс не запускается;
  - SSO → маршруты 69 сетей на LUID, DNS /32, суффиксы → `VpnDns` без закрепления;
  - адрес шлюза не закрепляется;
  - `DnsAnchor` не AnyConnect;
  - падение помощника → блок диапазонов → запрос входа;
  - `RejectCookie` → запрос входа без повторов;
  - Off → Stop (BYE);
  - стоп службы → фильтры блокировки применены до Stop;
  - перенос карточки меняет цели.
- **SplitVpn.OpenConnect.Tests:** `OcSession` на `FakeOcLib` — цикл webview (`-EAGAIN`/0/ошибка), таймаут, отмена, форма, `ResolveHost`, cookie вырезаются из логов, Stop, пауза и возобновление mainloop.
- **App:** `ProxyApplier` на фейке WinINet — применение, откат, изменение пользователем.

## Риски

- **Корпоративная политика** может запрещать сторонние клиенты — решение пользователя.
- **HostScan** — стоп-критерий КТ0.
- **ASA требует сертификат из CurrentUser** → импорт в LocalMachine или v2.
- **IdP в `example.org` недоступен** через DNS-правило суффикса → проверить в КТ0, при необходимости исключить хост IdP.
- **Прослойку `ocshim` не собрать** → `verbose = -1` и без `override_getaddrinfo` (служба заранее пропускает все A-записи шлюза).
- **Недоступны зеркала MSYS2** → архивы из релиза, крайний случай — сборка из исходников.
- **Аварийное падение службы** — окно без защиты для сетей сервера (`LIMITATIONS.md`).

## Сквозная проверка

1. `dotnet build SplitVpn.slnx -c Release` без предупреждений; `dotnet test --solution SplitVpn.slnx -c Release`.
2. КТ0: отчёт стенда — адрес туннеля, DTLS, MTU, число сетей, пробы к 10.x (через AnyConnect) и к 1.1.1.1 (не через AnyConnect).
3. КТ6: все сценарии `kt-ac-scenarios.ps1` зелёные.
   - `check 10.0.16.21` показывает цель «через Офис», интерфейс Wintun.
   - `nslookup x.office.example.org` идёт через посредник на 10.0.16.21, `nslookup ya.ru` — нет.
   - `check avpn.example.org` — напрямую; публичный `www.example.org` — по политике, не в AnyConnect.
   - После «Отключить и восстановить интернет» и `recover-network.cmd` сеть в исходном состоянии.
4. КТ7: MSI поверх рабочей версии в подключённом состоянии (SSTP и AnyConnect), затем удаление — снимок сети совпадает с исходным.
