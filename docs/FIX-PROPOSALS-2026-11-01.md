# SplitVpn - предложения по исправлению ошибок

Дата: 2026-11-01. Код: `D:/VPN`, HEAD `fde6954`. Документ содержит предложения, исходный код не изменён.

## Порядок работ

1. Секреты и чужие credentials: ID4, ID24, ID31, ID45, ID67. Централизовать очистку URL и диагностических вложений, исключить PBK из архива, связывать секрет с ID профиля до первого await. Проверять каждый entry архива и смену профиля во время Save.
2. Маршрутизация и DNS: ID1, ID2, ID5, ID10, ID11, ID12, ID26, ID29, ID30, ID66. Добавить IDNA и CNAME-связи, нормализовать хранение suffix, полную семантику cache key, поколение конфигурации после await, корректные REFUSED/NODATA, negative TTL и TCP transaction ID. Добавить тесты отдельных CNAME-запросов, Unicode, EDNS, смены правила и malformed ответов.
3. Состояние сети и AnyConnect: ID6, ID7, ID8, ID17, ID18, ID19, ID20, ID21, ID27, ID28, ID37, ID38, ID39, ID75, ID76, ID82, ID88. Повторять поиск адаптера, отклонять ambiguous LUID, сбрасывать исчезнувший adapter, настраивать Wintun после reconnect, передавать negotiated host/ports и gateway domain, ожидать завершение helper. Проверки на fake Windows слое плюс живые reconnect/redirect/DTLS.
4. Recovery и установка: ID3, ID70, ID71, ID72, ID73, ID77, ID78, ID81. Различать отсутствие службы и ошибку SCM, использовать реальные RAS entry names/phonebook, удалять failsafe только после успеха, запускать recovery до потенциально неуспешного MSI stop, сохранять чужой DNS, дожидаться прекращения фоновой работы и подтверждения RAS Gone. Прогнать failure injection и uninstall/recovery на тестовой машине.
5. Целостность настроек и секретов: ID13, ID14, ID40, ID62, ID65, ID69, ID84. Нормализовать объект до validation и сохранять его же, откатывать intent при ошибке записи, перехватывать numeric overflow, нормализовать Geo Skipped, карантировать нечитаемые DPAPI entries. Проверить null, overflow, locked files и чужую DPAPI scope.
6. Обновления: ID9, ID22, ID23, ID42, ID43, ID68, ID79. Отклонять unsolicited 304 и проверять freshness, восстанавливать прерванный Downloading, применять idle timeout к каждому read, обрабатывать быстрый выход msiexec, строить URL через path с сохранением query, передавать stopping token. Тесты подписи, restart, slow active download, early exit и cancellation.
7. IPC и асинхронный UI: ID33, ID35, ID41, ID46, ID47, ID57, ID58, ID59, ID60, ID61, ID86. Разделять ошибки write/read, ограничивать размеры моделей, ввести operation/edit generations и сериализацию whole-settings операций, закрывать stale sign-in, обрабатывать WebView2 ProcessFailed, запускать activation listener раньше. Проверки гонок и повторного входа.
8. Windows и ресурсы: ID15, ID16, ID32, ID36, ID63, ID64, ID74, ID80, ID83, ID85, ID87. Проверять результат IPv6 restore и PAC write, писать PBK атомарно, восстанавливать повреждённую Geo revision, валидировать folder/member Target, падать при ошибке ntldd, supervising DNS TCP accept. Тесты failure injection и повторного запуска loops.
9. Остальные функциональные ошибки: ID25, ID34, ID44, ID48, ID49, ID50, ID89. Строго разбирать CLI enum, маскировать JSON структурно, уведомлять menus об изменениях, очищать stale update details, откатывать failed profile order.
10. Доступность и формы: ID51, ID52, ID53, ID54, ID55, ID56. Добавить ScrollViewer и max height, live-region events, DynamicResource, focus navigation и Enter submit. ID56 сначала подтвердить screenshot на 640px с длинным target.

## Проверка

- Каждая работа получает регрессионный тест по сценарию соответствующей находки ниже.
- Общие команды: `dotnet build SplitVpn.slnx -c Release` и `dotnet test --solution SplitVpn.slnx -c Release`.
- Network/recovery/installer изменения проверяются на тестовой Windows среде с failure injection, не только fake objects.
- UI изменения проверяются selftest и screenshots на 640/1080 в Light/Dark, для accessibility дополнительно keyboard и Narrator.
- Покрытие документа: 89/89 ошибок и 16/16 UX-предложений.

---
tags: [сети, vpn, windows, ревью]
статус: зафиксировано
обновлено: 2026-10-30
---

# SplitVpn - аудит кода 2026-10-30

## Область и статус

- Код: `D:\VPN`, HEAD `fde6954d8e384dd3eeda5c1c96d9869a4ace584a`.
- Проверены DNS и маршрутизация, служба и IPC, Windows/WFP, AnyConnect, UI/CLI/обновления.
- Зафиксировано 25 находок: 9 уровня P1 и 16 уровня P2.
- Все находки подтверждены анализом текущих путей кода. Сценарии на живой службе, реальной сети и native VPN не запускались. Условия срабатывания, зависящие от Windows, отмечены отдельно.
- Исходники не менялись, рабочее дерево Git чистое.

## P1 - DNS и маршрутизация

### 1. CNAME-only ответ теряет цель исходного домена

- Доказательство: `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:600-608` возвращает ответ без A-записей, не сохраняя CNAME-связь. Поздний запрос канонического имени сопоставляется только с настроенными суффиксами в `DnsProxyServer.cs:519-529` и получает общий маршрут в `DnsProxyServer.cs:793-798`.
- Сценарий: `alias.example` назначен в VPN, upstream возвращает только `alias.example CNAME cdn.other.net`, затем клиент запрашивает `cdn.other.net A`.
- Последствие: каноническое имя не получает VPN-закрепление, трафик может пойти напрямую.
- Нарушен инвариант из `docs/DOMAIN-ROUTING-PLAN.md:38` и `:101`.

### 2. Unicode-правила не совпадают с IDNA-именами

- Доказательство: `src/SplitVpn.Core/Settings/SettingsSerializer.cs:319-323` только обрезает и переводит суффикс в нижний регистр. `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:1013-1025` устанавливает Unicode-суффикс, а `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:748-754` и `:801-806` сравнивают его напрямую с wire-именем.
- Проверенная семантика .NET: `Uri.CheckHostName("пример.рф")` возвращает `Dns`, IDNA-форма имени: `xn--e1afmkfd.xn--p1ai`.
- Последствие: правило для интернационализированного домена молча не применяется, возможен уход трафика по общему маршруту.

## P1 - служба и диагностика

### 3. Recovery принимает сбой запроса SCM за отсутствие службы

- Доказательство: `src/SplitVpn.Service/ServiceRecovery.cs:51-57` останавливает службу только при нулевом коде `sc query`. Любой другой результат, включая таймаут из `ServiceRecovery.cs:165-169`, пропускает остановку. Затем `ServiceRecovery.cs:59-81` выполняет восстановление и возвращает успех сетевого отчёта.
- Триггер: SCM недоступен, запрос превысил таймаут или отклонён по правам, но служба продолжает работать.
- Последствие: работающий актор может повторно применить удалённые маршруты, DNS и фильтры. При удалении `ServiceRecovery.cs:76-78` также может удалить данные работающей службы.

### 4. Диагностический ZIP включает PBK с IPsec PSK

- Доказательство: `src/SplitVpn.Windows/Operations/SystemOperations.cs:377-385` передаёт PSK в `RasPhonebook.SetPreSharedKey`. `src/SplitVpn.Windows/Ras/RasPhonebook.cs:195-204` сохраняет его через `RasSetCredentials(phonebook, ...)`. `src/SplitVpn.Service/Diagnostics/DiagnosticsCollector.cs:54-57` копирует `files/splitvpn.pbk` в архив.
- Сценарий: настроен L2TP/IPsec с PSK, затем собран диагностический архив.
- Последствие: credential-bearing файл выносится из защищённого каталога службы и может быть передан в поддержку. Это противоречит обещанию `src/SplitVpn.Core/Diagnostics/DiagnosticsArchive.cs:227` исключать пароли и токены.
- Ограничение проверки: точное представление и шифрование ключа Windows в PBK не исследовались, утечка открытого текста не утверждается.

## P1 - Windows и RAS

### 5. Поиск RAS-адаптера не повторяется

- Доказательство: `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:1278-1285` сохраняет подключение даже при `Adapter == null`. `Coordinator.Apply.cs:408-417` повторно ищет отсутствующий адаптер только для AnyConnect. `src/SplitVpn.Service/Coordination/Coordinator.Dial.cs:349-354` прекращает проверку при отсутствующем адаптере.
- Триггер: снимок IP Helper сразу после дозвона ещё не содержит PPP-адаптер или его адрес.
- Последствие: соединение считается существующим, но LUID, маршруты и WFP-разрешение не создаются. Автоматического восстановления нет.
- Условие гонки на Windows не воспроизводилось.

### 6. Одинаковые RAS-адреса привязывают туннели к одному адаптеру

- Доказательство: `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:1280-1285` выбирает первый адаптер только по `projection.ClientAddress`, без RAS handle или GUID записи.
- Триггер: два независимых RAS-сервера назначили клиентам одинаковый IPv4-адрес.
- Последствие: оба `TunnelFacts` получают один LUID. Маршруты и WFP-условия обоих профилей направляются в один интерфейс, второй туннель не может корректно нести назначенный трафик.
- Сценарий с двумя одинаковыми адресами на живом RAS не проверялся.

### 7. Исчезнувший адаптер остаётся в кеше как существующий

- Доказательство: `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:408-411` сохраняет старый адаптер через `?? tunnel.Adapter`, если его LUID отсутствует в новом снимке. `src/SplitVpn.Service/Coordination/TunnelFacts.cs:154-161` продолжает считать туннель поднятым.
- Триггер: PPP/Wintun исчез, а RAS ещё сообщает подключение.
- Последствие: создание маршрутов пропускается, обрыв не обнаруживается, повторный дозвон не начинается, состояние может оставаться `Connected`.
- Конкретная последовательность Windows, оставляющая RAS подключённым после исчезновения интерфейса, не воспроизводилась.

## P1 - AnyConnect

### 8. Reconnect не применяет новый адрес и MTU к Wintun

- Доказательство: единственная настройка интерфейса выполняется при первоначальном подключении в `src/SplitVpn.OpenConnect/OcSession.cs:203-205`. `OcSession.cs:377-381` при reconnect только отправляет новые сведения. `src/SplitVpn.Service/Coordination/Coordinator.AnyConnect.cs:174-177` обновляет политику без повторной настройки адаптера.
- Триггер: `openconnect_mainloop` переподключился, шлюз назначил другой IPv4 или MTU.
- Последствие: Wintun сохраняет прежние параметры, служба использует новые. Трафик и проверки туннеля могут перестать работать.
- Тест `tests/SplitVpn.Service.Tests/OpenConnect/OcSessionTests.cs:300-316` проверяет событие, но не настройку адаптера.

## P1 - обновления

### 9. Неподписанный HTTP 304 подавляет обновления

- Доказательство: `src/SplitVpn.Core/Update/ManifestDownloader.cs:133-135` принимает каждый 304, `ManifestDownloader.cs:70-72` возвращает его без зеркал, `src/SplitVpn.Service/Coordination/UpdateManager.cs:350-353` считает проверку успешной без подписи и проверки срока годности.
- Триггер: основной URL возвращает 304, в том числе когда клиент не отправлял `If-None-Match`.
- Последствие: повторяющийся ответ скрывает новые версии и обходит защиту `ExpiresUtc`. Это подавление обновлений, а не обход подписи пакета.

## P2 - DNS и маршрутизация

### 10. AAAA не заменяется NODATA для управляемых доменов

- `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:564-584` пересылает AAAA, а `DnsProxyServer.cs:600-603` возвращает ответ без изменений.
- Для dual-stack домена приложение может выбрать публичный IPv6, который глобальный WFP блокирует в `src/SplitVpn.Core/Protection/FilterPlan.cs:168`.
- Последствие: задержка или отказ вместо использования закреплённого IPv4. Утечка IPv6 не утверждается.

### 11. Block возвращает NXDOMAIN вместо REFUSED

- `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:522-527` вызывает `BuildEmptyResponse(query, rcode: 3)`. NXDOMAIN имеет код 3, REFUSED код 5.
- Последствие: приложение получает ложное сведение о несуществовании имени, возможно отрицательное кеширование.

### 12. Ключи DNS-кеша и in-flight не различают полную семантику запросов

- `src/SplitVpn.Core/Dns/DnsMessage.cs:119-122` сохраняет только CD, наличие EDNS и DO. `src/SplitVpn.Core/Dns/DnsCache.cs:22-23` и `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:667-669` не включают RD, EDNS Client Subnet, Cookies и NSID в ключ.
- Сценарий: два запроса одного имени имеют разные EDNS Client Subnet. Последовательный запрос получает чужой кеш, параллельные запросы объединяются.
- Последствие: возможен адрес для чужой подсети, ошибки CDN/split-horizon или проверки ответа.

## P2 - служба и состояние

### 13. `"servers": null` постоянно ломает сверку

- `src/SplitVpn.Service/Stores.cs:125-130` загружает состояние без нормализации null. `src/SplitVpn.Core/State/ConnectionState.cs:75` задаёт пустой список только при отсутствии свойства. `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:802-805` и `:812-814` разыменовывают `_state.Servers`.
- Триггер: допустимый JSON содержит `"servers": null`, активный профиль использует DNS-имя сервера.
- Последствие: повторяющийся `NullReferenceException`, partial-application retry без восстановления файла. Обычные Connect/Disconnect не устраняют null.

### 14. Intent применяется после ошибки его сохранения

- `src/SplitVpn.Service/Coordination/Coordinator.Requests.cs:575-577` сначала меняет `_state`, затем вызывает `SaveState`. `src/SplitVpn.Service/Coordination/Coordinator.Queue.cs:317-336` возвращает ошибку и планирует восстановление. `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:115-135` сохраняет новый intent в памяти и повторяет сверку.
- Триггер: `state.json` заблокирован, диск переполнен или доступ запрещён во время Connect/Disconnect/RecoverNetwork.
- Последствие: клиент получил ошибку, но сетевое изменение всё равно применяется. После перезапуска загружается прежний intent, возможен обратный эффект, включая повторное подключение VPN.

### 15. Ручное выключение verbose отменяется перезапуском после ошибки реестра

- `src/SplitVpn.Service/Diagnostics/VerboseMode.cs:101-117` выключает режим в памяти и вызывает `TrySave(null)`. `VerboseMode.cs:173-183` подавляет ошибку записи. `src/SplitVpn.Service/Coordination/Coordinator.Requests.cs:748-751` возвращает успех. `VerboseMode.cs:56-79` при запуске читает оставшийся срок.
- Триггер: удаление `VerboseUntilUtc` временно не удалось, служба перезапущена до прежнего срока.
- Последствие: подробное журналирование молча включается снова.

## P2 - Windows и DNS интерфейсов

### 16. Ошибка восстановления IPv6 DNS игнорируется, копия удаляется

- `src/SplitVpn.Windows/Dns/InterfaceDnsOps.cs:242-249` игнорирует Boolean от `TrySetIpv6NameServer` и всегда возвращает `Restored`. `InterfaceDnsOps.cs:153-165` превращает `NativeCallException` в `false`.
- `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:1093-1107` и `src/SplitVpn.Windows/Recovery/NetworkRecovery.cs:197-210` удаляют резервную копию после такого результата.
- Последствие: адаптер может сохранить `::1` без работающего посредника, исходные DNS уже не восстановить из удалённой копии.

### 17. On-link VPN-сервер маршрутизируется через default gateway

- `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:664-667` создаёт каждый серверный `/32` через `primary.DefaultGateway`, не проверяя `primary.OnLinkPrefixes`.
- Триггер: VPN-сервер находится в локальной подсети основного адаптера или сам является шлюзом.
- Последствие: `/32` перекрывает нормальный on-link маршрут. Роутер без hairpin может сделать сервер недоступным.
- Поведение зависит от маршрутизатора и принятия маршрута Windows, на живой сети не проверялось.

## P2 - AnyConnect

### 18. Отказ сертификата при reconnect неверно классифицируется

- `src/SplitVpn.OpenConnect/OcSession.cs:272-277` устанавливает `_certificateRejected`. Начальная классификация учитывает его в `OcSession.cs:237-247`, а `RunMainloop` в `OcSession.cs:219-227` не учитывает.
- `src/SplitVpn.Service/Coordination/Coordinator.AnyConnect.cs:324-351` блокирует только `CertificateRejected`, оставляя NetworkError/AuthRejected повторяемыми.
- Последствие: пользователь получает неверную ошибку и цикл входа вместо блокирующего отказа сертификата. Проверка сертификата при этом не обходится.

### 19. Зависший AnyConnect останавливает sequential dialing навсегда

- `src/SplitVpn.Service/Coordination/Coordinator.AnyConnect.cs:81-85` устанавливает `AnyConnectStartedUtc`, но не `DialStartedUtc`. `src/SplitVpn.Service/Coordination/Coordinator.Dial.cs:91-104` освобождает следующие профили через 15 секунд только по `DialStartedUtc`.
- Триггер: helper завис до SSO, AuthForm, Established или Terminated.
- Последствие: все следующие профили остаются без дозвона бессрочно.

### 20. Остановка службы не гарантирует 15 секунд graceful exit helper

- `src/SplitVpn.Service/Coordination/Coordinator.AnyConnect.cs:376-404` синхронно завершает остановку. `src/SplitVpn.Windows/OpenConnect/SystemAnyConnectOps.cs:181-214` запускает фактическое закрытие канала, ожидание и kill в неотслеживаемой задаче.
- `src/SplitVpn.Service/Program.cs:148-153` продолжает завершение службы. Job имеет `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` в `SystemAnyConnectOps.cs:120-122`.
- Последствие: выход службы может закрыть job и убить helper до BYE, серверная сессия останется до таймаута.

### 21. Gateway `domain` не попадает в SessionInfo

- Native layout содержит `Domain` в `src/SplitVpn.OpenConnect/Native/OcNative.cs:65`, но `src/SplitVpn.OpenConnect/NativeOcLib.cs:75-107` его не читает. `src/SplitVpn.Core/OpenConnect/HelperContract.cs:153-176` содержит только `SplitDns`.
- `src/SplitVpn.Service/Coordination/Coordinator.AnyConnect.cs:458-470` и `Coordinator.Apply.cs:951-957` используют только `SplitDns`.
- Триггер: шлюз передал `ip_info.domain`, но пустой `split_dns`.
- Последствие: корпоративные имена не направляются к DNS шлюза, short-name expansion не получает суффикс. Задокументированный fallback в `docs/ANYCONNECT-PLAN.md:181` не работает.

## P2 - обновления, диагностика и CLI

### 22. Перезапуск во время загрузки оставляет `Downloading`

- `src/SplitVpn.Service/Coordination/UpdateManager.cs:143` и `:341` сохраняют `Downloading`. `UpdateManager.cs:51-55` при запуске обрабатывает только установку и уборку. `_work` после запуска отсутствует.
- `src/SplitVpn.App/ViewModels/SimplePages.cs:821-824` блокирует Check/Download/Install/Skip. `UpdateManager.cs:74-76` не запускает плановое восстановление при `AutoCheck == false`.
- Последствие: при выключенной автопроверке обновление зависает бессрочно, иначе до следующей плановой проверки.

### 23. Idle timeout является общим таймаутом загрузки

- `src/SplitVpn.Core/Update/PackageDownloader.cs:120-121` один раз вызывает `CancelAfter` на источник. `PackageDownloader.cs:195-204` читает и пишет данные без продления срока.
- Триггер: загрузка длится больше 60 секунд, хотя данные непрерывно поступают.
- Последствие: медленное активное скачивание отменяется как зависшее. `src/SplitVpn.Service/Program.cs:120-123` подтверждает, что задуман именно предел отсутствия активности.

### 24. Диагностика и журналы могут содержать PAC URL с секретами

- `src/SplitVpn.Core/Diagnostics/ProxyApplier.cs:27` сохраняет исходный и применённый URL. `src/SplitVpn.Core/Diagnostics/DiagnosticsArchive.cs:25-30` включает `proxy-backup.json` без очистки. `src/SplitVpn.App/Services/ProxyService.cs:45` и `:53` журналирует полный URL.
- Триггер: PAC URL содержит логин, пароль или токен.
- Последствие: секрет попадает в архив или verbose-журнал. `src/SplitVpn.Core/Diagnostics/LogText.cs:6-9` уже описывает необходимость redaction URL credentials и query values.

### 25. Неизвестная роль CLI становится Primary

- `src/SplitVpn.Cli/ServiceCommands.cs:99` принимает результат `ParseRole`, а `ServiceCommands.cs:162-167` преобразует любое неизвестное значение в `Primary`.
- `ServiceCommands.cs:108-115` понижает прежний Primary и может изменить `DefaultTarget`.
- Сценарий: `profile set ... --role secndary`.
- Последствие: опечатка не отклоняется, а меняет роли и маршрутизацию.

## Проверка сборки и тестов

- `dotnet build SplitVpn.slnx -c Release`: успешно, 0 ошибок, 0 предупреждений.
- Первый `dotnet test --solution SplitVpn.slnx -c Release`: 1013 успешно, 4 пропущено, 2 ошибки доступа к временным файлам `GeoStore`.
- Повторный `dotnet test --solution SplitVpn.slnx -c Release --no-build`: 1015 успешно, 4 пропущено, 0 ошибок.
- Две ошибки первого прогона не воспроизвелись, причина не установлена. Они не отнесены к подтверждённым находкам.
- Пропущенные 4 теста `SecretStore` требуют неповышенного процесса.
- Найденные сценарии текущие тесты не покрывают. Реальные WFP/RAS, сетевые маршруты, служба, helper и native reconnect не проверялись.

## Рекомендуемый порядок исправления

1. Исключить PBK и секреты PAC из диагностики.
2. Закрыть обходы DNS-правил: CNAME и IDNA.
3. Исправить reconnect AnyConnect и восстановление RAS-адаптера.
4. Запретить неподписанный 304 и восстанавливать прерванные загрузки.
5. Исправить recovery SCM и целостность сохранения intent.
6. Перейти к остальным ошибкам P2 с регрессионными тестами на каждый сценарий.

## Связи

- [[SSTP клиент с разделением трафика]]
- [[SplitVpn - ревью диагностического архива]]
- [[SplitVpn - оптимизация DNS и сборки политики]]


## Второй проход - новые находки

- Добавлено 19 находок: 3 уровня P1, 14 уровня P2 и 2 уровня P3.
- Общий итог двух проходов: 44 находки, из них 12 уровня P1, 30 уровня P2 и 2 уровня P3.
- Все новые находки получены анализом кода на том же HEAD `fde6954`. Живые сценарии не запускались, повторы первого прохода исключены.

### 26. P1 - DNS-ответ можно вернуть после отзыва подтверждённого маршрута

- `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:611-625` проверяет конфигурацию только до `await RouteSink.ObserveAsync`, после успешного ожидания ответ возвращается без повторной проверки.
- `src/SplitVpn.Service/Coordination/Coordinator.Pinned.cs:95-100` имеет такой же промежуток между проверкой владельца и возвратом результата. Последующая сверка может удалить владельца в `Coordinator.Pinned.cs:257-263` и заменить DNS-конфигурацию в `Coordinator.Apply.cs:1067-1080`.
- Сценарий: старый ответ прошёл закрепление, затем домен изменён на Block или другую цель до возврата из `AnnounceAsync`.
- Последствие: клиент получает старый адрес уже после применения новой политики и очистки кеша службы. Точная межпоточная последовательность не воспроизводилась.

### 27. P2 - DNS-кеш переживает смену сети с теми же индексом и DNS-адресами

- Контекст кеша содержит только индекс интерфейса и upstream endpoints в `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:729-731`. Такая же идентичность используется в `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:1083-1091`.
- При их совпадении `Coordinator.Apply.cs:1069-1071` не очищает кеш, хотя смена адреса/шлюза вызывает сверку через `Fingerprint` в `Coordinator.Apply.cs:1391-1393`.
- Сценарий: тот же адаптер переходит между сетями с одинаковым DNS `192.168.1.1`, но разными внутренними зонами.
- Последствие: клиент получает адрес прежней сети, возможны обращения к неправильному внутреннему сервису и потеря связи.

### 28. P2 - Сети AnyConnect перекрывают обязательную link-scope классификацию

- `src/SplitVpn.Core/Policy/PolicyCompiler.cs:175-176` сначала красит `SpecialRanges.LinkScope` как Local, затем `PolicyCompiler.cs:178-186` перекрашивает диапазоны сетями шлюза.
- `src/SplitVpn.Core/Policy/SpecialRanges.cs:18-22` включает `169.254.0.0/16`, multicast и broadcast. Шлюз может передать такие split-include сети.
- Последствие: link-local или multicast классифицируются как VPN и направляются в корпоративный туннель вместо сохранения локального поведения.

### 29. P2 - NXDOMAIN с CNAME игнорирует SOA MINIMUM

- `src/SplitVpn.Core/Dns/DnsMessage.cs:133` считает ответ негативным только при `ANCOUNT == 0`. NXDOMAIN с CNAME имеет ненулевой ANCOUNT, поэтому SOA MINIMUM в `DnsMessage.cs:137-140` пропускается.
- `src/SplitVpn.Core/Dns/DnsCache.cs:121-137` использует полученный чрезмерный TTL.
- Пример: CNAME TTL 600 и SOA MINIMUM 60 дают отрицательный кеш на 600 секунд вместо 60.
- Последствие: новая запись может оставаться недоступной до ошибочного истечения негативного кеша.

### 30. P3 - TCP DNS принимает ответ с чужим transaction ID

- UDP проверяет ID в `src/SplitVpn.Windows/Dns/DnsForwarder.cs:61-64`, TCP в `DnsForwarder.cs:93-95` вызывает только `DnsMessage.Answers`.
- `src/SplitVpn.Core/Dns/DnsMessage.cs:276-285` проверяет QR, opcode и вопрос, но не сравнивает ID ответа и запроса.
- Последствие: malformed или вмешивающийся TCP upstream может вернуть ответ, который попадёт в кеш и доменное закрепление. Off-path UDP poisoning не утверждается.

### 31. P1 - Update state выносит токены mirror URL в диагностику

- `src/SplitVpn.Core/Update/UpdateSources.cs:52-70` сохраняет полный mirror URI. `src/SplitVpn.Service/Coordination/UpdateManager.cs:434-456` записывает `PackageUrls` через `u.ToString()`.
- `src/SplitVpn.Core/Update/UpdateState.cs:61` и `src/SplitVpn.Core/Update/UpdateStore.cs:45-50` сохраняют URL без redaction. `src/SplitVpn.Service/Diagnostics/DiagnosticsCollector.cs:57` включает этот state в ZIP.
- Триггер: HTTPS mirror содержит секрет в userinfo или query, проверка обновления успешно сохранила пакетные URL.
- Последствие: секрет оказывается в `files/update/state.json` диагностического архива. Sanitizing отдельного settings в `Coordinator.Requests.cs:782-784` эту копию не очищает.

### 32. P2 - Ошибка смены PAC оставляет старый VPN proxy после отключения

- `src/SplitVpn.Core/Diagnostics/ProxyApplier.cs:78-80` сохраняет `AppliedUrl = desiredUrl` до записи WinINet. При ошибке Windows сохраняет прежний PAC, а backup утверждает, что применён новый.
- `ProxyApplier.cs:66-70` позже считает mismatch пользовательским override, а `ProxyApplier.cs:83-93` пропускает восстановление и удаляет backup.
- `src/SplitVpn.App/Services/ProxyService.cs:50-54` подавляет ошибку записи, само исключение возможно в `ProxyService.cs:101-104`.
- Последствие: старый PAC A остаётся активным вне VPN, исходный proxy пользователя не восстанавливается.

### 33. P2 - IOException чтения ответа вызывает повтор уже выполненной команды

- `src/SplitVpn.Core/Ipc/IpcClient.cs:184-204` объединяет запись запроса и чтение ответа в один `try`, а `IpcClient.cs:206-209` одинаково оборачивает IOException обеих операций.
- `src/SplitVpn.App/Services/ServiceConnection.cs:283-285` считает любую такую ошибку недоставкой, затем `ServiceConnection.cs:123-136` повторяет команду.
- Триггер: служба выполнила команду, но канал сломался при чтении ответа с IOException вместо EOF.
- Последствие: неидемпотентная команда может выполниться дважды или вернуть ошибку повтора, например повторная подготовка установки встретит `Installing`.

### 34. P2 - Маскирование отчёта может сломать JSON

- `src/SplitVpn.Service/Coordination/Coordinator.Requests.cs:722-730` добавляет имена профилей и групп в literal secrets. `Coordinator.Requests.cs:731-732` учитывает escaping только backslash, не кавычек.
- `src/SplitVpn.Core/Diagnostics/Redactor.cs:12-15` выполняет сырой `string.Replace` по сериализованному JSON.
- `src/SplitVpn.Core/Settings/SettingsValidator.cs:312-317` разрешает кавычку в имени профиля.
- Триггер: имя профиля или группы содержит `"`, экспорт выполнен с маскированием.
- Последствие: заменяются структурные кавычки JSON, отчёт становится невалидным. Короткие имена также могут заменить схемные поля.

### 35. P2 - Допустимые настройки делают status больше лимита IPC

- `src/SplitVpn.Core/Settings/SettingsValidator.cs:312-317` не ограничивает длину имени профиля. Имя повторяется в `src/SplitVpn.Service/Coordination/Coordinator.cs:257-260` и `Coordinator.cs:305-309`.
- `src/SplitVpn.Core/Ipc/FrameCodec.cs:10-18` ограничивает кадр 2 MiB. `src/SplitVpn.Service/Ipc/IpcServer.cs:238-240` обрабатывает превышение как disconnect.
- Сценарий: активный профиль имеет имя около 1,1 млн ASCII-символов и назначен default route. SaveSettings укладывается в лимит, status с повторениями имени уже нет.
- Последствие: UI теряет IPC со службой, reconnect verification также не может получить status.

### 36. P2 - IKEv2 policy перезаписывает PBK неатомарно

- `src/SplitVpn.Windows/Ras/RasPhonebook.cs:39-65` читает всю телефонную книгу и напрямую перезаписывает её через `File.WriteAllLines`, без temp-файла и atomic replace.
- `src/SplitVpn.Windows/Operations/SystemOperations.cs:370-375` вызывает `RasPhonebook.Save` до своего `try`, поэтому ошибка policy rewrite не попадает в cleanup в `SystemOperations.cs:394-398`.
- Триггер: завершение процесса, питание, переполнение диска или I/O-ошибка во время записи IKEv2.
- Последствие: PBK всех профилей может остаться усечённой. Последующая сверка читает записи в `Coordinator.Apply.cs:299,310-318` и может упасть до пересоздания записей. Поведение RAS на каждом виде частичного файла не проверялось.

### 37. P1 - Cross-host redirect не даёт собрать SSO cookies

- `src/SplitVpn.OpenConnect/OcSession.cs:301-305` отправляет `GatewayHost()` исходного профиля, а не текущего OpenConnect host. `src/SplitVpn.App/Views/SignInWindow.xaml.cs:125-130` читает cookies только при совпадении page host с этим исходным именем.
- Bundled OpenConnect меняет `vpninfo->hostname` при cross-host redirect в `third_party/openconnect/work/openconnect-9.21/http.c:669-676`.
- Триггер: HTTPS redirect ведёт на другой gateway/cluster host, SSO token cookie принадлежит новому host.
- Последствие: браузер отправляет пустой список cookies, OpenConnect не получает SSO token, вход завершается по таймауту.

### 38. P2 - Public-only certificate блокирует использование исправного machine certificate

- `src/SplitVpn.OpenConnect/WindowsHelperSystem.cs:40-59` проверяет LocalMachine certificate перед копированием. `WindowsHelperSystem.cs:69-83` пропускает копирование при любом совпадении thumbprint в CurrentUser store, не проверяя `HasPrivateKey`.
- Триггер: в SYSTEM `CurrentUser\My` есть public-only или повреждённая запись с тем же thumbprint, а в `LocalMachine\My` исправный сертификат с ключом.
- Последствие: GnuTLS получает URL непригодной копии, клиентская аутентификация не проходит несмотря на исправный machine certificate.

### 39. P2 - Выбранная шлюзом auth group заменяется первой в списке

- При пустой группе профиля auto selection пропускается в `src/SplitVpn.OpenConnect/OcSession.cs:388-394`. Native `GroupSelection` читается в `src/SplitVpn.OpenConnect/NativeOcLib.cs:275-284`, но `AskUser()` в `OcSession.cs:445-454` его не применяет.
- UI выбирает первый элемент в `src/SplitVpn.App/Views/SignInFormWindow.cs:104-114`.
- Триггер: шлюз предлагает несколько групп и выбирает не первую, профиль группу не задаёт.
- Последствие: отправка формы меняет выбор шлюза на первую группу, возможен вход в неправильный контекст или отказ аутентификации.

### 40. P2 - Служба валидирует normalized copy, а сохраняет исходник

- `src/SplitVpn.Core/Settings/SettingsValidator.cs:16-20` валидирует `SettingsSerializer.Normalize(settings)`. `src/SplitVpn.Service/Coordination/Coordinator.Requests.cs:76-80` принимает результат, но `Coordinator.Requests.cs:89` сохраняет исходный `settings`, а `Coordinator.Requests.cs:117` назначает его в `_settings`.
- Триггер: IPC JSON содержит nullable section, например `"appUpdate": null`. C# non-nullable annotation не мешает JSON deserialization.
- Последствие: validation проходит на normalized copy, а null сохраняется. `src/SplitVpn.Service/Coordination/UpdateManager.cs:61` и другие потребители затем повторно разыменовывают null.

### 41. P2 - Поздняя загрузка Routing page стирает новые edits

- `src/SplitVpn.App/ViewModels/RoutingViewModel.cs:64` проверяет `Dirty` только до запуска async load. После await `RoutingViewModel.cs:97-107` очищает текущие folders/cards, а `RoutingViewModel.cs:133-140` перестраивает board и ставит `Dirty = false`.
- Пользователь может создать группу и изменить Dirty во время загрузки через `RoutingViewModel.cs:496-503`.
- Последствие: несохранённые изменения молча исчезают, Save отключается. Нужна generation check или повторная проверка Dirty после await.

### 42. P2 - Быстрый выход msiexec блокирует Installing на 15 минут

- `src/SplitVpn.Service/SystemSignals.cs:91-96` возвращает null, если PID уже исчез или недоступен. `src/SplitVpn.Service/Coordination/UpdateManager.cs:635-640` просто завершает watcher без результата.
- Deadline составляет 15 минут в `UpdateManager.cs:23-24`, fallback срабатывает только в `UpdateManager.cs:728-736`.
- Триггер: `msiexec` завершился до открытия PID, например сразу с ошибкой 1618.
- Последствие: Installing остаётся до deadline, затем показывается общий сбой вместо фактического результата.

### 43. P3 - Signature URL ломается при query в manifest mirror

- `src/SplitVpn.Core/Update/ManifestDownloader.cs:96-97` строит подпись как `url.AbsoluteUri + ".sig"`. `src/SplitVpn.Core/Update/UpdateSources.cs:52-69` и `src/SplitVpn.Core/Settings/SettingsValidator.cs:393` допускают HTTPS URL с query.
- Пример: `/update.json?token=value` превращается в `/update.json?token=value.sig` вместо `/update.json.sig?token=value`.
- Последствие: запрашивается неправильный URL подписи, исправное зеркало с SAS/token query не работает.

### 44. P2 - Неизвестный `--list` меняет Geo вместо отказа

- `src/SplitVpn.Cli/ServiceCommands.cs:300-301` распознаёт только точное lowercase `bypass`, остальное превращает в `Geo`. `ServiceCommands.cs:302-310` создаёт mutating request, а `ServiceCommands.cs:318-320` отправляет его.
- Сценарий: `geo rollback --list Bypass` или `geo update --list byapss`.
- Последствие: CLI молча обновляет, импортирует или откатывает неправильный список. Нужны case-insensitive parsing и отказ для неизвестных значений.

## Итог после второго прохода

- Всего зафиксировано 44 различные находки.
- Приоритет новых исправлений: секреты в update state, cross-host SSO, гонка возврата DNS после смены политики, неатомарная PBK, сохранение ненормализованных настроек и повтор выполненных IPC-команд.
- Код после второго прохода не менялся. Дополнительный прогон тестов не требовался для статического отчёта, результаты прежнего полного прогона сохранены выше.


## Третий проход - интерфейс

- По явному запросу пользователя отдельно проверены WPF MVVM, XAML, доступность, навигация, трей, окна входа и диалоги.
- Добавлено 17 уникальных находок: 2 уровня P1, 10 уровня P2 и 5 уровня P3. Совпадение двух проверок по высоте формы входа записано один раз.
- Общий итог трёх проходов: 61 находка, из них 14 уровня P1, 40 уровня P2 и 7 уровня P3.
- Все находки получены статическим анализом HEAD `fde6954`. UI automation и screenshots не запускались.

### 45. P1 - Пароль одного профиля можно сохранить под другим

- `src/SplitVpn.App/ViewModels/ConnectionsViewModel.cs:258-263` фиксирует только выбранный `item`, не его пароль. Выполнение приостанавливается на загрузке настроек в `ConnectionsViewModel.cs:270` и возможном подтверждении в `:292-295`.
- `ConnectionsViewModel.cs:42-50` при смене выбора заменяет общий `Password`. Запрос в `ConnectionsViewModel.cs:298-303` соединяет прежний `item.Id` с текущим общим паролем, затем очищает поле.
- Сценарий: начато сохранение профиля A, до чтения общего поля выбран профиль B и введён его пароль.
- Последствие: пароль B сохраняется под A и может быть отправлен серверу A. Очистка поля скрывает подмену до ошибки аутентификации. Гонка на живом UI не воспроизводилась.

### 46. P2 - Изменения во время Save ошибочно считаются сохранёнными

- `src/SplitVpn.App/ViewModels/SimplePages.cs:415-441` формирует и отправляет настройки, затем безусловно ставит `Dirty = false` в `SimplePages.cs:442`. Аналогично `SimplePages.cs:174-185`, `src/SplitVpn.App/ViewModels/RoutingViewModel.cs:559-562`, `src/SplitVpn.App/ViewModels/ConnectionsViewModel.cs:298-306`.
- Сценарий: пользователь нажал Save и изменил другое поле до ответа службы. Позднее изменение в запрос не вошло.
- Последствие: индикатор несохранённых изменений исчезает, хотя экран расходится с сохранённым состоянием. Последующая загрузка теряет правку.
- Нужна edit generation: Dirty очищается только при совпадении поколения на отправке и завершении.

### 47. P2 - Service-control операции сбрасывают pending друг друга

- `src/SplitVpn.App/ViewModels/ServiceHostViewModel.cs:152-160` очищает `_pending` до `await Main.RefreshAsync`, затем `ServiceHostViewModel.cs:162-166` повторно очищает его без проверки поколения.
- `ServiceHostViewModel.cs:140-148` использует это поле как единственную защиту от повторного входа.
- Сценарий: после завершения elevated process первой операции, но во время её refresh, запущена вторая. Первая завершается и очищает pending второй.
- Последствие: прогресс исчезает, кнопки активируются во время работающей операции, возможны дальнейшие перекрытия Start/Stop/Restart.

### 48. P2 - Move menus сохраняют удалённые цели и не показывают новые

- `src/SplitVpn.App/ViewModels/RoutingViewModel.cs:729` вычисляет `MoveTargets`, но не уведомляет об изменении. Колонки перестраиваются в `RoutingViewModel.cs:202-206`, группы меняются в `:496-518`.
- Аналогично `FolderTargets` в `RoutingViewModel.cs:819` не обновляется после изменений папок в `:370-400`.
- Последствие: новые цели отсутствуют, удалённые остаются доступными. Выбор удалённой группы приводит к отказу Save, первая папка может не открыть доступный пункт меню.

### 49. P3 - About сохраняет старые notes и install log после потери службы

- `src/SplitVpn.App/ViewModels/SimplePages.cs:799-809` при null status меняет только текст, flags команд и progress. Поля из `SimplePages.cs:812-818` не очищаются.
- `src/SplitVpn.App/Views/Pages.xaml:991-998` продолжает показывать notes, release link и install log по прежним flags.
- Последствие: при сообщении о неизвестном состоянии пользователь видит и может открыть устаревшие сведения как актуальные.

### 50. P3 - Неудачный reorder профилей не откатывается на экране

- `src/SplitVpn.App/ViewModels/ConnectionsViewModel.cs:179-183` меняет и нумерует `Profiles` до `SetProfileOrderRequest`. Ошибка обрабатывается общим `src/SplitVpn.App/ViewModels/PageViewModel.cs:57-63` без rollback/reload.
- `ConnectionsViewModel.cs:146-148` описывает экранный порядок как порядок службы и sequential dialing.
- Последствие: после отказа экран показывает несохранённый порядок как авторитетный, служба использует прежний. Dirty-индикатора нет.

### 51. P2 - Высокая форма входа делает кнопки недоступными

- `src/SplitVpn.App/Views/SignInFormWindow.cs:41-47` задаёт `SizeToContent.Height`, `ResizeMode.NoResize` и непрокручиваемый `StackPanel`. Поля и кнопки добавляются в `SignInFormWindow.cs:60-81`.
- Триггер: много полей, длинное сообщение шлюза или увеличенный текст делают окно выше work area.
- Последствие: без resize и scrollbar поля и кнопки "Войти"/"Отмена" могут оказаться вне доступной области, вход блокируется.

### 52. P2 - Динамические ошибки входа не вызывают live-region event

- `src/SplitVpn.App/Views/SignInWindow.xaml:30-31` и `src/SplitVpn.App/Views/SignInFormWindow.cs:70-71` задают только `AutomationProperties.LiveSetting`.
- Ошибки меняются после открытия в `SignInWindow.xaml.cs:151-155` и `SignInFormWindow.cs:157-159`, но `views:LiveRegion.Value` не используется.
- `src/SplitVpn.App/Views/Controls.cs:157-177` прямо указывает, что одного LiveSetting недостаточно, и реализует `LiveRegionChanged`.
- Последствие: screen reader может не объявить причину сбоя входа. Отсутствие события доказано, поведение конкретного диктора требует runtime-проверки.

### 53. P3 - Подзаголовок шлюза не меняет кисть при смене темы

- `src/SplitVpn.App/Views/SignInFormWindow.cs:117-123` один раз получает `TextFillColorSecondaryBrush` через `FindResource`, а не DynamicResource.
- Форма немодальна в `src/SplitVpn.App/Services/SignInCoordinator.cs:96-110`, поэтому тему можно сменить, пока она открыта.
- Последствие: подзаголовок сохраняет кисть прежней темы и может стать малоконтрастным.

### 54. P2 - Кнопка предупреждения "Ввести пароль" может быть видимым no-op

- `src/SplitVpn.App/ViewModels/HomeViewModel.cs:510-512` только присваивает `PasswordRequired = true`. Предупреждение создаётся для туннеля, уже требующего пароль, в `src/SplitVpn.Service/Coordination/Coordinator.cs:388-400`.
- Парольная карточка находится в `src/SplitVpn.App/Views/Pages.xaml:154-155`, но действие не переводит на неё фокус и не прокручивает страницу.
- Последствие: при уже видимой карточке нажатие ничего не меняет, фокус остаётся на предупреждении, пользователь не получает следующего понятного шага.

### 55. P3 - Enter не отправляет пароль на Home page

- `src/SplitVpn.App/Views/Pages.xaml:154-156` содержит поле пароля и кнопку "Подключить" без `IsDefault`, Enter KeyBinding или key handler.
- Последствие: после ввода пароля Enter ничего не делает, нужно отдельно перейти к кнопке или нажать мышь. Поведение отличается от остальных форм входа и wizard.

### 56. P2 - Бейджи результата проверки адреса могут обрезаться

- `src/SplitVpn.App/Views/Pages.xaml:719-724` размещает адрес, decision, target и необязательный badge "заблокировано сейчас" в одном горизонтальном StackPanel без wrapping, trimming, tooltip или horizontal scroll.
- `src/SplitVpn.App/Views/MainWindow.xaml:13` допускает ширину 640.
- Предполагаемый результат: при минимальной ширине или длинном имени профиля/группы поздние бейджи выходят за карточку и не читаются.
- Это visual hypothesis: требуется screenshot на минимальной ширине с blocked result и длинным target name.

### 57. P1 - Параллельные выключения из трея отменяют друг друга

- Tray вызывает `TurnOffProfileAsync` напрямую в `src/SplitVpn.App/Services/TrayIcon.cs:180-185`. Готовность меню в `TrayIcon.cs:116-123` не учитывает `Home.IsBusy`.
- `src/SplitVpn.App/ViewModels/PageViewModel.cs:46-64` не блокирует reentrancy, а `src/SplitVpn.App/App.xaml.cs:173-183` не сериализует confirmations.
- `src/SplitVpn.App/ViewModels/HomeViewModel.cs:464-485` читает settings, строит whole-settings update до confirmation и сохраняет его после.
- Сценарий: два secondary connections выключаются подряд, обе операции читают один snapshot до первого save.
- Последствие: второй save возвращает прежнюю роль первого подключения и связанные routes, молча отменяя уже подтверждённое действие. Гонка на живом UI не воспроизводилась.

### 58. P2 - Окна входа переживают потерю службы со stale request ID

- `src/SplitVpn.App/ViewModels/MainViewModel.cs:395-425` при сбое ставит Status null и вызывает `StatusUpdated`. `src/SplitVpn.App/Services/SignInCoordinator.cs:22-27` при null сразу возвращается, не закрывая окна.
- Триггер: открыт AnyConnect browser/form login, служба остановлена или упала.
- Последствие: окно остаётся открытым при сообщении о недоступной службе. После restart пользователь работает с устаревшим request и получает "Запрос входа устарел" вместо своевременного закрытия/замены окна.

### 59. P2 - Поздняя загрузка Settings/Protection перезаписывает ввод

- `src/SplitVpn.App/ViewModels/SimplePages.cs:130-158` проверяет Dirty только до await, затем заменяет все editable fields. Такой же путь в `SimplePages.cs:322-354`.
- Controls в `src/SplitVpn.App/Views/Pages.xaml:739-799` и `:804-880` не отключены через IsBusy.
- Сценарий: страница открыта при медленном ответе, пользователь меняет поле до завершения загрузки.
- Последствие: ответ молча заменяет ввод. Dirty может остаться установленным, хотя изменения исчезли; Save запишет уже возвращённые старые значения.

### 60. P2 - WebView2 ProcessFailed оставляет неработающее окно без объяснения

- Единственный handler в `src/SplitVpn.App/Views/SignInWindow.xaml.cs:83` пишет verbose log, но не вызывает `ShowProblem`, не закрывает окно и не пересоздаёт browser.
- Триггер: WebView2 browser/renderer process завершился из-за сбоя runtime или ресурсов во время SSO.
- Последствие: окно остаётся с непригодным browser и без видимой ошибки/recovery action. Служба продолжает ждать вход, пользователь должен сам закрыть окно и повторить попытку.

### 61. P3 - Ранний второй запуск исчезает до запуска activation listener

- Mutex захватывается в `src/SplitVpn.App/App.xaml.cs:64`, activation pipe запускается только после инициализации window/tray/view models в `App.xaml.cs:73-103`.
- Второй процесс ждёт подключение лишь одну секунду и молча завершается в `App.xaml.cs:65-70` и `:190-201`.
- Триггер: сразу после autostart с `--tray` пользователь запускает shortcut, пока скрытый первый процесс инициализируется.
- Последствие: второй процесс не активирует окно и завершается, первый остаётся скрытым. Для пользователя запуск ничего не сделал. Длительность гонки зависит от среды.

## Итог после интерфейсного прохода

- Всего зафиксирована 61 различная находка.
- Первыми в UI стоит исправить связывание пароля с профилем и сериализацию whole-settings операций из трея: обе ошибки могут изменить не тот профиль или отменить подтверждённое действие пользователя.
- Затем нужны generation-based guards для async load/save, корректная высота и прокрутка форм, обработка потери службы/WebView2 и уведомления для изменяющихся menus.


## Четвёртый проход - парсеры, безопасность, установщик и жизненный цикл

- Добавлено 20 уникальных находок: 7 уровня P1, 12 уровня P2 и 1 уровень P3.
- Два совпадения не записаны повторно: PAC URL уже учтён в ID24, malformed signature URL уже учтён в ID43. Для query-bearing package mirror заведена отдельная новая находка.
- Общий итог четырёх проходов: 81 находка, из них 21 уровня P1, 52 уровня P2 и 8 уровней P3.
- Анализ статический на HEAD `fde6954`. Установщик, recovery, native helper, служба и сеть не запускались.

### 62. P1 - Out-of-range schemaVersion обходит обработку ошибок настроек

- `src/SplitVpn.Core/Settings/SettingsSerializer.cs:33` вызывает `GetValue<int>()` до миграции. `SettingsSerializer.cs:60-67` перехватывает только JsonException и InvalidOperationException, не FormatException numeric overflow.
- `src/SplitVpn.Service/Stores.cs:34-35` вызывает parser без дополнительной границы.
- Триггер: синтаксически валидный JSON содержит `"schemaVersion":2147483648`.
- Последствие: вместо controlled unsupported/corrupt result возможно исключение при загрузке и остановка startup службы. Startup failure не запускался.

### 63. P2 - Идентичная загрузка не восстанавливает повреждённую активную Geo revision

- `src/SplitVpn.Service/Coordination/GeoManager.cs:49-59` оставляет `state.Active`, если revision отсутствует или невалидна, ActiveSet пуст. `GeoManager.cs:103-104` запрашивает полную загрузку.
- `src/SplitVpn.Core/Geo/GeoUpdateEvaluator.cs:48-52` возвращает Unchanged по совпадению hash с `state.Active` до проверки/восстановления файла.
- Триггер: активная revision X удалена или повреждена, upstream продолжает отдавать X.
- Последствие: каждое обновление сообщает Unchanged, база остаётся пустой, Geo/Bypass не применяются до смены upstream или ручного восстановления.

### 64. P2 - Цель папки и member rule расходятся между UI и политикой

- `src/SplitVpn.Core/Settings/SettingsValidator.cs:175-184` проверяет только существование FolderId, не равенство Target папки и правила.
- Policy использует собственный target правила в `src/SplitVpn.Core/Settings/SettingsSerializer.cs:303-308`. UI перезаписывает отображаемый target из папки в `src/SplitVpn.App/ViewModels/RoutingViewModel.cs:169-175`.
- Триггер: импортированные или повреждённые настройки содержат папку Block с member rule Direct.
- Последствие: UI показывает Block, служба применяет Direct, возможен ложный смысл защиты. Обратное сочетание скрывает фактическую блокировку.

### 65. P2 - `"skipped": null` ломает каждую Geo update evaluation

- `src/SplitVpn.Core/Geo/GeoStore.cs:85-100` возвращает десериализованный state без нормализации Skipped. `src/SplitVpn.Core/Geo/GeoUpdateEvaluator.cs:54` безусловно вызывает `state.Skipped.Contains(id)`.
- Триггер: валидный `geo/state.json` содержит `"active":null,"skipped":null`.
- Последствие: файл не помечается corrupt, manual/scheduled updates повторно падают с NullReferenceException до ручного восстановления state.

### 66. P2 - Local DNS suffix валидируется после normalize, а используется raw

- `src/SplitVpn.Core/Settings/SettingsValidator.cs:304-309` валидирует `NormalizeSuffix(s)`, но `src/SplitVpn.Core/Settings/SettingsSerializer.cs:84` сохраняет исходную строку.
- Proxy получает raw list в `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:975-979`. Matching `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:801-806` обрезает только dots, не whitespace.
- Триггер: сторонний IPC client или файл содержит `" home.arpa "` либо `"home.arpa. "`.
- Последствие: local query идёт не в intended local resolver, а в общий tunnel/direct upstream `DnsProxyServer.cs:793-798`. WPF editor сам trims input, поэтому триггер вне текущего редактора.

### 67. P1 - Активный SSO URL с секретами попадает в status.json диагностики

- `src/SplitVpn.Service/Coordination/Coordinator.AnyConnect.cs:138-146` копирует `open.Uri` в SignInPromptDto. `src/SplitVpn.Core/Ipc/Messages.cs:516-526` exposes URI, `src/SplitVpn.Service/Coordination/Coordinator.cs:328` включает prompt в tunnel status.
- `src/SplitVpn.Service/Coordination/Coordinator.Requests.cs:775-784` сериализует `status.json` напрямую; URL stripping применяется только к settings.
- `src/SplitVpn.Core/Diagnostics/LogText.cs:6-19` уже признаёт query credentials чувствительными, но здесь sanitizer не применён.
- Триггер: активный SSO prompt содержит SAML/token/RelayState в query, собрана диагностика.
- Последствие: секреты входа попадают в support archive. Наличие секрета зависит от шлюза, путь раскрытия подтверждён кодом.

### 68. P2 - Query-bearing package mirror не получает имя MSI

- `src/SplitVpn.Core/Update/UpdateSources.cs:52-69` дописывает filename только если полная mirror string заканчивается `/`.
- `https://host/packages/?key=x` не заканчивается `/`, поэтому остаётся directory URL и скачивается как package.
- `src/SplitVpn.Core/Settings/SettingsValidator.cs:393` принимает такой HTTPS mirror.
- Последствие: authenticated package mirror с query не работает. Это отдельная ошибка от malformed signature URL в ID43.

### 69. P2 - Undecryptable DPAPI entry обходит corrupt-state recovery

- `src/SplitVpn.Windows/Security/SecretStore.cs:649-673` проверяет JSON/base64, но не возможность DPAPI decrypt. `SecretStore.cs:59-80` вызывает Decode до try, `SecretStore.cs:83` считает наличие ключа наличием секрета.
- DPAPI failure становится NativeCallException в `SecretStore.cs:614-627`. Dial path читает password в `src/SplitVpn.Service/Coordination/Coordinator.Dial.cs:121` и `:145-153` без обработки этого случая.
- Legacy migration сохраняет undecryptable values в `SecretStore.cs:523-531`.
- Триггер: service data восстановлены на другой машине или под другой учётной записью.
- Последствие: Contains сообщает о пароле, дозвон падает при decrypt вместо missing-password/corrupt recovery, сверка повторяется до перезаписи секрета.

### 70. P1 - Fallback recovery не отключает текущие product RAS sessions

- `scripts/recover-network.ps1:35` отключает только имена `SplitVpn Proto` и `Раздельный VPN`.
- Текущие записи называются `ServicePaths.EntryName + " " + profile.Id.ToString("N")[..8]` в `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:305-307`, phonebook задаётся в `src/SplitVpn.Service/ServicePaths.cs:10,19`.
- Триггер: штатный recover завершился ошибкой, fallback запущен при активном текущем RAS session.
- Последствие: VPN остаётся подключённым, fallback сообщает о завершении. rasdial на живой сессии не вызывался.

### 71. P1 - Failsafe удаляет себя даже при неудачном recovery

- `scripts/failsafe.ps1:35-38` выполняет `& $exe recover` и сразу вызывает Done, не проверяя `$LASTEXITCODE`. Done удаляет scheduled task в `failsafe.ps1:29`.
- Триггер: recover вернул nonzero из-за WFP/DNS/RAS cleanup failure.
- Последствие: timed/startup failsafe triggers удалены, автоматического повтора не будет.
- Дополнительно connectivity probe `failsafe.ps1:31-34` не имеет exception handler. Если `ConnectAsync(...).Wait(5000)` бросит исключение, payload завершится до recover.

### 72. P2 - MSI stop failure не даёт запустить recovery custom action

- `installer/Package.wxs:98-100` задаёт ServiceControl stop с `Wait="yes"`. Recovery custom action назначен только `After="StopServices"` в `Package.wxs:47-50`.
- Триггер: служба не может завершить SCM stop, например зависла в native call.
- Последствие: MSI ожидает/завершается с ошибкой до `SplitVpn.Service.exe recover --uninstall`. Собственные timeout/forced-kill `src/SplitVpn.Service/ServiceRecovery.cs:133-154` не вызываются, сетевые изменения остаются.

### 73. P2 - Fallback recovery сбрасывает чужой loopback DNS resolver

- `scripts/recover-network.ps1:32-34` выбирает любой interface, чей DNS состоит только из `127.0.0.1`/`::1`, и сбрасывает его в DHCP без backup/ownership/listener проверки.
- Триггер: штатный recover не сработал, пользователь или другое приложение намеренно использует локальный resolver.
- Последствие: unrelated static DNS молча заменяется DHCP, нарушается гарантия сохранения manual DNS. Основной `src/SplitVpn.Windows/Recovery/NetworkRecovery.cs:120-125,167-183` имеет дополнительные проверки, fallback их обходит.

### 74. P2 - Ошибка ntldd молча отключает dependency closure validation

- `scripts/build-openconnect.sh:91-97` захватывает ntldd output с `|| true`, теряя exit status. Пустой `$actual` отключает undeclared-dependency loop.
- Триггер: ntldd упал, не разобрал DLL или вернул ошибку.
- Последствие: build создаёт bin и SHA256SUMS без полного dependency closure. Hash доказывает только совпадение с этим incomplete output; на clean machine DLL может не загрузиться. Последующий --version зависит от DLL build host.

### 75. P1 - Redirected CSTP port не попадает в WFP permit

- OpenConnect меняет hostname и port при redirect в `third_party/openconnect/work/openconnect-9.21/http.c:669-676`.
- `native/ocshim/ocshim.c:79-95` сохраняет service для getaddrinfo, но managed `ResolveHostEvent` содержит только host в `src/SplitVpn.Core/OpenConnect/HelperContract.cs:112`, и новый порт не передаётся в TunnelFacts.
- Service сохраняет profile port в `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:293-296`. WFP permit AnyConnect TCP/UDP только на нём в `src/SplitVpn.Core/Protection/FilterPlan.cs:354-363`.
- Триггер: gateway redirect на HTTPS URL с другим port.
- Последствие: адрес разрешается и маршрутизируется, новый TCP port блокируется WFP, authentication/reconnect не проходит.

### 76. P2 - Negotiated DTLS port игнорируется и остаётся заблокированным

- OpenConnect применяет DTLS `Port` option в `third_party/openconnect/work/openconnect-9.21/cstp.c:504-507`.
- `src/SplitVpn.OpenConnect/NativeOcLib.cs:75-107` получает dtlsOptions, но не читает порт. `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:296` сохраняет profile port, WFP UDP permit только на нём в `src/SplitVpn.Core/Protection/FilterPlan.cs:361-362`.
- Триггер: шлюз назначил DTLS port, отличный от profile port.
- Последствие: DTLS packets блокируются, сеанс остаётся на TLS без negotiated DTLS performance/reconnect benefits.

### 77. P1 - Recovery продолжается после сообщения watchdog об остановке

- `src/SplitVpn.Service/ServiceRecovery.cs:29-43` после `WaitAsync` timeout возвращает 1 и восстанавливает failure actions, но не ожидает и не завершает `work`.
- Тот же task продолжает `RunCoreAsync` в `ServiceRecovery.cs:47-81`, включая DeleteData в `:76-79`.
- Триггер: recover превысил 3 минуты плюс 15 секунд grace.
- Последствие: после сообщения "прервано" фоновая работа может продолжать менять routes/DNS/WFP/state и удалять данные при uninstall. Caller уже восстановил failure actions в `ServiceRecovery.cs:106-115`.

### 78. P1 - RAS hangup возвращает успех без подтверждения Gone

- `src/SplitVpn.Windows/Ras/RasClient.cs:165-169` завершает цикл через 15 секунд без final status check или timeout error.
- `src/SplitVpn.Service/Coordination/Coordinator.Apply.cs:1338-1355` считает завершение успешным, очищает `tunnel.Connection` и применяет routes как для разорванного туннеля.
- Триггер: RAS освобождает handle дольше 15 секунд.
- Последствие: активный туннель остаётся вне модели состояния службы, возможны неправильные маршруты и traffic exposure.

### 79. P2 - Scheduled update игнорирует service cancellation

- `src/SplitVpn.Service/Coordination/UpdateManager.cs:58` получает lifecycle token, но `UpdateManager.cs:86-88` запускает scheduled work с CancellationToken.None.
- Поздние continuations используют тот же token в `UpdateManager.cs:326-344` и `:510-511`. Queue loop завершается в `src/SplitVpn.Service/Coordination/Coordinator.Queue.cs:69-87`.
- Триггер: остановка службы во время manifest check или package download.
- Последствие: network/file work продолжается, continuation может ждать уже остановленную queue и выполнять поздние update-state writes после начала shutdown.

### 80. P2 - Одна TCP accept error навсегда отключает DNS-over-TCP

- `src/SplitVpn.Windows/Dns/DnsProxyServer.cs:884-895` выходит из accept loop при каждой SocketException. Loop запускается один раз в `DnsProxyServer.cs:216-219`, retry task завершается в `:253-281`.
- `listener.Tcp` остаётся non-null, UDP truncation продолжает рекламировать TCP в `DnsProxyServer.cs:159-166` и `:871`.
- Триггер: transient AcceptTcpClientAsync SocketException после успешного bind.
- Последствие: TCP больше никто не accept, клиенты по TC идут в неработающий listener до restart службы.

### 81. P3 - Timed-out ipconfig /flushdns остаётся работать и считается успешным

- `src/SplitVpn.Windows/Dns/InterfaceDnsOps.cs:268-271` игнорирует Boolean `WaitForExit(10_000)` и не завершает process. `src/SplitVpn.Windows/Recovery/NetworkRecovery.cs:50-54` считает отсутствие исключения успехом.
- Триггер: ipconfig не завершился за 10 секунд.
- Последствие: процесс остаётся, повторные DNS changes накапливают процессы, recovery не сообщает, что flush не подтверждён.

## Итог после четвёртого прохода

- Всего зафиксирована 81 различная находка.
- Наиболее срочные новые исправления: SSO secrets в diagnostics, failsafe и fallback recovery, redirected CSTP port, recovery watchdog и RAS hangup confirmation.
- Код не менялся. Живые installer/recovery/native scenarios остаются обязательной частью проверки будущих исправлений.


## Пятый проход - целостность данных и ресурсов

- Добавлено 8 уникальных находок: 6 уровня P2 и 2 уровня P3.
- Не записаны повторы: ранняя активация второго процесса уже учтена в ID61, многопроцессная ротация журнала из двух проверок объединена в ID85.
- Общий итог пяти проходов: 89 находок, из них 21 уровня P1, 58 уровня P2 и 10 уровней P3.
- Анализ статический на HEAD `fde6954`, живые гонки и сетевые условия не воспроизводились.

### 82. P2 - Export/import теряет cross-profile target для AnyConnect gateway networks

- Export создаёт новые profile IDs в `src/SplitVpn.App/ViewModels/ConnectionsViewModel.cs:342-345`, но не меняет `AnyConnectSettings.ServerNetworksTarget`.
- Import снова создаёт IDs в `src/SplitVpn.Core/Settings/ConnectionEdits.cs:85-104`, также без old-to-new mapping. При включении `WithUsableServerNetworks` сбрасывает stale target в null в `ConnectionEdits.cs:199-203`, что означает собственный AnyConnect tunnel.
- Триггер: gateway networks назначены в другой SSTP/IKEv2 profile, затем выполнен export/import и включён AnyConnect.
- Последствие: выбранный cross-profile route молча теряется, сети идут через AnyConnect вместо назначенного ранее туннеля.

### 83. P3 - Effective route metric переполняется и выбирает неправильный primary adapter

- `src/SplitVpn.Windows/Net/NetInventory.cs:154-155` складывает `defaultRoute.RouteMetric + interfaceMetric` как uint без checked/расширения типа.
- `src/SplitVpn.Core/Net/AdapterSelection.cs:80-88` сортирует адаптеры по полученному wrapped значению.
- Пример: interface metric `uint.MaxValue - 5` и route metric 10 дают 4 вместо очень большой стоимости, выигрывая у реальной metric 100.
- Последствие: direct traffic и VPN-server transport могут закрепиться за неправильным физическим путём. Extreme metric на живом адаптере не устанавливалась.

### 84. P2 - SafeFile.Load принимает некоторые inaccessible files за отсутствующие

- Контракт `src/SplitVpn.Core/Settings/JsonDefaults.cs:113-117` требует пропускать I/O и access errors наверх. `JsonDefaults.cs:124-127` сначала использует небросающий `File.Exists` и возвращает fallback при false.
- .NET `File.Exists` возвращает false для ряда invalid/inaccessible paths, поэтому `File.ReadAllText` в `JsonDefaults.cs:132` не вызывается и UnauthorizedAccessException не возникает.
- Триггер: файл существует, но attributes или parent directory недоступны caller.
- Последствие: существующее состояние может молча заменяться defaults вместо видимой ошибки прав. ACL-сценарий не создавался.

### 85. P2 - Многопроцессная ротация журнала теряет записи

- `src/SplitVpn.Core/Diagnostics/RollingTextLog.cs:7-9` объявляет поддержку нескольких writer processes, но `RollingTextLog.cs:24-32` имеет только process-local lock.
- `FileShare.Delete` позволяет rename при открытом append handle. `RollingTextLog.cs:48-50` перемещает и затем перезаписывает единственный `.1`.
- Сценарий: B открыл append, A переместил файл в `.1`, B записал через старый handle в `.1`, следующая ротация перезаписала `.1`.
- Последствие: часть diagnostic history удаляется. Гонка процессов не воспроизводилась.

### 86. P2 - Диагностика может блокировать shutdown IPC server и службы

- `src/SplitVpn.Service/Coordination/Coordinator.Queue.cs:259-263` запускает synchronous CollectDiagnostics через Task.Run. Token предотвращает scheduling, но не отменяет уже работающий delegate.
- `src/SplitVpn.Service/Ipc/IpcServer.cs:447-454` ожидает SubmitAsync в client task, а `IpcServer.cs:142` ждёт все client tasks при shutdown.
- Synchronous EventLog reads в `src/SplitVpn.Service/Diagnostics/SystemDiagnostics.cs:139-157` и file copies в `src/SplitVpn.Service/Diagnostics/DiagnosticsCollector.cs:191-200` не принимают cancellation.
- Триггер: сбор диагностики заблокирован в Event Log или file I/O во время остановки службы.
- Последствие: stop/restart/update ждут неотменяемую операцию до внешнего kill/timeout.

### 87. P2 - Service DNS permits не привязаны к primary adapter

- `src/SplitVpn.Core/Protection/FilterPlan.cs:366-382` создаёт high-priority permits по AppID, SYSTEM, remote DNS и port 53 без LocalInterfaceCondition для PrimaryLuid.
- WeightInfrastructure 12 выше RouteGuard 11 и ForeignInterface 6 в `FilterPlan.cs:122-134`. Tunnel DNS получает interface guard в `FilterPlan.cs:384-390`, service DNS нет.
- Триггер: configured/local DNS имеет более specific route через non-primary interface.
- Последствие: WFP разрешает запрос на неправильном интерфейсе, возможны утечка имени и split-horizon answer чужой зоны. `IP_UNICAST_IF` в `src/SplitVpn.Windows/Dns/UnicastSocket.cs:25-30` может вместо этого дать NetworkUnreachable, но permit остаётся неправильным. Пакетная проверка не выполнялась.

### 88. P3 - IPv6 остаётся включённым на Wintun и разрешён local-network filters

- `src/SplitVpn.Windows/Net/TunnelInterfaceConfig.cs:82-122` настраивает только IPv4/MTU/metric и не отключает IPv6 или `ms_tcpip6`. Вызова `openconnect_disable_ipv6` нет.
- WFP разрешает IPv6 neighbor discovery в `src/SplitVpn.Core/Protection/FilterPlan.cs:162-163`, а при LocalAccess также `fc00::/7`, `fe80::/10`, `ff00::/8` в `FilterPlan.cs:145-150,174-180`.
- Это противоречит intended config в `docs/ANYCONNECT-PLAN.md:144`.
- Последствие: Windows и приложения могут обмениваться IPv6 ND/link-local/ULA/multicast через Wintun вне IPv4-only routing model. Default binding и реальные packets не проверялись, уверенность средняя.

### 89. P2 - Одноразовый password file удаляется даже при ошибке чтения

- `src/SplitVpn.Cli/ServiceCommands.cs:559-567` вызывает `File.Delete(file)` в finally независимо от успеха `ReadAllTextAsync`. Тот же шаблон в `src/SplitVpn.Cli/Proto/CredsCommand.cs:86-93`.
- Триггер: transient sharing/antivirus/filesystem ошибка чтения, при разрешённом удалении.
- Последствие: команда завершается с ошибкой без передачи пароля, но единственная копия секрета уже удалена. Реальные password files не читались и не изменялись.

## Итог после пятого прохода

- Всего зафиксировано 89 различных находок.
- Новые приоритеты: сохранение cross-profile targets при import/export, отменяемая диагностика при shutdown, привязка service DNS к primary adapter, безопасное чтение одноразовых password files.
- Результаты также должны быть перенесены в `D:\VPN\docs\FIX-PROPOSALS-2026-11-01.md`.


---

---
tags: [сети, vpn, windows, интерфейс, ux]
статус: предложения
обновлено: 2026-10-30
---

# SplitVpn - улучшения интерфейса 2026-10-30

## Основание

- Рассмотрены текущие XAML/ViewModels и снимки `artifacts/ui-after/light` и `dark`, включая ширины 1080 и 640.
- Это предложения по UX, а не дополнение к списку из 61 подтверждённой ошибки. Исправление багов сохранения, гонок и недоступных controls остаётся предварительным условием.
- Главная цель: быстрее понять текущее состояние, безопасно выполнить действие и проверить результат без чтения длинных технических объяснений.

## Приоритет 1 - быстрые улучшения с высокой пользой

### 1. Показывать фактические маршруты на Главной

- Сейчас `src/SplitVpn.App/Views/Pages.xaml:76-77` всегда описывает одну фиксированную схему: российские адреса напрямую, остальные через VPN.
- Предложение: показывать текущие назначения RU, Default, Bypass и сетей шлюза с именами профилей/групп и ссылкой на доску. Данные уже загружаются в `src/SplitVpn.App/ViewModels/HomeViewModel.cs:163-182`.
- Польза: пользователь сразу видит реальную схему и не принимает устаревший текст за текущее состояние.
- Трудоёмкость: S.

### 2. Перестроить ошибки Главной вокруг действия

- На `viewport-640-HomePage.png` длинное объяснение CRL занимает экран, а шаги восстановления начинаются ниже сгиба.
- Предложение: сначала краткая суть, основное действие и "Что сделать". Сертификат, CRL, код ошибки и длинное объяснение перенести в раскрываемые "Технические подробности".
- Основание: `src/SplitVpn.App/Views/Pages.xaml:121-147`.
- Польза: восстановление без чтения сетевой диагностики, меньше тревожности и лишнего текста.
- Трудоёмкость: S.

### 3. Добавить контекстное действие в трей

- Сейчас `src/SplitVpn.App/Services/TrayIcon.cs:47-67,96-124` содержит общие Open/Connect/Disconnect.
- Предложение: одно действие по текущему состоянию: "Войти в ...", "Установить обновление ...", "Проверить адрес" или текущее recovery action. Переиспользовать mapping из `src/SplitVpn.App/ViewModels/HomeViewModel.cs:488-526`.
- Польза: частое восстановление выполняется одним щелчком без поиска нужной карточки.
- Трудоёмкость: S/M.

### 4. Добавить понятное восстановление службы в error banner

- Сейчас banner в `src/SplitVpn.App/Views/MainWindow.xaml:150-159` только сообщает об ошибке. Действия спрятаны в трёх icon-only кнопках footer `MainWindow.xaml:110-117`.
- Предложение: показывать "Запустить службу" или "Перезапустить" прямо в banner, Stop оставить среди дополнительных действий с текстовой подписью/tooltip.
- Польза: быстрый очевидный выход из сбоя, меньше случайных разрушительных действий.
- Трудоёмкость: S.

### 5. Закрепить Save и состояние изменений в длинных формах

- Save находится в конце форм `src/SplitVpn.App/Views/Pages.xaml:368-375`, `:591-596`, `:795-799`, `:875-880`. На первом экране 640px его нет.
- Предложение: sticky footer с "Сохранить", "Отменить изменения"/"Перечитать" и Dirty-индикатором; добавить Ctrl+S. После исправления async generation эта панель должна отражать только реально несохранённое состояние.
- Польза: не нужно искать Save прокруткой, всегда видно, есть ли несохранённые изменения.
- Трудоёмкость: M.

## Приоритет 2 - компоновка и основные сценарии

### 6. Сделать узкую Маршрутизацию одноколоночной

- `viewport-640-RoutingPage.png` показывает две тесные колонки, длинные русские имена и actions конкурируют за ширину.
- Сейчас `src/SplitVpn.App/Views/Pages.xaml:583-588` использует `EvenWrapPanel MinItemWidth="240"`.
- Предложение: при 640px одна полноширинная target column на строку либо список целей с details выбранной цели. Desktop board сохранить.
- Польза: читаемые названия, нормальные touch/keyboard targets, понятный порядок фокуса.
- Трудоёмкость: M.

### 7. Перейти к master-detail навигации в Подключениях на узком окне

- `viewport-640-ConnectionsPage.png` показывает список и toolbar, редактор начинается только внизу первого экрана.
- Предложение: выбор профиля открывает редактор отдельным view с кнопкой "Назад к подключениям". На desktop сохранить текущий master-detail рядом.
- Основание: `src/SplitVpn.App/Views/Pages.xaml:270-378`.
- Польза: пользователь сразу попадает к параметрам выбранного профиля и не ищет их под списком.
- Трудоёмкость: M.

### 8. Сократить постоянные инструкции через progressive disclosure

- На снимках заголовок и пояснения занимают около 100-200px до рабочих controls. Примеры: `src/SplitVpn.App/Views/Pages.xaml:577-580`, `:819-821`.
- Предложение: оставить одну строку сути страницы и field-specific hints, длинные концепции убрать в доступные Help expanders. На 640px использовать compact header.
- Польза: основные действия попадают на первый экран, опытным пользователям не нужно repeatedly читать одно и то же.
- Трудоёмкость: S.

### 9. Добавить проверку маршрута прямо из правила

- Сейчас правило создаётся/переносится на доске, затем его значение нужно вручную повторить на странице "Проверить адрес".
- Предложение: действие "Проверить" в card/folder, предзаполняющее Check Address; после Save предлагать проверить изменённые правила.
- Основание: `src/SplitVpn.App/ViewModels/RoutingViewModel.cs:242-303,420-494,531-564`, `src/SplitVpn.App/ViewModels/SimplePages.cs:28-44`.
- Польза: замыкается основной цикл "назначил маршрут - проверил результат" без навигации и повторного ввода.
- Трудоёмкость: M.

### 10. Добавить поиск и массовое назначение правил

- Доска показывает все cards, перемещение реализовано по одному в `src/SplitVpn.App/ViewModels/RoutingViewModel.cs:242-303`.
- Предложение: search/filter по домену, CIDR, комментарию и цели; массовое "Назначить выбранным" для отфильтрованных правил. Folders сохранить для постоянной организации.
- Польза: большие конфигурации не требуют десятков drag-and-drop операций.
- Трудоёмкость: M.

### 11. Сделать добавление профиля коротким guided flow

- Сейчас Add сразу создаёт пустой профиль в `src/SplitVpn.App/ViewModels/ConnectionsViewModel.cs:195-204` и открывает длинный редактор `src/SplitVpn.App/Views/Pages.xaml:332-376`.
- Предложение: шаблон протокола -> сервер -> способ входа -> роль -> тест -> сохранение. Полный редактор оставить под "Дополнительно". Переиспользовать подход `WizardViewModel`.
- Польза: меньше недопустимых сочетаний protocol/auth и меньше прокрутки при обычном создании профиля.
- Трудоёмкость: M.

### 12. Заменить одновременные окна входа единой очередью

- `src/SplitVpn.App/Services/SignInCoordinator.cs:30-33,96-110` открывает окно для каждого ожидающего туннеля. Home показывает только первый request в `src/SplitVpn.App/ViewModels/HomeViewModel.cs:334-340`.
- Предложение: одно активное окно с именем профиля, счётчиком оставшихся и следующим request после завершения. На Home показывать список ожидающих профилей.
- Польза: нет стопки окон и путаницы, к какому профилю относятся вводимые credentials.
- Трудоёмкость: M.

## Приоритет 3 - состояния, доступность и завершение операций

### 13. Ввести единые Empty/Loading/Unavailable компоненты

- `viewport-640-CheckAddressPage.png` почти пустой, Diagnostics empty state выглядит как незаполненная полоса.
- Предложение: empty state с следующим действием, skeleton/spinner при загрузке, отдельный unavailable state с Retry. Для Check Address добавить recent queries, для пустых Connections - Add Profile.
- Основание: `src/SplitVpn.App/Views/Pages.xaml:698-735`, `:923-957`.
- Польза: пустая страница не выглядит сломанной, следующий шаг очевиден.
- Трудоёмкость: M.

### 14. Стандартизировать keyboard focus и screen reader flow

- `src/SplitVpn.App/Views/MainWindow.xaml.cs:41-49` меняет модель и names, но не page focus. Заголовки страниц - обычные TextBlock.
- Предложение: фокус на heading после навигации, на error summary или первом invalid field после validation, возврат фокуса после dialogs/menus, однократное объявление Save result.
- Польза: предсказуемая работа с клавиатурой и Narrator, меньше повторного Tabbing.
- Трудоёмкость: M.

### 15. Усилить типографику и contrast scale

- `src/SplitVpn.App/Views/Styles.xaml:44-72` использует secondary text 13-14px, `src/SplitVpn.App/Views/Pages.xaml:420,495` до 11.5px. На 1440px explanations образуют слишком длинные строки.
- Предложение: essential hints не меньше 14px, усилить secondary contrast, ограничить текст примерно 70-85 символами в строке, включить system High Contrast в visual checks.
- Польза: читаемость при low vision и на больших/маленьких окнах.
- Трудоёмкость: M.

### 16. Объединить скачивание и установку обновления

- Сейчас Download и Install разделены в `src/SplitVpn.App/ViewModels/SimplePages.cs:848-898`, после установки пользователь должен сам открыть приложение через Start `SimplePages.cs:890-895`.
- Предложение: "Скачать и установить" одним действием с понятными фазами, автоматический повторный запуск UI после успешного MSI. Оставить раздельные advanced actions при необходимости.
- Польза: меньше промежуточных шагов, приложение не остаётся закрытым после успешного обновления.
- Трудоёмкость: L.

## Рекомендуемый порядок

1. Исправить подтверждённые баги сохранения, гонок и доступности controls.
2. Сделать фактическую routing summary, action-first errors и recovery action в трей/banner.
3. Добавить sticky Save и узкие layouts для Routing/Connections.
4. Замкнуть проверку правил и добавить guided profile creation.
5. Унифицировать состояния, focus, sign-in queue и update flow.

## Связи

- [[SSTP клиент с разделением трафика]]
- [[SplitVpn - аудит кода 2026-10-30]]
- [[SplitVpn - аккуратная компоновка интерфейса]]
