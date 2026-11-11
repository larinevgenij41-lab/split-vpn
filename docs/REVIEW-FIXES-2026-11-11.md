# Исправления ревью N01-N15

Версия 0.15.14. Все 15 замечаний исправлены; воспроизведения включены в штатные проекты тестов. Новых сценариев: Core 6, Service 14, App 2, всего 22. Два существующих варианта теста конфликта CNAME обновлены: второй несовместимый ответ отклоняется, а первый выданный маршрут сохраняется.

| Замечание | Решение | Регрессионный тест |
|---|---|---|
| N01 | ANY под закрепляемым правилом отклоняется; CNAME обрабатывается независимо от типа вопроса | AnyQueryMustNotReturnAddressWithoutRouteAcceptance |
| N02 | Вся цепочка CNAME резервируется атомарно с проверкой ёмкости | FullCanonicalTableMustRefuseUntrackedAlias; CanonicalChainCapacityIsAtomicAndCancellationFreesIt |
| N03 | Несовместимая цель отклоняется, включая незавершённый параллельный ответ | CanonicalSharedByTwoVpnsMustRefuseConflictingAlias; CanonicalReservationRejectsConflictBeforeFirstResponseCompletes |
| N04 | Совместимые владельцы имеют независимые сроки | SameTargetAliasMustKeepLongerLeaseFromSecondRule; CanonicalSameTargetOwnersKeepIndependentAcceptedLifetimes |
| N05 | Исходный снимок доски получается нормализацией отправленных настроек, а не повторным чтением | RoutingSaveMustNotAdoptUnseenExternalBaseline |
| N06 | Связи CNAME подтверждаются/отменяются по идентификатору ответа | RefusedAddressResponseMustNotLeaveCanonicalPolicy, два варианта; CanonicalRejectedRefreshPreservesOnlyPreviouslyAcceptedLifetime |
| N07 | В ответ передаётся оставшийся срок временного pin | TemporaryPinAnswerMustNotOutliveItsLease |
| N08 | Выбор локального суффикса выполняется до Block | MoreSpecificLocalSuffixMustOverrideBroadBlock |
| N09 | Поколение статуса отсекает старый poll; отложенное принудительное обновление выполняется | OldPollMustNotOverwriteCompletedDisconnect |
| N10 | RequestId проверяется до изменения разрешения на вход | Nov11_StaleCancelMustNotCancelNewSignInWaitingForHelperExit |
| N11 | Для каждого узла хранится ограниченный набор адресов за сеанс; DNS pin получает только разрешённые адреса | Nov11_RotatingDnsMustNotBypassGatewayAddressLimit |
| N12 | Отслеживается каждая успешная смена секрета, переподключение не подавляется соседней ошибкой | Nov11_PartialSecretWriteMustNotLeaveOldSession |
| N13 | Проверка версии предшествует всем веткам SubmitAsync | Nov11_IncompatibleOffQueueRequestMustBeRejected, три команды |
| N14 | 403 считается rate limit только с Retry-After или X-RateLimit-Remaining: 0 | ForbiddenCustomSourceMustTryIndependentMirror; существующий RateLimited_StopsAndReportsRetryAfter |
| N15 | Восстанавливается только принадлежащий программе PAC-бит, остальные текущие флаги сохраняются | ProxyRestoreMustPreserveUserAutoDetectChange |

Исходники новых тестов: `tests/SplitVpn.Core.Tests/ReviewNov11CoreTests.cs`, `tests/SplitVpn.Service.Tests/ReviewNov11DnsTests.cs`, `tests/SplitVpn.Service.Tests/ReviewNov11CoordinatorTests.cs`, `tests/SplitVpn.App.Tests/ReviewNov11AppTests.cs`.

При закреплении N12 уточнено воспроизведение: исходный тест использовал недопустимый для L2TP адрес с портом и останавливался на валидации. С корректным адресом тест отдельно проверен со старым условием переподключения: PSK удалён, пароль не сохранён, HangUps=0, старый сеанс остаётся. С исправлением старый сеанс разрывается.

Проверки выполняются с поддельными системными зависимостями, loopback DNS и STA-моделями WPF. Реальное подключение к VPN и локальная установка не входят в этот прогон. Подробные журналы находятся в `artifacts/review-2026-11-11/`.

Полный прогон `dotnet test --solution SplitVpn.slnx -c Release --no-restore`: 1460 успешно, 0 падений, 6 пропущено (SecretStoreTests в повышенном процессе), всего 1466.
