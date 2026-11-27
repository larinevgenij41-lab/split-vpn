# Исправления ревью от 2026-11-10

Версия 0.15.13 закрывает R01-R22 расширенного ревью версии 0.15.12 и прежнюю гонку CNAME. Ниже каждому замечанию сопоставлен регрессионный тест. Имена без пространства имён уникальны в решении.

| Замечание | Исправление | Регрессионный тест |
| --- | --- | --- |
| R01 | Ручное родительское правило имеет приоритет над split-DNS шлюза | `Review_GatewayMustNotBypassParentRule` (Block, Direct, Tunnel) |
| R02 | Явный локальный DNS выбран отдельно от DNS провайдера | `Review_ExplicitLocalDnsMustPrecedeProvider` |
| R03 | Неполное восстановление DNS даёт частичный сбой с повтором | `Review_IncompleteDnsRestoreMustReportPartialFailure` |
| R04 | Ключ незавершённого DNS-запроса включает экземпляр конфигурации | `Review_NewNetworkGenerationMustNotJoinOldDnsQuery` |
| R05 | TTL ответа только с CNAME ограничен сроком наследования правила | `Review_CnameOnlyTtlMustNotOutliveCanonicalLink` |
| R06 | Обновление CNAME не сокращает срок ранее выданной связи | `Review_CanonicalRefreshMustNotShortenOutstandingLease` |
| R07 | Сброс кеша ответов сохраняет действующие связи CNAME; цель выбирается по текущим правилам | `Review_UnrelatedConfigurationChangeMustKeepLiveCnamePolicy` |
| R08 | Каждая запись DNS стареет со своим TTL, включая additional | `Review_CacheMustNotExtendAdditionalRecordTtl` |
| R09 | Валидация запрещает общий ID профиля и группы | `Review_ProfileGroupCollisionMustNotRedirectExplicitTunnel` |
| R10 | Отпечаток сети включает метрику, префиксы и DNS, в том числе DHCP за loopback | `Review_DhcpDnsChangeMustTriggerImmediateReconcile` |
| R11 | После записи PSK сохраняется требование переподключения при ошибке разрыва RAS | `Review_PskHangupFailureMustRetryReconnect` |
| R12 | Результат установщика проверяется по поколению попытки и PID | `Review_OldInstallerExitMustNotCompleteNewAttempt` (0, 1602, неизвестный код) |
| R13 | Полный манифест того же пакета сохраняет счётчик неудачных загрузок | `Review_FullManifestMustNotResetDownloadRetryCounter` |
| R14 | Автозагрузка повторно проверяет актуальные настройки и сетевые ограничения | `Review_DisablingAutoDownloadDuringCheckMustBeRespected` |
| R15 | ETag манифеста привязан к URL источника | `Review_MirrorEtagMustNotBeSentToPrimary` |
| R16 | Null в package/urls возвращает ошибку валидации | `Review_MalformedManifestShouldReturnError` (2 варианта) |
| R17 | HTTP 304 без условия отвергается с переходом к зеркалу | `Review_GeoUnsolicited304MustTryNextMirror` |
| R18 | Формат и минимальные требования к списку сетей проверяются внутри перебора зеркал | `Review_GeoInvalidPrimaryMustTryHealthyMirror` |
| R19 | Незавершённая смена PAC сверяется с фактическим значением Windows | `Review_PendingProxyMustConvergeToDesiredUrl` |
| R20 | После сохранения снимаются только подтверждённые отметки правок | `SavedFieldDoesNotOverwriteAnotherWindow`, `EditsMadeDuringSaveRemainPending` (по 2 страницы) |
| R21 | После диалога подтверждения настройки перечитываются | `ProtectionConfirmationPreservesChangesFromAnotherWindow` |
| R22 | Завершение запроса не стирает новый PSK или новую отметку очистки | `NewPskEditSurvivesSaveCompletion` (2 варианта) |
| Прежняя гонка CNAME | Ответ старой политики отвергается до выдачи CNAME-only | `CnameOnlyResponseFromOldPolicyIsRefused` |

Тесты находятся в `tests/SplitVpn.Core.Tests/ComprehensiveReviewTests.cs`, `tests/SplitVpn.Service.Tests/ComprehensiveReviewTests.cs`, `tests/SplitVpn.Service.Tests/ComprehensiveDnsReviewTests.cs` и `tests/SplitVpn.App.Tests/SettingsSaveTests.cs`. Всего добавлено 32 сценария.

Проверки используют фейки, временные каталоги и UDP loopback. Тесты WPF работают с настоящими моделями страниц через изолированный IPC. Установленная служба и сетевые настройки Windows в этих сценариях не меняются. Релизный скрипт собирает решение, выполняет все три тестовых проекта, собирает MSI и проверяет версии и подпись манифеста.
