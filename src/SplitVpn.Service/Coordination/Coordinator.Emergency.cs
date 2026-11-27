using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Recovery;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Recovery;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Служба после экстренного отключения («пустая»). Флаг EmergencyOff в HKLM\Software\SplitVpn ставит команда
/// emergency-off, снимает emergency-on (она же перезапускает службу). Служба с флагом запускается — иначе установщик,
/// запускающий её при обновлении, сообщил бы об ошибке, — но ничего не применяет: ни настройки Wi-Fi Windows, ни
/// автоподключения, ни сверки, ни DNS-посредника, ни фоновой загрузки списков и обновлений. Канал управления работает и
/// сообщает об отключении в статусе; команды, которые меняли бы сеть, отклоняются с понятным текстом. Обновление
/// программы по команде пользователя (проверка, загрузка, установка) работает.
/// </summary>
public sealed partial class Coordinator
{
    private readonly EmergencyFlag? _emergency;

    /// <summary>Программа экстренно отключена: служба «пустая».</summary>
    internal bool EmergencyOff => _emergency is not null;

    /// <summary>
    /// Флаг при создании координатора. Сбой чтения — не «программа не отключена»: чтение повторяется (EmergencyRegistry.Read
    /// повторяет и сам), а не прочитался и повтор — служба запускается «пустой» (<see cref="EmergencyFlag.Unreadable"/>):
    /// включить отключённую программу хуже, чем остаться без VPN до перезапуска службы.
    /// </summary>
    private static EmergencyFlag? ReadEmergencyFlag(ServiceDependencies deps)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return deps.EmergencyFlag();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                if (attempt >= 3)
                {
                    deps.Logger.LogWarning(ex, "Флаг экстренного отключения не прочитан; служба запускается «пустой»");
                    return new EmergencyFlag(null, Unreadable: true);
                }

                Thread.Sleep(100);
            }
        }
    }

    /// <summary>
    /// Запуск «пустой» службы. Два действия всё же выполняются, оба идемпотентны: служба возвращает себе ручной запуск,
    /// если его сбросила установка обновления или исправление программы, и долечивает сеть после частично выполненного
    /// экстренного отключения (фильтры WFP, свои маршруты, DNS адаптеров).
    /// </summary>
    private void StartInert()
    {
        if (_emergency is { Unreadable: true })
        {
            Journal("Предупреждение", @"Отметка экстренного отключения (HKLM\Software\SplitVpn, EmergencyOff) не прочитана и после повторов: "
                + "служба на всякий случай запущена «пустой» и ничего не меняет в сети. Перезапустите службу или включите программу.");
        }

        Journal("Предупреждение", "Программа экстренно отключена"
            + (_emergency?.SinceUtc is { } since ? $" ({since.ToLocalTime():dd.MM.yyyy HH:mm})" : "")
            + ": служба запущена без защиты, VPN и DNS-посредника и ничего не меняет в сети. Включите программу, чтобы снова пользоваться VPN.");
        StartupStep("ручной запуск службы", () =>
        {
            if (_deps.EnsureManualStart() is { } changed)
            {
                Journal("Сведения", "Службе возвращён ручной запуск после экстренного отключения (" + changed + ").");
            }
        });
        // Только локальные файлы: статус показывает, какие списки и обновление есть, но в сеть служба не ходит.
        StartupStep("загрузка RU-базы", _geo.LoadActive);
        StartupStep("загрузка списка обхода", _bypass.LoadActive);
        StartupStep("состояние обновления программы", () => _update.StartUp(this));
        StartupStep("завершение оставшихся процессов движка SSH", () => _deps.SshTunnel.StopLeftovers());
        StartupStep("очистка сети после экстренного отключения", () =>
        {
            var problems = HealAfterEmergency();
            if (problems.Count > 0)
            {
                Journal("Ошибка", "Очистка сети после экстренного отключения выполнена не полностью: " + string.Join("; ", problems)
                    + $". Повтор через {(int)EmergencyHealRetryDelay.TotalSeconds} с.");
                ScheduleHealRetry(1);
            }
        });
        _started = true;
        RefreshReadSnapshot();
    }

    /// <summary>
    /// Повторы очистки «пустой» службы: при запуске после загрузки служба фильтрации (BFE) или стек сети могут быть ещё не
    /// готовы, а такт «пустой» службы ничего не делает — без повтора остатки ждали бы «Восстановить сеть» вручную.
    /// </summary>
    internal const int EmergencyHealRetries = 5;

    internal static readonly TimeSpan EmergencyHealRetryDelay = TimeSpan.FromSeconds(15);

    /// <summary>Повтор <paramref name="attempt"/> через <see cref="EmergencyHealRetryDelay"/> — в очереди актора, как остальная работа.</summary>
    private void ScheduleHealRetry(int attempt)
    {
        _ = Task.Delay(EmergencyHealRetryDelay, _deps.Time).ContinueWith(
            _ => TryEnqueue("EmergencyHealRetry", () =>
            {
                RetryHeal(attempt);
                return Task.CompletedTask;
            }),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private void RetryHeal(int attempt)
    {
        var problems = HealAfterEmergency();
        if (problems.Count == 0)
        {
            Journal("Сведения", $"Очистка сети после экстренного отключения выполнена при повторе {attempt}.");
        }
        else if (attempt < EmergencyHealRetries)
        {
            _deps.Logger.LogWarning("Очистка сети после экстренного отключения, повтор {Attempt}: {Problems}", attempt, string.Join("; ", problems));
            ScheduleHealRetry(attempt + 1);
        }
        else
        {
            Journal("Ошибка", $"Очистка сети после экстренного отключения не выполнена и после {attempt} повторов: " + string.Join("; ", problems)
                + ". Нажмите «Восстановить сеть» или перезагрузите компьютер.");
        }

        RefreshReadSnapshot();
    }

    /// <summary>
    /// Идемпотентная очистка: фильтры своего провайдера WFP, свои маршруты, DNS адаптеров по правилам остановленной службы
    /// (копия DNS, затем всё, что выглядит нашим без копии). Каждый шаг — отдельно. Ответ — что не получилось.
    /// </summary>
    internal List<string> HealAfterEmergency()
    {
        var problems = new List<string>();
        try
        {
            _deps.Wfp.RemoveAll();
            Facts.AppliedFilters.Clear();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            problems.Add("фильтры WFP: " + ex.Message);
        }

        try
        {
            var routes = _deps.Routes.Reconcile([]);
            Facts.AppliedRoutes = "";
            if (routes.Failed > 0)
            {
                problems.Add($"маршруты: не удалено {routes.Failed}");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            problems.Add("маршруты: " + ex.Message);
        }

        try
        {
            RestoreDnsStopped(problems);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            problems.Add("DNS: " + ex.Message);
        }

        return problems;
    }

    /// <summary>
    /// DNS из копии при остановленном посреднике: IPv6-список, который не вернулся (на адаптере остался ::1), сбрасывается на
    /// «автоматически»; копия адаптера, на котором уже не наш DNS, больше не нужна. Затем — адаптеры без копии.
    /// </summary>
    private void RestoreDnsStopped(List<string> problems)
    {
        var backups = _deps.DnsBackups.Load();
        var ourSuffixes = OrphanDns.OurSuffixes(backups.Values);
        foreach (var backup in backups.Values)
        {
            var guid = backup.InterfaceGuid;
            try
            {
                var outcome = _deps.Dns.Restore(guid, backup);
                if (outcome == DnsRestoreOutcome.Incomplete && !_deps.Dns.ResetToAutomatic(guid, v4: false, v6: true))
                {
                    problems.Add($"IPv6 DNS адаптера {guid} не восстановлены и не сброшены");
                    continue;
                }

                _deps.DnsBackups.Remove(guid);
            }
            catch (NativeCallException ex) when (ex.Code == 2)
            {
                // Адаптера сейчас нет: копия остаётся до его возвращения.
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                problems.Add($"DNS адаптера {guid}: {ex.Message}");
            }
        }

        ResetOrphanDns(serviceStopped: true, ourSuffixes, problems);
    }

    /// <summary>
    /// Адаптеры без копии DNS, на которых DNS выглядит нашим (<see cref="OrphanDns.Decide"/>), — на «автоматически».
    /// <paramref name="serviceStopped"/> = false — команда «Восстановить сеть» работающей службы: если свой посредник
    /// слушает порт 53, чужого резолвера на 127.0.0.1:53 быть не может; без посредника решает таблица UDP. «Пустая»
    /// служба (<paramref name="serviceStopped"/> = true) тоже смотрит таблицу: резолвер пользователя именно на
    /// 127.0.0.1:53 (или [::1]:53) — его DNS, а не наш остаток. Адаптер со статическим IPv4-адресом не сбрасывается:
    /// без DHCP он остался бы без DNS — в журнал идёт просьба указать DNS вручную.
    /// <paramref name="ourSuffixes"/> — суффиксы программы: список поиска только из них очищается (null — не трогать).
    /// </summary>
    private void ResetOrphanDns(bool serviceStopped, IReadOnlySet<string>? ourSuffixes, List<string> problems)
    {
        var backups = _deps.DnsBackups.Load();
        IReadOnlyList<Core.Net.AdapterCandidate> adapters;
        try
        {
            adapters = _deps.Inventory.Capture().Adapters;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            problems.Add("список адаптеров: " + ex.Message);
            return;
        }

        var listeners = new Lazy<LoopbackListeners>(() => _deps.DnsProxy.IsRunning ? default : _deps.LoopbackResolverListeners());
        foreach (var adapter in adapters.Where(a => !backups.ContainsKey(a.InterfaceGuid)))
        {
            try
            {
                string v4;
                try
                {
                    v4 = _deps.Dns.ReadNameServer(adapter.InterfaceGuid);
                }
                catch (NativeCallException)
                {
                    continue;
                }

                var v6 = _deps.Dns.ReadNameServerV6(adapter.InterfaceGuid);
                var looksOurs = InterfaceDnsOps.IsProxySet(v4) || (v6 is not null && InterfaceDnsOps.IsLoopback(v6));
                var reset = looksOurs ? OrphanDns.Decide(v4, v6, serviceStopped, listeners.Value, _deps.IsStaticIpv4(adapter.InterfaceGuid)) : default;
                if (reset.KeptStatic)
                {
                    Journal("Предупреждение", "DNS: " + OrphanDnsReset.StaticNote(adapter.Name, v4) + ".");
                }

                if (reset.Any)
                {
                    if (!_deps.Dns.ResetToAutomatic(adapter.InterfaceGuid, reset.V4, reset.V6))
                    {
                        problems.Add($"IPv6 DNS адаптера «{adapter.Name}» не сброшен");
                    }

                    Journal("Сведения", $"DNS адаптера «{adapter.Name}» без сохранённой копии («{v4}») сброшен на автоматический.");
                    _dnsFlushPending = true;
                }

                if (ourSuffixes is not null && OrphanDns.ShouldClearSearchList(_deps.Dns.ReadSearchList(adapter.InterfaceGuid), ourSuffixes))
                {
                    _deps.Dns.SetSearchList(adapter.InterfaceGuid, "");
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                problems.Add($"DNS адаптера «{adapter.Name}»: {ex.Message}");
            }
        }

        if (serviceStopped && _dnsFlushPending)
        {
            _dnsFlushPending = false;
            FlushDnsCacheSafely("очистка после экстренного отключения");
        }
    }

    /// <summary>
    /// Отказ «пустой» службы: команды, которые подключали бы, меняли сеть или ходили в интернет (дозвон, вход, проверка
    /// подключения, загрузка списков). Настройки, журнал, статус, диагностика и локальные действия со списками работают.
    /// «Восстановить сеть» не отказывается: она повторяет очистку. Проверка, загрузка и установка обновления по команде
    /// пользователя тоже работают: программу могли выключить из-за ошибки, которую исправляет обновление. Сама служба
    /// при этом обновления не проверяет и не загружает (такт «пустой» службы ничего не делает).
    /// </summary>
    private IpcResponse? RefuseWhileEmergencyOff(IpcRequest request) =>
        _emergency is not null && request is ConnectRequest or DisconnectRequest or SetProfileRoleRequest or SetTunnelPausedRequest
            or TestProfileRequest or BeginSignInRequest or SsoNavigationRequest or SubmitAuthFormRequest or GeoUpdateNowRequest
            ? IpcResponse.Failure(IpcErrorCodes.EmergencyOff, IpcErrorCodes.EmergencyOffMessage)
            : null;

    /// <summary>«Восстановить сеть» у «пустой» службы — повтор очистки.</summary>
    private IpcResponse RecoverWhileEmergencyOff()
    {
        var problems = HealAfterEmergency();
        return problems.Count == 0
            ? IpcResponse.Success(BuildStatus())
            : IpcResponse.Failure(IpcErrorCodes.RecoveryIncomplete, "Сеть возвращена не полностью: " + string.Join("; ", problems));
    }
}
