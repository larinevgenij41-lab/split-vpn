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
/// автоподключения, ни сверки, ни DNS-посредника, ни загрузки списков и обновлений. Канал управления работает и
/// сообщает об отключении в статусе; команды, которые меняли бы сеть, отклоняются с понятным текстом.
/// </summary>
public sealed partial class Coordinator
{
    private readonly EmergencyFlag? _emergency;

    /// <summary>Программа экстренно отключена: служба «пустая».</summary>
    internal bool EmergencyOff => _emergency is not null;

    private static EmergencyFlag? ReadEmergencyFlag(ServiceDependencies deps)
    {
        try
        {
            return deps.EmergencyFlag();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Флаг не прочитан: как раньше, служба работает обычно — иначе сбой чтения реестра выключал бы VPN.
            deps.Logger.LogWarning(ex, "Флаг экстренного отключения не прочитан; служба работает обычно");
            return null;
        }
    }

    /// <summary>
    /// Запуск «пустой» службы. Два действия всё же выполняются, оба идемпотентны: служба возвращает себе ручной запуск,
    /// если его сбросила установка обновления или исправление программы, и долечивает сеть после частично выполненного
    /// экстренного отключения (фильтры WFP, свои маршруты, DNS адаптеров).
    /// </summary>
    private void StartInert()
    {
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
                Journal("Ошибка", "Очистка сети после экстренного отключения выполнена не полностью: " + string.Join("; ", problems));
            }
        });
        _started = true;
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
    /// <paramref name="serviceStopped"/> = false — команда «Восстановить сеть» работающей службы: свой посредник ещё
    /// слушает порт 53, и тогда чужого резолвера на 127.0.0.1:53 быть не может; без посредника решает таблица UDP.
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

        var listeners = new Lazy<(bool V4, bool V6)>(() => serviceStopped || _deps.DnsProxy.IsRunning ? (false, false) : _deps.LoopbackResolverListeners());
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
                var reset = looksOurs ? OrphanDns.Decide(v4, v6, serviceStopped, listeners.Value.V4, listeners.Value.V6) : default;
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
    /// подключения, загрузка списков и обновлений). Настройки, журнал, статус, диагностика и локальные действия со
    /// списками работают. «Восстановить сеть» не отказывается: она повторяет очистку.
    /// </summary>
    private IpcResponse? RefuseWhileEmergencyOff(IpcRequest request) =>
        _emergency is not null && request is ConnectRequest or DisconnectRequest or SetProfileRoleRequest or SetTunnelPausedRequest
            or TestProfileRequest or BeginSignInRequest or SsoNavigationRequest or SubmitAuthFormRequest
            or GeoUpdateNowRequest or CheckUpdateRequest or DownloadUpdateRequest or InstallUpdateRequest
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
