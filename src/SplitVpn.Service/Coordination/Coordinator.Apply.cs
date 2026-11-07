using Microsoft.Extensions.Logging;
using System.Globalization;
using System.Net;
using System.Runtime.ExceptionServices;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    private static readonly Ipv4Cidr[] HalfRoutes = [Ipv4Cidr.Parse("0.0.0.0/1"), Ipv4Cidr.Parse("128.0.0.0/1")];
    private static readonly uint[] FallbackUpstreams = [Ipv4.Parse("1.1.1.1"), Ipv4.Parse("8.8.8.8")];
    private static readonly TimeSpan ServerResolveInterval = TimeSpan.FromHours(1);

    /// <summary>Максимальная пауза между повторами сверки после неполного применения.</summary>
    private static readonly TimeSpan MaxPartialErrorDelay = TimeSpan.FromSeconds(60);

    /// <summary>Приводит систему к намерению пользователя. Каждый шаг идемпотентен.</summary>
    internal async Task ReconcileAsync(CancellationToken cancellationToken)
    {
        var step = "подготовка";
        Facts.PolicyApplied = false;
        Facts.ReconcilePending = false;
        try
        {
            Facts.LastFullReconcile = _deps.Time.GetUtcNow();
            MaintainAnyConnect();
            if (_state.ProtectionSuspended)
            {
                CancelServerResolutions();
                ClearPartialError();
                Facts.PolicyApplied = true;
                return;
            }

            if (_state.Intent == Intent.Off)
            {
                step = "снятие защиты";
                await TeardownAsync(cancellationToken);
                Facts.PolicyApplied = true;
            }
            else
            {
                step = "применение";
                await ApplyAsync(cancellationToken);
            }

            ClearPartialError();
        }
        catch (Exception ex) when (!IsShutdown(ex, cancellationToken))
        {
            // Ловится всё, кроме отмены при остановке службы: иначе неожиданная ошибка (разбор файла, NRE,
            // криптография) оставалась бы без текста в статусе, а сверка повторялась бы каждые 2 с.
            var expected = ex is NativeCallException or IOException or InvalidOperationException or UnauthorizedAccessException or System.Net.Sockets.SocketException;
            var message = expected
                ? $"Неполное применение: {step} — {ex.Message}"
                : $"Неполное применение: {step} — {ex.GetType().Name}: {ex.Message}";
            if (Facts.PartialError != message)
            {
                Journal("Ошибка", message);
            }

            if (!expected)
            {
                // Полный стек — только в журнал службы: в журнале событий он не нужен.
                _deps.Logger.LogError(ex, "Сверка: неожиданная ошибка на этапе «{Step}»", step);
            }

            Facts.PartialError = message;
            Facts.ForceProtection = true;
            SchedulePartialErrorRetry();
            if (ex is NativeCallException)
            {
                _deps.Wfp.Reopen();
            }
        }
        finally
        {
            ClearProgress();
        }
    }

    /// <summary>Остановка службы проходит насквозь: это не ошибка сверки.</summary>
    private static bool IsShutdown(Exception exception, CancellationToken cancellationToken) =>
        exception is OperationCanceledException && cancellationToken.IsCancellationRequested;

    private void ClearPartialError()
    {
        Facts.PartialError = null;
        Facts.PartialErrorDelay = TimeSpan.Zero;
        Facts.PartialErrorRetryAt = default;
    }

    /// <summary>Пауза до следующего повтора: 2, 4, 8 … 60 с. Считается от текущего времени.</summary>
    private void SchedulePartialErrorRetry()
    {
        var delay = Facts.PartialErrorDelay <= TimeSpan.Zero
            ? TimeSpan.FromSeconds(2)
            : TimeSpan.FromTicks(Math.Min(Facts.PartialErrorDelay.Ticks * 2, MaxPartialErrorDelay.Ticks));
        Facts.PartialErrorDelay = delay;
        Facts.PartialErrorRetryAt = _deps.Time.GetUtcNow() + delay;
    }

    /// <summary>
    /// Команда прервалась исключением вне сверки: всё проверяется заново, а сверка повторяется на ближайшем
    /// тике — без этого настройки остались бы записаны, а маршруты и фильтры не приведены к ним.
    /// </summary>
    internal void MarkInterruptedApply(string what, Exception exception, bool canceledByClient = false)
    {
        if (canceledByClient)
        {
            // Клиент отменил ожидание ответа: это не ошибка, но команда могла остановиться посреди применения —
            // полная сверка назначается на ближайший тик без записи «Ошибка» и без признака неполного применения.
            Facts.ForceProtection = true;
            Facts.ReconcilePending = true;
            return;
        }

        var message = $"Неполное применение: {what} — {exception.Message}";
        if (Facts.PartialError != message)
        {
            Journal("Ошибка", message);
        }

        Facts.PartialError = message;
        Facts.ForceProtection = true;
        Facts.PartialErrorRetryAt = _deps.Time.GetUtcNow();
    }

    private async Task ApplyAsync(CancellationToken cancellationToken)
    {
        // Сверка идёт в очереди актора: пока она длится, запросы интерфейса ждут. Долгие этапы видны в журнале.
        var timing = new ApplyTiming();
        SetProgress("Подготовка подключений", 5);
        await SyncTunnelsAsync(cancellationToken);
        timing.Mark("туннели");
        StartupProgress();

        // Подхват до построения политики: соединения, пережившие перезапуск службы, не дозваниваем заново.
        if (_state.Intent == Intent.Connected)
        {
            SetProgress("Подхват существующих VPN-сеансов", 10);
            await AdoptConnectionsAsync(cancellationToken);
            timing.Mark("подхват");
            StartupProgress();
        }

        SetProgress("Проверка сетевых адаптеров", 15);
        RefreshInventory();
        timing.Mark("снимок сети");
        PreloadServerAddresses();
        RefreshTunnelDnsAddresses();
        SetProgress("Подготовка правил разделения трафика", 20);
        CompilePolicy();
        timing.Mark("политика");
        SetProgress("Применение сетевой защиты (WFP)", 25);
        EnsureProtection();
        timing.Mark("WFP");
        StartupProgress();
        SetProgress("Применение маршрутов", 65);
        EnsureRoutes();
        CompletePins(applied: true);
        timing.Mark("маршруты");
        Facts.PolicyApplied = true;
        StartServerResolutions();

        // Сбой DNS (список суффиксов, посредник, чужая программа на 53 порту) не должен мешать подключению:
        // ошибка запоминается, дозвоны идут, и только потом сверка сообщает о неполном применении.
        ExceptionDispatchInfo? dnsFailure = null;
        try
        {
            SetProgress("Настройка DNS", 85);
            EnsureDns();
        }
        catch (Exception ex) when (!IsShutdown(ex, cancellationToken))
        {
            dnsFailure = ExceptionDispatchInfo.Capture(ex);
        }

        timing.Mark("DNS");
        // Полная сверка (фильтры, маршруты) выполнена — дальше только по изменениям.
        Facts.ForceProtection = false;
        if (_state.Intent == Intent.Connected)
        {
            SetProgress("Запуск и проверка VPN-подключений", 95);
            await EnsureDialsAsync(cancellationToken);
        }
        else
        {
            SetProgress("Завершение VPN-сеансов с сохранением защиты", 95);
            foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.HasSession).ToList())
            {
                await HangUpAsync(tunnel, "отключение VPN с сохранением защиты", cancellationToken);
            }
        }

        timing.Mark("дозвоны");
        timing.ReportIfSlow(_deps.Logger, "Сверка заняла");
        dnsFailure?.Throw();
    }

    private static readonly TimeSpan SlowApply = TimeSpan.FromSeconds(1);

    /// <summary>Во время первой сверки при запуске — промежуточный снимок: интерфейс видит туннели и базу до её конца.</summary>
    private void StartupProgress()
    {
        if (!_started)
        {
            RefreshReadSnapshot();
        }
    }

    /// <summary>Длительность этапов сверки для журнала; этапы короче 100 мс не перечисляются.</summary>
    private sealed class ApplyTiming
    {
        private readonly System.Diagnostics.Stopwatch _watch = System.Diagnostics.Stopwatch.StartNew();
        private readonly List<string> _steps = [];
        private TimeSpan _last;

        public TimeSpan Total => _watch.Elapsed;

        public void Mark(string step)
        {
            var now = _watch.Elapsed;
            if (now - _last >= TimeSpan.FromMilliseconds(100))
            {
                _steps.Add($"{step} {(int)(now - _last).TotalMilliseconds}");
            }

            _last = now;
        }

        public override string ToString() => string.Join(", ", _steps);

        /// <summary>Пишет разбивку по этапам, если всё действие заняло дольше SlowApply.</summary>
        public void ReportIfSlow(ILogger logger, string action)
        {
            if (Total > SlowApply)
            {
                logger.LogWarning("{Action} {Total} мс: {Steps}", action, (int)Total.TotalMilliseconds, this);
            }
            else
            {
                logger.LogDebug("{Action} {Total} мс: {Steps}", action, (int)Total.TotalMilliseconds, this);
            }
        }
    }

    /// <summary>Приводит набор туннелей к списку активных профилей и чистит лишние записи телефонной книги.</summary>
    private async Task SyncTunnelsAsync(CancellationToken cancellationToken)
    {
        var profiles = ActiveProfiles;
        foreach (var stale in Facts.Tunnels.Values.Where(t => profiles.All(p => p.Id != t.ProfileId)).ToList())
        {
            // Подключение выключили или удалили: соединение нужно разорвать, иначе оно останется поднятым.
            // Запись туннеля удаляется только после разрыва: иначе сбой RasHangUp оставил бы живой туннель,
            // о котором служба больше ничего не знает.
            try
            {
                if (stale.Connection is { } handle)
                {
                    await _deps.Ras.HangUpAsync(handle, cancellationToken);
                    stale.Connection = null;
                }

                StopAnyConnect(stale);
            }
            catch (Exception ex) when (ex is NativeCallException or InvalidOperationException or IOException or TimeoutException)
            {
                Journal("Ошибка", $"Не удалось отключить «{stale.Name}»: {ex.Message}. Повтор на следующей сверке.");
                continue;
            }

            Facts.Tunnels.Remove(stale.ProfileId);
            Journal("Сведения", $"Подключение «{stale.Name}» больше не поднимается.");
        }

        foreach (var profile in profiles)
        {
            if (!Facts.Tunnels.TryGetValue(profile.Id, out var tunnel))
            {
                tunnel = new TunnelFacts(profile.Id, EntryNameFor(profile)) { NextDialAt = _deps.Time.GetUtcNow() };
                Facts.Tunnels[profile.Id] = tunnel;
            }

            tunnel.Name = profile.Name;
            tunnel.Role = profile.Role;
            tunnel.Protocol = profile.Protocol;
            tunnel.ServerPort = VpnProtocols.TryParseServer(profile.Server, profile.Protocol, out var server) ? server.Port : ServerAddress.DefaultPort;
        }

        CleanupEntries();
        _deps.DnsProxy.RetainPins(profiles
            .Select(p => TryParseServer(p, out var server) && !server.IsIpLiteral ? server.Host : null)
            .OfType<string>());
    }

    /// <summary>Имя записи RAS: постоянное для профиля и уникальное среди подключений.</summary>
    internal static string EntryNameFor(ConnectionProfile profile) =>
        ServicePaths.EntryName + " " + profile.Id.ToString("N")[..8];

    /// <summary>Удаляет записи телефонной книги, которым больше не соответствует ни один профиль.</summary>
    private void CleanupEntries()
    {
        var wanted = Facts.Tunnels.Values.Select(t => t.EntryName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var busy = _deps.Ras.FindOwnConnections().Select(c => c.EntryName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in _deps.Ras.EntryNames().Where(e => !wanted.Contains(e) && !busy.Contains(e)))
        {
            _deps.Ras.DeleteEntry(entry);
            _deps.Logger.LogInformation("Удалена запись телефонной книги {Entry}", entry);
        }
    }

    private async Task TeardownAsync(CancellationToken cancellationToken)
    {
        CancelServerResolutions();
        var timing = new ApplyTiming();
        SetProgress("Проверка сети перед отключением", 5);
        RefreshInventory();
        timing.Mark("снимок сети");
        SetProgress("Завершение VPN-сеансов", 15);
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.HasSession).ToList())
        {
            await HangUpAsync(tunnel, "отключение VPN", cancellationToken);
        }

        // Пробный дозвон «Проверить профиль» идёт как раз при снятой защите и тоже виден среди своих
        // соединений: сверка не должна обрывать его на полпути — он разорвёт себя сам.
        foreach (var own in Facts.ProfileTestRunning ? [] : _deps.Ras.FindOwnConnections())
        {
            await _deps.Ras.HangUpAsync(own.Handle, cancellationToken);
        }

        timing.Mark("разрыв соединений");
        SetProgress("Удаление VPN-маршрутов", 40);
        if (Facts.AppliedRoutes.Length > 0 || Facts.ForceProtection)
        {
            ThrowOnRouteFailure(_deps.Routes.Reconcile([],
                (done, total) => ReportItems("Удаление VPN-маршрутов", done, total)), "снятие маршрутов");
            Facts.AppliedRoutes = "";
        }

        timing.Mark("маршруты");
        SetProgress("Восстановление обычного DNS", 65);
        RestoreAllDns();
        timing.Mark("DNS");
        SetProgress("Снятие сетевой защиты (WFP)", 75);
        if (Facts.AppliedFilters.Count > 0 || Facts.ForceProtection)
        {
            _deps.Wfp.RemoveAll((done, total) => ReportFilterItems("Удаление фильтров защиты", done, total));
            Facts.AppliedFilters.Clear();
        }

        timing.Mark("WFP");
        SetProgress("Завершение восстановления сети", 95);
        ClearPins();
        SetProxyConfiguration(new DnsProxyConfiguration { Mode = DnsProxyMode.Offline });

        // Записи телефонной книги живут только пока служба держит подключения: с ними уходят и ключи IPsec.
        if (!Facts.ProfileTestRunning && Facts.Tunnels.Values.All(t => !t.Dialing))
        {
            foreach (var entry in _deps.Ras.EntryNames())
            {
                _deps.Ras.DeleteEntry(entry);
            }

            foreach (var tunnel in Facts.Tunnels.Values)
            {
                tunnel.AppliedEntryServer = null;
            }
        }

        timing.Mark("посредник и записи RAS");
        timing.ReportIfSlow(_deps.Logger, "Снятие защиты заняло");
        Facts.ForceProtection = false;
    }

    private void RefreshInventory()
    {
        var snapshot = _deps.Inventory.Capture();
        RefreshTunnelAdapters(snapshot);
        var profiles = ActiveProfiles;
        var anchorProfile = _settings.PrimaryProfile ?? (profiles.Count > 0 ? profiles[0] : null);
        var pinned = anchorProfile?.PrimaryAdapter == AdapterSelection.Pinned ? anchorProfile.PinnedInterfaceGuid : null;
        var tunnelLuids = TunnelLuids();
        var result = PrimaryAdapterSelector.Select(
            snapshot.Adapters.Where(a => !tunnelLuids.Contains(a.Luid) && !IsTrusted(a)).ToList(),
            pinned,
            anchorProfile?.AllowFallbackWhenPinnedMissing ?? false,
            anchorProfile?.PinnedAdapterDescription);
        var pinnedMissing = result.Status == PrimaryAdapterStatus.PinnedMissing;
        if (pinnedMissing && !Facts.PinnedAdapterMissing)
        {
            // Пишется и при запуске службы, когда адаптера не было с самого начала: смены адаптера тогда нет.
            var available = snapshot.Adapters.Where(a => a.IsHardware && a.IsUp && a.DefaultGateway is not null).Select(a => $"«{a.Name}»").ToList();
            Journal("Ошибка", $"Закреплённый основной адаптер не найден (например, после сброса сети Windows): VPN не поднимается, трафик заблокирован."
                + (available.Count > 0 ? $" Доступны: {string.Join(", ", available)} - выберите адаптер заново в настройках подключения." : ""));
        }
        else if (result.Adapter?.Luid != Facts.Primary?.Luid && !pinnedMissing)
        {
            Journal("Сведения", result.Adapter is null
                ? "Основной адаптер недоступен: трафик заблокирован до появления сети."
                : $"Основной адаптер: {result.Adapter.Name}.");
        }

        Facts.PinnedAdapterMissing = pinnedMissing;
        if (anchorProfile is not null && pinned is not null && result.Adapter is { } chosen
            && result.Status is PrimaryAdapterStatus.Selected or PrimaryAdapterStatus.PinnedRebound)
        {
            RememberPinnedAdapter(anchorProfile, chosen, result.Status == PrimaryAdapterStatus.PinnedRebound);
        }

        Facts.Primary = result.Adapter;
        Facts.NetworkFingerprint = Fingerprint(snapshot);
        Facts.Conflicts = PrimaryAdapterSelector.PublicOnLinkConflicts(snapshot.Adapters.Where(a => !tunnelLuids.Contains(a.Luid) && !IsTrusted(a)))
            .Select(c => (c.Adapter.Name, c.Prefix)).ToList();
        RememberTrustedPrefixes(snapshot, tunnelLuids);
        _snapshot = snapshot;
    }

    /// <summary>
    /// Закрепление переживает сброс сети Windows: служба запоминает описание драйвера закреплённого адаптера,
    /// а если GUID сменился, переносит закрепление на найденный по описанию адаптер. Запоминается и переносится
    /// у всех профилей, закреплённых за тем же адаптером, одной записью: опорным может стать любой из них. Настройки
    /// пишутся, только когда что-то изменилось, то есть один раз после закрепления и один раз после смены GUID;
    /// неудавшаяся запись не повторяется, пока не изменятся настройки или адаптер.
    /// </summary>
    private void RememberPinnedAdapter(ConnectionProfile profile, AdapterCandidate adapter, bool rebound)
    {
        if (string.IsNullOrWhiteSpace(adapter.Description) || profile.PinnedInterfaceGuid is not { } pinned)
        {
            return;
        }

        bool Stale(ConnectionProfile p) =>
            p.PrimaryAdapter == AdapterSelection.Pinned && p.PinnedInterfaceGuid == pinned
            && (rebound || !string.Equals(p.PinnedAdapterDescription, adapter.Description, StringComparison.Ordinal));

        var stale = _settings.Profiles.Where(Stale).ToList();
        if (stale.Count == 0)
        {
            return;
        }

        var attempt = (_settings, adapter.InterfaceGuid, adapter.Description);
        if (_failedPinnedAdapterSave == attempt)
        {
            return;
        }

        var settings = _settings with
        {
            Profiles = _settings.Profiles
                .Select(p => Stale(p) ? p with { PinnedInterfaceGuid = adapter.InterfaceGuid, PinnedAdapterDescription = adapter.Description } : p)
                .ToList(),
        };
        try
        {
            _deps.Stores.SaveSettings(settings);
            _settings = settings;
            _failedPinnedAdapterSave = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Запись не удалась: адаптер всё равно выбран на эту сверку. Повтор - когда изменятся настройки или
            // адаптер, а не на каждой сверке: постоянный сбой диска иначе писал бы предупреждение раз в несколько секунд.
            _failedPinnedAdapterSave = attempt;
            _deps.Logger.LogWarning(ex, "Не удалось запомнить закреплённый адаптер «{Name}»", adapter.Name);
            return;
        }

        if (rebound)
        {
            Journal("Предупреждение", $"«{string.Join("», «", stale.Select(p => p.Name))}»: закреплённый адаптер сменил идентификатор (обычно после сброса сети Windows); закрепление перенесено на «{adapter.Name}» ({adapter.Description}).");
        }
    }

    /// <summary>Настройки и адаптер, для которых запись закреплённого адаптера не удалась.</summary>
    private (AppSettings Settings, Guid Adapter, string Description)? _failedPinnedAdapterSave;

    /// <summary>
    /// Интерфейсы туннелей по новому снимку. Исчезнувший интерфейс сбрасывается, а не остаётся из прежнего
    /// снимка: на него нельзя ставить маршруты, а RAS-туннель без интерфейса переподключается (см.
    /// <see cref="AdapterMissingTimeout"/>). Не найденный сразу после дозвона интерфейс ищется снова при каждой сверке.
    /// </summary>
    private void RefreshTunnelAdapters(NetSnapshot snapshot)
    {
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.Adapter is not null))
        {
            var current = snapshot.Adapters.FirstOrDefault(a => a.Luid == tunnel.Adapter!.Luid);
            if (current is null && tunnel.IsUp)
            {
                _deps.Logger.LogWarning("Туннель {Name}: интерфейс LUID {Luid} исчез из системы", tunnel.Name, tunnel.Adapter!.Luid);
            }

            tunnel.Adapter = current;
        }

        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.Adapter is null))
        {
            if (tunnel.AnyConnect is { Established: true } link)
            {
                // Адаптер Wintun мог не попасть в снимок в момент события Established: ищем его по LUID сеанса.
                tunnel.Adapter = snapshot.Adapters.FirstOrDefault(a => a.Luid == link.Luid);
            }
            else if (tunnel.Connection is { } handle)
            {
                // Интерфейс PPP мог не попасть в снимок сразу после дозвона.
                tunnel.Adapter = FindRasAdapter(tunnel, handle, snapshot);
                if (tunnel.Adapter is { } found)
                {
                    _deps.Logger.LogInformation("Туннель {Name}: интерфейс {Interface} LUID {Luid} найден после дозвона", tunnel.Name, found.Name, found.Luid);
                }
            }
        }
    }

    private AdapterCandidate? FindRasAdapter(TunnelFacts tunnel, RasConnectionHandle handle, NetSnapshot snapshot)
    {
        try
        {
            return FindRasAdapter(tunnel, _deps.Ras.GetProjection(handle).ClientAddress, snapshot);
        }
        catch (NativeCallException ex)
        {
            // Соединение уже разорвано: обрыв заметит проверка соединений.
            _deps.Logger.LogDebug(ex, "Туннель {Name}: адрес соединения RAS не получен", tunnel.Name);
            return null;
        }
    }

    /// <summary>
    /// Интерфейс RAS-соединения по выданному ему адресу. Интерфейсы других туннелей не рассматриваются.
    /// Два разных сервера могут выдать одинаковый адрес: тогда интерфейс узнаётся по имени — Windows называет
    /// интерфейс PPP именем записи телефонной книги. Не удалось отличить — интерфейс не выбирается, чтобы
    /// маршруты и разрешения двух туннелей не легли на один интерфейс. Аппаратный интерфейс (Wi-Fi, Ethernet)
    /// с тем же адресом туннелем не считается: иначе разрешение туннеля открыло бы весь трафик через него.
    /// </summary>
    private AdapterCandidate? FindRasAdapter(TunnelFacts tunnel, uint clientAddress, NetSnapshot snapshot)
    {
        if (clientAddress == 0)
        {
            return null;
        }

        var taken = Facts.Tunnels.Values.Where(t => t != tunnel).Select(t => t.Adapter?.Luid).OfType<ulong>().ToHashSet();
        var candidates = snapshot.Adapters
            .Where(a => a.Addresses.Contains(clientAddress) && !taken.Contains(a.Luid) && CanBeRasInterface(a))
            .ToList();
        if (candidates.Count <= 1)
        {
            return candidates.FirstOrDefault();
        }

        var named = candidates.Where(a => string.Equals(a.Name, tunnel.EntryName, StringComparison.OrdinalIgnoreCase)).ToList();
        if (named.Count == 1)
        {
            return named[0];
        }

        _deps.Logger.LogWarning("Туннель {Name}: адрес {Address} есть у нескольких интерфейсов ({Interfaces}), интерфейс не выбран",
            tunnel.Name, Ipv4.Format(clientAddress), string.Join(", ", candidates.Select(a => string.Create(CultureInfo.InvariantCulture, $"{a.Name} LUID {a.Luid}"))));
        return null;
    }

    /// <summary>Тип интерфейса PPP (IANA): такие Windows создаёт для соединений SSTP, L2TP, PPTP и IKEv2.</summary>
    private const uint PppInterfaceType = 23;

    /// <summary>Интерфейс RAS-соединения - PPP или во всяком случае не аппаратный адаптер.</summary>
    private static bool CanBeRasInterface(AdapterCandidate adapter) => adapter.IfType == PppInterfaceType || !adapter.IsHardware;

    private NetSnapshot? _snapshot;

    /// <summary>
    /// Последние сети доверенных адаптеров. Пока адаптер есть в системе, его сеть считается локальной,
    /// даже если он на время потерял адрес: иначе политика и фильтры перестраивались бы при каждом
    /// переподключении Radmin VPN, а его адреса на это время уходили бы по общим правилам.
    /// </summary>
    private readonly Dictionary<ulong, IReadOnlyList<Ipv4Cidr>> _trustedPrefixes = [];

    private bool IsTrusted(AdapterCandidate adapter) =>
        (_settings.TrustOverlayAdapters && adapter.IsOverlay) || _settings.TrustedAdapters.Contains(adapter.InterfaceGuid);

    private List<AdapterCandidate> TrustedAdapters()
    {
        var tunnelLuids = TunnelLuids();
        return (_snapshot?.Adapters ?? []).Where(a => !tunnelLuids.Contains(a.Luid) && a.Luid != Facts.Primary?.Luid && IsTrusted(a)).ToList();
    }

    private void RememberTrustedPrefixes(NetSnapshot snapshot, HashSet<ulong> tunnelLuids)
    {
        var trusted = snapshot.Adapters.Where(a => !tunnelLuids.Contains(a.Luid) && IsTrusted(a)).ToList();
        foreach (var luid in _trustedPrefixes.Keys.Where(l => !trusted.Exists(a => a.Luid == l)).ToList())
        {
            _trustedPrefixes.Remove(luid);
        }

        foreach (var adapter in trusted.Where(a => a.IsUp && a.OnLinkPrefixes.Count > 0))
        {
            _trustedPrefixes[adapter.Luid] = adapter.OnLinkPrefixes;
        }
    }

    private HashSet<ulong> TunnelLuids() =>
        Facts.Tunnels.Values.Select(t => t.Adapter?.Luid).OfType<ulong>().ToHashSet();

    private readonly PolicyCompilationCache _policyCache = new();
    private readonly FilterPlanCache _filterPlanCache = new();

    private void CompilePolicy()
    {
        PromotePins();
        // Неразобранные правила и адреса DNS пропускаются: о них — запись в журнале и предупреждение в состоянии.
        ReportSkippedSettings();
        var (rules, _) = SettingsSerializer.ParseRules(_settings.Rules);
        try
        {
            Facts.Policy = _policyCache.Compile(BuildPolicyInput(rules));
        }
        catch (PolicyIntegrityException ex)
        {
            _deps.Logger.LogError("Сборка политики: {Details}", ex.Details);
            throw;
        }
    }

    private PolicyInput BuildPolicyInput(IReadOnlyList<UserRule> rules) => new()
    {
        DefaultTarget = _settings.DefaultTarget,
        GeoTarget = _geo.HasBase ? _settings.GeoTarget : _settings.DefaultTarget,
        Geo = _geo.ActiveSet,
        BypassTarget = BypassTarget,
        Bypass = BypassForPolicy(),
        Rules = rules,
        Groups = ResolveGroups(),
        OnLinePrefixes = OnLinkPrefixes(),
        ServerAddresses = AllServerAddresses(),
        ServiceDnsAddresses = ServiceDnsAddresses(),
        ServerNetworks = GatewayNetworks(),
        TunnelHosts = TunnelHosts(),
        PinnedHosts = Facts.Pinned.Select(p => new PinnedHost(p.Key, p.Value.Target)).ToList(),
    };

    private List<uint> AllServerAddresses() =>
        Facts.Tunnels.Values.SelectMany(ServerAddressesOf).Distinct().ToList();

    /// <summary>Адреса сервера туннеля и узлы шлюза AnyConnect, на которые помощника перенаправили в сеансе.</summary>
    private static IEnumerable<uint> ServerAddressesOf(TunnelFacts tunnel) =>
        tunnel.ServerAddresses
            .Concat(tunnel.HasSession || tunnel.Dialing ? tunnel.SessionServerAddresses : [])
            .Concat(tunnel.AnyConnect is { } link ? link.ResolvedAddresses : [])
            .Distinct();

    /// <summary>Разбор адреса сервера профиля: у AnyConnect это адрес шлюза (https-ссылка, хост/группа).</summary>
    private static bool TryParseServer(ConnectionProfile? profile, out ServerAddress server)
    {
        if (profile?.Protocol == VpnProtocol.AnyConnect)
        {
            return VpnProtocols.TryParseServer(profile.Server, profile.Protocol, out server);
        }

        return ServerAddress.TryParse(profile?.Server, out server);
    }

    private List<Ipv4Cidr> OnLinkPrefixes()
    {
        var tunnelLuids = TunnelLuids();
        return (_snapshot?.Adapters ?? []).Where(a => a.IsUp && !tunnelLuids.Contains(a.Luid))
            .SelectMany(a => a.OnLinkPrefixes)
            .Concat(_trustedPrefixes.Values.SelectMany(p => p))
            .Where(p => p.PrefixLength >= PolicyCompiler.MinOnLinkPrefix)
            .Distinct()
            .ToList();
    }

    /// <summary>Исходный DNS основного адаптера (до нашего loopback) и DNS локальной сети.</summary>
    private List<uint> ServiceDnsAddresses()
    {
        var result = new List<uint>();
        if (Facts.Primary is { } primary)
        {
            var backup = _deps.DnsBackups.Load().GetValueOrDefault(primary.InterfaceGuid);
            var configured = ParseAddresses(backup?.NameServerV4 ?? "");
            result.AddRange(configured.Count > 0 ? configured : _deps.Inventory.DhcpDnsServers(primary.InterfaceGuid));
        }

        if (Ipv4.TryParse(_settings.LocalDnsServer, out var local))
        {
            result.Add(local);
        }

        return result.Distinct().ToList();
    }

    private ProtectionInputs ProtectionInputs() => new()
    {
        Policy = Facts.Policy!,
        LocalAccess = _settings.LocalAccess,
        OutageMode = _settings.OutageMode,
        Intent = _state.Intent,
        PrimaryLuid = Facts.Primary?.Luid,
        Tunnels = TunnelInputs(),
        ServiceDnsAddresses = ServiceDnsAddresses(),
        ServiceExecutablePath = _deps.ServiceExecutablePath,
        OnLinkPrefixes = OnLinkPrefixes(),
        TrustedAdapters = TrustedAdapters().Select(a => new TrustedAdapterInput(a.Luid, a.Name)).ToList(),
        RevocationEndpoints = RevocationEndpoints(),
    };

    /// <summary>Туннели для плана фильтров: активные подключения и группы-заполнители.</summary>
    private List<TunnelInput> TunnelInputs()
    {
        var carriers = DefaultCarriers;
        var inputs = Facts.Tunnels.Values.Select(tunnel => new TunnelInput
        {
            Id = tunnel.ProfileId,
            Name = tunnel.Name,
            Luid = tunnel.Luid,
            ServerAddresses = ServerAddressesOf(tunnel).ToList(),
            ServerPort = tunnel.ServerPort,
            GatewayTcpPorts = tunnel.AnyConnect is { } tcp ? [.. tcp.GatewayTcpPorts] : [],
            GatewayUdpPorts = tunnel.AnyConnect is { } udp ? [.. udp.GatewayUdpPorts] : [],
            Protocol = tunnel.Protocol,
            ServesDefault = carriers.Contains(tunnel.ProfileId),
            Paused = tunnel.Paused,
            DnsAddresses = TunnelDnsRoute(tunnel)?.Servers.Select(s => Ipv4.ToUInt(s.Address)).ToList() ?? [],
        }).ToList();

        // Группа попадает в план как всегда не поднятый туннель: назначенные ей адреса остаются за её
        // идентификатором только тогда, когда ни один участник не доступен.
        inputs.AddRange(_settings.Groups.Select(group => new TunnelInput
        {
            Id = group.Id,
            Name = group.Name,
            Luid = null,
            ServesDefault = _settings.DefaultTarget.IsGroup(out var id) && id == group.Id,
            Paused = AllPaused(group.Members),
        }));
        return inputs;
    }

    /// <summary>
    /// Как часто полная сверка проверяет, что фильтры группы Direct на месте. Их десятки тысяч, и счёт идёт
    /// перечислением всех фильтров системы (около 300 мс); небольшие группы защиты проверяются каждую сверку.
    /// </summary>
    internal static readonly TimeSpan DirectFilterCheckInterval = TimeSpan.FromMinutes(10);

    private void EnsureProtection()
    {
        var inputs = ProtectionInputs();
        var installed = Facts.ForceProtection ? InstalledFilterCounts() : null;
        var changed = _filterPlanCache.Build(inputs);
        foreach (var (group, specs) in changed.ToList())
        {
            if (!GroupChanged(group, specs, installed))
            {
                changed.Remove(group);
            }
        }

        if (changed.Count == 0)
        {
            return;
        }

        var counts = _deps.Wfp.ReplaceGroups(changed,
            (done, total) => ReportFilterItems("Обновление фильтров защиты", done, total));
        foreach (var (group, specs) in changed)
        {
            Facts.AppliedFilters[group] = (specs, counts[group]);
        }

        if (_deps.Logger.IsEnabled(LogLevel.Debug))
        {
            _deps.Logger.LogDebug("WFP: заменены группы {Groups}", string.Join(", ", changed.Select(p =>
                string.Create(CultureInfo.InvariantCulture, $"{p.Key} (правил {p.Value.Count}, фильтров {counts[p.Key]})"))));
        }
    }

    private IReadOnlyDictionary<FilterGroup, int> InstalledFilterCounts()
    {
        var now = _deps.Time.GetUtcNow();
        var includeDirect = now - Facts.LastDirectFilterCheck >= DirectFilterCheckInterval;
        var counts = _deps.Wfp.InstalledCounts(includeDirect);
        if (includeDirect)
        {
            Facts.LastDirectFilterCheck = now;
        }

        return counts;
    }

    /// <summary>
    /// Выбирает группу, если изменился план или (при полной сверке) число фильтров в системе. Группы,
    /// которой нет в подсчёте, проверка расхождения не касается.
    /// </summary>
    private bool GroupChanged(FilterGroup group, IReadOnlyList<FilterSpec> specs, IReadOnlyDictionary<FilterGroup, int>? installed)
    {
        var unchanged = Facts.AppliedFilters.TryGetValue(group, out var applied)
            && (ReferenceEquals(applied.Specs, specs) || applied.Specs.SequenceEqual(specs, FilterSpecComparer.Instance));
        var drifted = unchanged && installed is not null && installed.TryGetValue(group, out var installedCount) && installedCount != applied.Count;
        if (unchanged && !drifted)
        {
            return false;
        }

        if (drifted)
        {
            Journal("Ошибка", $"Фильтры группы {group} изменены извне: восстанавливаются.");
        }

        return true;
    }

    private void EnsureRoutes()
    {
        var desired = new List<RouteKey>();
        var halfRouteTunnel = HalfRouteTunnel();
        if (Facts.Primary is { DefaultGateway: { } gateway } primary)
        {
            // Сервер в локальной сети основного адаптера (или сам шлюз) достижим напрямую: его /32 — тоже
            // on-link, без шлюза. Иначе маршрут через шлюз перекрыл бы прямой путь, а роутер без hairpin его не вернёт.
            desired.AddRange(AllServerAddresses().Select(a => new RouteKey(new Ipv4Cidr(a, 32),
                a == gateway || primary.OnLinkPrefixes.Any(p => p.Contains(a)) ? 0u : gateway, primary.Luid)));
            desired.AddRange(PinnedCidrs(RouteTarget.Direct).Select(c => new RouteKey(c, gateway, primary.Luid)));
            desired.AddRange(StrandedRevocationAddresses().Select(a => new RouteKey(new Ipv4Cidr(a, 32), gateway, primary.Luid)));
        }

        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.Luid is not null && AdapterPresent(t.Luid.Value)))
        {
            if (tunnel.ProfileId == halfRouteTunnel)
            {
                desired.AddRange(HalfRoutes.Select(c => new RouteKey(c, 0, tunnel.Luid!.Value)));
            }

            desired.AddRange(PinnedCidrs(RouteTarget.Tunnel(tunnel.ProfileId)).Select(c => new RouteKey(c, 0, tunnel.Luid!.Value)));
        }

        desired.AddRange(BaseRoutes(halfRouteTunnel));

        var fingerprint = string.Create(CultureInfo.InvariantCulture, $"{desired.Count}:{desired.Aggregate(17L, (h, r) => (h * 31) + r.GetHashCode())}");
        if (fingerprint == Facts.AppliedRoutes && !Facts.ForceProtection)
        {
            return;
        }

        var result = _deps.Routes.Reconcile(desired,
            (done, total) => ReportItems("Обновление маршрутов", done, total));
        if (_deps.Logger.IsEnabled(LogLevel.Debug))
        {
            _deps.Logger.LogDebug("Маршруты: нужно {Desired}, добавлено {Added}, удалено {Removed}, ошибок {Failed}{Errors}",
                desired.Count, result.Added, result.Removed, result.Failed, result.Errors.Count == 0 ? "" : " — " + string.Join("; ", result.Errors));
        }
        ThrowOnRouteFailure(result, "маршруты");
        if (fingerprint == Facts.AppliedRoutes && result.Added + result.Removed > 0)
        {
            Journal("Ошибка", $"Маршруты изменены извне: добавлено {result.Added}, удалено {result.Removed}.");
        }

        Facts.AppliedRoutes = fingerprint;
    }

    /// <summary>Интерфейс туннеля мог исчезнуть раньше, чем RAS сообщил об обрыве: маршрут на него не добавить.</summary>
    private bool AdapterPresent(ulong luid) => _snapshot?.Adapters.Any(a => a.Luid == luid) == true;

    /// <summary>
    /// Маршруты адресных слоёв: прямые и туннелей, кроме туннеля пары /1. Каждый адрес идёт туда же, куда
    /// при точном CIDR-покрытии каждой цели, но широкие подсети с исключениями дают меньше записей
    /// (<see cref="RouteCover"/>): при «остальном через VPN» российская база — около 12 тысяч маршрутов
    /// вместо 20. Цель 0 — путь по умолчанию: пара /1 туннеля или, при «остальном напрямую», основной адаптер.
    /// Покрытие считается по настройкам, а не по поднятым туннелям: обрыв и подъём туннеля снимают и ставят
    /// только его собственные маршруты, без перестройки тысяч прямых. Адреса цели без интерфейса при этом
    /// попадают под соседний маршрут, и их, как и прежде, держит защита («Туннель недоступен», обрыв).
    /// </summary>
    private List<RouteKey> BaseRoutes(Guid? halfRouteTunnel)
    {
        var policy = Facts.Policy!;
        var primary = Facts.Primary is { DefaultGateway: { } gateway } adapter ? (adapter.Luid, Gateway: gateway) : default((ulong Luid, uint Gateway)?);
        var layers = new List<(RangeSet Ranges, int Target)>();
        var defaultTunnel = _settings.DefaultTarget.IsTunnel(out var defaultId) ? defaultId : (Guid?)null;

        // Цель 0. У группы «остального интернета» своего интерфейса нет: исключения к ней невозможны.
        // Интерфейс туннеля мог исчезнуть раньше, чем RAS сообщил об обрыве: маршрут на него не добавить.
        var restRoutable = defaultTunnel is not null || !_settings.DefaultTarget.IsVpn;
        RouteKey? Rest(Ipv4Cidr c) =>
            defaultTunnel is not null
                ? halfRouteTunnel is { } half && Facts.Tunnels.GetValueOrDefault(half)?.Luid is { } luid && AdapterPresent(luid) ? new RouteKey(c, 0, luid) : null
                : primary is { } p ? new RouteKey(c, p.Gateway, p.Luid) : null;

        // Основной адаптер без шлюза (PPPoE, модем) получает маршруты без следующего узла: на них Windows тоже
        // ставит маршрут последнего адреса, как на туннели.
        var primaryOnLink = primary is { Gateway: 0 };
        var targets = new List<Func<Ipv4Cidr, RouteKey?>> { Rest };
        var properties = new List<CoverTarget> { new(restRoutable, OnLink: defaultTunnel is not null || primaryOnLink) };
        // Номер цели покрытия для цели закрепления правилом домена; неизвестная цель — -1.
        var indexOf = new Dictionary<RouteTarget, int> { [RouteTarget.Direct] = 0 };
        if (defaultTunnel is not null)
        {
            indexOf[RouteTarget.Tunnel(defaultTunnel.Value)] = 0;
        }

        // При «остальном напрямую» прямые адреса и есть цель 0: своих маршрутов им не нужно. Адреса серверов VPN
        // идут напрямую своими маршрутами /32 (EnsureRoutes): в покрытии они прямые, иначе под широким прямым
        // маршрутом им понадобилось бы исключение в туннель, и второй /32 увёл бы транспорт туннеля в другой туннель.
        if (_settings.DefaultTarget.IsVpn)
        {
            indexOf[RouteTarget.Direct] = targets.Count;
            layers.Add((DirectLayer(policy), targets.Count));
            targets.Add(c => primary is { } p ? new RouteKey(c, p.Gateway, p.Luid) : null);
            properties.Add(new CoverTarget(true, OnLink: primaryOnLink));
        }

        foreach (var id in policy.Tunnels.Where(id => id != defaultTunnel && _settings.Profile(id) is not null))
        {
            var ranges = policy.RangesFor(id);
            if (ranges.Count == 0)
            {
                continue;
            }

            indexOf[RouteTarget.Tunnel(id)] = targets.Count;
            layers.Add((ranges, targets.Count));
            targets.Add(c => Facts.Tunnels.GetValueOrDefault(id)?.Luid is { } luid && AdapterPresent(luid) ? new RouteKey(c, 0, luid) : null);
            properties.Add(new CoverTarget(true, OnLink: true, HoldsDefault: defaultTunnel is null));
        }

        if (_routeCover is not { } cached
            || !ReferenceEquals(cached.Local, policy.LocalRanges)
            || !cached.Targets.SequenceEqual(properties)
            || !cached.Layers.Select(l => l.Ranges).SequenceEqual(layers.Select(l => l.Ranges), ReferenceEqualityComparer.Instance))
        {
            List<CoverRoute> routes;
            try
            {
                routes = RouteCover.Build(layers, properties, policy.LocalRanges);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
            {
                // Прежняя схема — точное покрытие каждой цели — всегда возможна: связь важнее числа маршрутов.
                _deps.Logger.LogWarning(ex, "Маршруты с исключениями не построены, ставится точное покрытие");
                routes = layers.SelectMany(l => l.Ranges.ToCidrs().Select(c => new CoverRoute(c, l.Target))).ToList();
            }

            cached = new RouteCoverCache(layers, properties, policy.LocalRanges, routes);
            _routeCover = cached;
        }

        // Закреплённые адреса и серверы получают свои /32 (EnsureRoutes): второй /32 из покрытия не нужен.
        int PinIndex(uint address) => policy.PinTarget(address) is { } pin ? indexOf.GetValueOrDefault(pin, -1) : -2;
        var result = new List<RouteKey>(cached.Routes.Count);
        foreach (var route in cached.Routes)
        {
            if (route.Cidr.PrefixLength == 32 && (policy.IsPinned(route.Cidr.Network) || IsServer(policy, route.Cidr.Network)))
            {
                continue;
            }

            var last = route.Cidr.ToRange().End;
            if (properties[route.Target].OnLink && route.Cidr.PrefixLength <= RouteCover.MaxBroadcastPrefix
                && PinIndex(last) is var pinned && pinned != -2 && pinned != route.Target)
            {
                // Последний адрес закреплён правилом домена за другой целью: маршрут Windows на этот адрес перекрыл бы /32 закрепления.
                foreach (var piece in BroadcastSafePieces(route, cached, PinIndex))
                {
                    if (targets[route.Target](piece) is { } part)
                    {
                        result.Add(part);
                    }
                }

                continue;
            }

            if (targets[route.Target](route.Cidr) is { } key)
            {
                result.Add(key);
            }
        }

        return result;
    }

    /// <summary>
    /// Части маршрута цели без шлюза, на последних адресах которых нет адресов других целей. Маршрут делится пополам,
    /// пока последний адрес части не станет своим или часть не станет /31 (на /31 и /32 Windows маршрута последнего
    /// адреса не ставит). Часть целиком под более узким маршрутом покрытия не нужна: её адреса решает он.
    /// </summary>
    internal static List<Ipv4Cidr> BroadcastSafePieces(CoverRoute route, RouteCoverCache cover, Func<uint, int> pinIndex)
    {
        var pieces = new List<Ipv4Cidr>();
        int TargetAt(uint address) => pinIndex(address) is var pinned and not -2
            ? pinned
            : cover.Layers.FirstOrDefault(l => l.Ranges.Contains(address)).Target;
        bool Covered(Ipv4Cidr piece) => cover.Routes.Any(r => r.Cidr.PrefixLength > route.Cidr.PrefixLength
            && r.Cidr.PrefixLength <= piece.PrefixLength && r.Cidr.Contains(piece.Network));

        void Split(Ipv4Cidr piece)
        {
            if (piece != route.Cidr && Covered(piece))
            {
                return;
            }

            if (piece.PrefixLength > RouteCover.MaxBroadcastPrefix
                || (piece != route.Cidr && TargetAt(piece.ToRange().End) == route.Target))
            {
                pieces.Add(piece);
                return;
            }

            var length = piece.PrefixLength + 1;
            Split(new Ipv4Cidr(piece.Network, length));
            Split(new Ipv4Cidr(piece.Network | (1u << (32 - length)), length));
        }

        Split(route.Cidr);
        return pieces;
    }

    private static bool IsServer(CompiledPolicy policy, uint address) => policy.ServerAddresses.Contains(address);

    /// <summary>
    /// Адреса проверки отзыва, которые по политике принадлежат не поднятому дополнительному туннелю. Без своего
    /// маршрута проверка ушла бы под пару /1 туннеля «остального интернета», где её заблокировал бы «Туннель
    /// недоступен», а разрешение проверки отзыва действует только на основном адаптере. Пока проверка нужна, такой
    /// адрес получает /32 через основной адаптер: прочий трафик к нему и так заблокирован, пока его туннель лежит.
    /// Адресам носителей «остального интернета» маршрут не нужен: без их пары /1 они и так идут через основной адаптер.
    /// </summary>
    private List<uint> StrandedRevocationAddresses()
    {
        if (Facts.Policy is not { } policy || Facts.RevocationPins.Count == 0)
        {
            return [];
        }

        var carriers = DefaultCarriers.ToHashSet();
        return Facts.RevocationPins.Keys.Where(address => policy.Classify(address) is { Decision: Decision.Vpn, Tunnel: { } id }
            && !carriers.Contains(id)
            && !(Facts.Tunnels.GetValueOrDefault(id)?.Luid is { } luid && AdapterPresent(luid))).ToList();
    }

    /// <summary>
    /// Прямой слой покрытия: прямые адреса политики и адреса серверов VPN. Политика пересобирается и при каждом
    /// закреплении домена, поэтому слой хранится по набору прямых адресов, а не по объекту политики: иначе
    /// покрытие считалось бы заново на каждый ответ DNS.
    /// </summary>
    private RangeSet DirectLayer(CompiledPolicy policy)
    {
        if (_directLayer is not { } cached
            || !ReferenceEquals(cached.Direct, policy.DirectRanges)
            || !ReferenceEquals(cached.Local, policy.LocalRanges)
            || !cached.Servers.SequenceEqual(policy.ServerAddresses))
        {
            var servers = RangeSet.From(policy.ServerAddresses.Select(Ipv4Range.Host));
            cached = new DirectLayerCache(policy.DirectRanges, policy.LocalRanges, policy.ServerAddresses.ToArray(),
                servers.Count == 0 ? policy.DirectRanges : policy.DirectRanges.Union(servers.Subtract(policy.LocalRanges)));
            _directLayer = cached;
        }

        return cached.Ranges;
    }

    private sealed record DirectLayerCache(RangeSet Direct, RangeSet Local, uint[] Servers, RangeSet Ranges);

    private DirectLayerCache? _directLayer;

    internal sealed record RouteCoverCache(
        IReadOnlyList<(RangeSet Ranges, int Target)> Layers, IReadOnlyList<CoverTarget> Targets, RangeSet Local, List<CoverRoute> Routes);

    private RouteCoverCache? _routeCover;

    /// <summary>
    /// Туннель, который забирает «остальной интернет» парой маршрутов /1. У группы такого туннеля нет:
    /// её участники получают точные маршруты своих долей.
    /// </summary>
    private Guid? HalfRouteTunnel() =>
        _settings.DefaultTarget.IsTunnel(out var id) && Facts.Tunnels.GetValueOrDefault(id)?.Luid is not null ? id : null;

    /// <summary>
    /// Адреса из правил для доменов, закреплённые за указанной целью. Берутся из скомпилированной политики:
    /// там группы уже раскрыты в участников, а адреса, которые держат за собой адресные слои (сервер VPN,
    /// DNS службы, сеть адаптера), закреплению не подлежат.
    /// </summary>
    private List<Ipv4Cidr> PinnedCidrs(RouteTarget target) =>
        Facts.Policy!.PinsFor(target).Select(p => new Ipv4Cidr(p.Address, 32)).ToList();

    private static void ThrowOnRouteFailure(RouteApplyResult result, string step)
    {
        if (result.Failed > 0)
        {
            throw new InvalidOperationException($"{step}: не применено {result.Failed} ({string.Join("; ", result.Errors.Take(3))})");
        }
    }

    private void SaveServerCache()
    {
        var known = _state.Servers.ToDictionary(s => s.ProfileId, s => s.Fingerprint);
        _state = _state with
        {
            Servers = Facts.Tunnels.Values
                .Where(t => t.ServerAddresses.Count > 0)
                .Select(t => new ServerCacheEntry(
                    t.ProfileId,
                    t.ServerAddresses.Select(Ipv4.Format).ToList(),
                    t.ServerResolvedUtc,
                    known.GetValueOrDefault(t.ProfileId),
                    t.RevocationHosts,
                    t.HasSession || t.Dialing ? t.SessionServerAddresses.Select(Ipv4.Format).ToList() : [],
                    // В списке туннеля только узлы проверенного сертификата: непроверенный его очищает.
                    RevocationHostsTrusted: t.RevocationHosts.Count > 0))
                .ToList(),
        };
        _deps.Stores.SaveState(_state);
    }

    /// <summary>Запоминает, с какими параметрами входа поднято соединение туннеля.</summary>
    private void RememberFingerprint(TunnelFacts tunnel, string fingerprint)
    {
        var others = _state.Servers.Where(s => s.ProfileId != tunnel.ProfileId).ToList();
        var current = _state.Servers.FirstOrDefault(s => s.ProfileId == tunnel.ProfileId)
            ?? new ServerCacheEntry(tunnel.ProfileId, tunnel.ServerAddresses.Select(Ipv4.Format).ToList(), tunnel.ServerResolvedUtc);
        others.Add(current with
        {
            Fingerprint = fingerprint,
            Addresses = tunnel.ServerAddresses.Select(Ipv4.Format).ToList(),
            SessionAddresses = tunnel.SessionServerAddresses.Select(Ipv4.Format).ToList(),
        });
        _state = _state with { Servers = others };
        _deps.Stores.SaveState(_state);
    }

    /// <summary>
    /// Адреса серверов без сети: IP из профиля или сохранённые. Без них первая сверка после перезапуска
    /// службы сняла бы маршрут /32 и разрешение к серверу — и оборвала подхваченное SSTP-соединение.
    /// </summary>
    private void PreloadServerAddresses()
    {
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.ServerAddresses.Count == 0))
        {
            var profile = _settings.Profile(tunnel.ProfileId);
            if (!TryParseServer(profile, out var server))
            {
                continue;
            }

            if (Ipv4.TryParse(server.Host, out var literal))
            {
                tunnel.ServerAddresses = [literal];
            }
            else if (_state.Servers.FirstOrDefault(s => s.ProfileId == tunnel.ProfileId) is { } cached)
            {
                tunnel.ServerAddresses = cached.Addresses.Select(Ipv4.Parse).ToList();
                tunnel.ServerResolvedUtc = cached.ResolvedUtc;
            }
        }

        PreloadRevocationHosts();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.HasSession && t.SessionServerAddresses.Count == 0))
        {
            var cached = _state.Servers.FirstOrDefault(s => s.ProfileId == tunnel.ProfileId);
            tunnel.SessionServerAddresses = cached?.SessionAddresses is { Count: > 0 } active
                ? active.Select(Ipv4.Parse).ToArray() : tunnel.ServerAddresses.ToArray();
        }
    }

    /// <summary>
    /// Узлы проверки отзыва из кеша: без них первый дозвон после перезапуска службы снова упёрся бы
    /// в закрытый список отзыва и ждал бы новой пробы.
    /// </summary>
    private void PreloadRevocationHosts()
    {
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.RevocationHosts.Count == 0))
        {
            // Кеш без признака доверия записан версиями до 0.9.6 из сертификата любого ответившего: он не используется.
            if (_state.Servers.FirstOrDefault(s => s.ProfileId == tunnel.ProfileId) is { RevocationHostsTrusted: true, RevocationHosts: { Count: > 0 } hosts })
            {
                // Кеш прежних версий мог сохранить имя из одной метки: такое правило открыло бы целую зону.
                tunnel.RevocationHosts = hosts.Where(IsRevocationHost).ToList();
            }
        }
    }

    /// <summary>Адреса DNS нужны политике до закреплений и подмены DNS интерфейса на loopback.</summary>
    private void RefreshTunnelDnsAddresses()
    {
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { Connection: not null, Adapter: not null }))
        {
            var current = _deps.Dns.ReadNameServer(tunnel.Adapter!.InterfaceGuid);
            if (!InterfaceDnsOps.IsLoopback(current))
            {
                var vpnDns = ParseAddresses(current);
                tunnel.VpnDns = vpnDns.Count > 0 ? vpnDns : tunnel.VpnDns;
            }
        }
    }

    private void EnsureDns()
    {
        EnsureProxyRunning();

        // Сбой на одном адаптере или туннеле не должен оставлять без DNS остальные и посредник без настроек:
        // каждый обрабатывается отдельно, первая ошибка пробрасывается в конце (сверка отметит неполное применение).
        // Настройки посредника — после адаптеров: адреса «напрямую» берутся из только что сохранённой копии DNS адаптера.
        ExceptionDispatchInfo? failure = null;
        var tunnelLuids = TunnelLuids();
        foreach (var adapter in (_snapshot?.Adapters ?? []).Where(a => a.IsUp && a.Addresses.Count > 0 && !tunnelLuids.Contains(a.Luid) && a.DnsServers.Count > 0))
        {
            try
            {
                EnsureAdapterLoopback(adapter.InterfaceGuid);
                EnsureSearchList(adapter.InterfaceGuid);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failure ??= ExceptionDispatchInfo.Capture(ex);
            }
        }

        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { Connection: not null, Adapter: not null }))
        {
            try
            {
                // DNS туннеля целиком наш (при отключении он очищается): исходный IPv6-список пуст, и ::1,
                // оставшийся без слушателя на [::1]:53, снимается.
                var guid = tunnel.Adapter!.InterfaceGuid;
                if (InterfaceDnsOps.IsLoopback(_deps.Dns.ReadNameServer(guid)) && _deps.Dns.Ipv6LoopbackMatches(guid, originalV6: ""))
                {
                    continue;
                }

                _deps.Dns.ApplyLoopback(guid, originalV6: "");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failure ??= ExceptionDispatchInfo.Capture(ex);
            }
        }

        SetProxyConfiguration(BuildProxyConfiguration());
        failure?.Throw();
    }

    private void EnsureProxyRunning()
    {
        if (_deps.DnsProxy.IsRunning)
        {
            return;
        }

        _deps.DnsProxy.Start();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.ServerAddresses.Count > 0))
        {
            if (TryParseServer(_settings.Profile(tunnel.ProfileId), out var server) && !server.IsIpLiteral)
            {
                _deps.DnsProxy.Pin(server.Host, tunnel.ServerAddresses);
            }
        }
    }

    private void EnsureAdapterLoopback(Guid interfaceGuid)
    {
        if (InterfaceDnsOps.IsLoopback(_deps.Dns.ReadNameServer(interfaceGuid)))
        {
            // IPv4 уже на посреднике, но ::1 мог не встать, если слушатель на [::1]:53 появился позже, или
            // остаться от прежнего запуска, если слушателя больше нет: наш ::1 от пользовательского отличает
            // исходный IPv6-список из копии. Без копии 127.0.0.1 — собственный резолвер пользователя: адаптер не трогаем.
            if (_deps.DnsBackups.Load().GetValueOrDefault(interfaceGuid) is { } backup
                && !_deps.Dns.Ipv6LoopbackMatches(interfaceGuid, backup.NameServerV6))
            {
                _deps.Dns.ApplyLoopback(interfaceGuid, backup.NameServerV6);
            }

            return;
        }

        var existing = _deps.DnsBackups.Load().GetValueOrDefault(interfaceGuid);
        if (existing is not null)
        {
            // Исходный DNS уже сохранён: внешнее изменение — дрейф, а не новый исходный DNS.
            Journal("Предупреждение", "DNS адаптера изменён извне: возвращён локальный посредник.");
        }
        else
        {
            existing = _deps.Dns.Capture(interfaceGuid, null);
            _deps.DnsBackups.Upsert(existing);
        }

        _deps.Dns.ApplyLoopback(interfaceGuid, existing.NameServerV6);
    }

    /// <summary>
    /// Суффиксы шлюзов AnyConnect с установленным сеансом — в список поиска адаптера после исходных, чтобы короткие имена
    /// («ws-001») дополнялись, как у Cisco-клиента. Запрос уходит в посредник, а он по доменному правилу — в DNS шлюза.
    /// Суффиксы на адаптере туннеля Windows не использует: у того нет своих DNS-серверов.
    /// </summary>
    private void EnsureSearchList(Guid interfaceGuid)
    {
        if (_deps.DnsBackups.Load().GetValueOrDefault(interfaceGuid) is not { } backup)
        {
            return;
        }

        // Суффиксы шлюза — только имена из двух и более меток, не публичные зоны: «ru» или «com.ru» в списке
        // поиска дописывались бы к любому короткому имени и отправляли запросы в чужие зоны.
        var original = SplitSuffixes(backup.SearchList);
        var gateway = Facts.Tunnels.Values
            .Where(t => t is { IsUp: true, Session: not null })
            .SelectMany(t => t.Session!.DnsSuffixes())
            .Select(s => s.Trim().TrimEnd('.'))
            .Where(Core.Dns.PublicSuffixes.IsSearchListSuffix);
        var desired = string.Join(",", original.Concat(gateway).Distinct(StringComparer.OrdinalIgnoreCase));
        if (string.Equals(string.Join(",", SplitSuffixes(_deps.Dns.ReadSearchList(interfaceGuid))), desired, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _deps.Dns.SetSearchList(interfaceGuid, desired);
        _deps.Dns.FlushCache();
    }

    private static List<string> SplitSuffixes(string list) =>
        list.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries).ToList();

    private DnsProxyConfiguration BuildProxyConfiguration()
    {
        var local = _settings.LocalDnsSuffixes.Count > 0 && Facts.Primary is { } p
            ? new DnsRoute(ServiceDnsAddresses().Select(Endpoint).ToList(), p.InterfaceIndex)
            : null;
        var configuration = new DnsProxyConfiguration
        {
            // Сравнение в посреднике — с теми же нормализованными суффиксами, что прошли проверку настроек.
            LocalSuffixes = _settings.LocalDnsSuffixes.Select(SettingsSerializer.NormalizeSuffix).Where(s => s.Length > 0).ToList(),
            Local = local,
            DomainRoutes = BuildDomainRoutes(),
        };

        if (DnsAnchor is { } anchor)
        {
            return configuration with { Mode = DnsProxyMode.Online, Tunnel = TunnelDnsRoute(anchor) };
        }

        // «Остальной интернет» напрямую — не обрыв: DNS идёт исходным путём, иначе без опорного туннеля не разрешается ни одно имя.
        // Носители, положенные пользователем, - не обрыв и для «Разрешить всё»: их трафик заблокирован, DNS тоже.
        var directAllowed = _settings.DefaultTarget.Kind == TargetKind.Direct
            || _settings.DnsDirectOnOutage
            || (_settings.OutageMode == OutageMode.AllowAll && _state.Intent == Intent.Connected && !AllPaused(DefaultCarriers));
        return directAllowed && Facts.Primary is { } primary
            ? configuration with { Mode = DnsProxyMode.DirectAllowed, Direct = new DnsRoute(ServiceDnsAddresses().Select(Endpoint).ToList(), primary.InterfaceIndex) }
            : configuration with { Mode = DnsProxyMode.Offline };
    }

    private DnsRoute? TunnelDnsRoute(TunnelFacts tunnel)
    {
        if (tunnel.Adapter is not { } adapter)
        {
            return null;
        }

        // У AnyConnect свои DNS шлюза: общий «DNS через VPN» из настроек к ним не относится.
        var upstream = tunnel.Protocol == VpnProtocol.AnyConnect ? [] : UpstreamDnsAddresses();
        var servers = upstream.Count > 0 ? upstream : tunnel.VpnDns.Count > 0 ? [.. tunnel.VpnDns] : FallbackUpstreams.ToList();
        return new DnsRoute(servers.Select(Endpoint).ToList(), adapter.InterfaceIndex);
    }

    /// <summary>Правила для доменов: имя разрешается по тому же пути, по которому пойдёт трафик.</summary>
    private List<DomainRoute> BuildDomainRoutes() => BuildDomainRoutes(out _);

    /// <param name="revocationSuffixes">Имена узлов проверки отзыва, для которых добавлен служебный маршрут.</param>
    private List<DomainRoute> BuildDomainRoutes(out HashSet<string> revocationSuffixes)
    {
        var routes = new List<DomainRoute>(_settings.DomainRules.Count);
        foreach (var rule in _settings.DomainRules)
        {
            var suffix = SettingsSerializer.NormalizeSuffix(rule.Suffix);
            if (suffix.Length == 0)
            {
                continue;
            }

            var route = DomainDnsRoute(rule.Target);

            // Цель правила недоступна: имя не разрешается вовсе. Общий DNS увёл бы частное имя
            // к провайдеру или в другой VPN — правило требовало не этого.
            routes.Add(new DomainRoute(suffix, rule.Target, route, PinAddresses: true, Unavailable: route is null));
        }

        AddGatewayDomainRoutes(routes);
        AddGatewayHostRoutes(routes);
        revocationSuffixes = AddRevocationDomainRoutes(routes);
        return routes;
    }

    /// <summary>
    /// Узлы проверки отзыва сертификата сервера. Перед подключением Windows идёт к ним за списком отзыва,
    /// а за kill switch наружу открыты только разрешённые адреса - и исправный сертификат отклоняется с
    /// «проверка отзыва недоступна» (0x80092013). Пока туннелю нужна эта проверка (<see cref="RevocationHostsNeeded"/>),
    /// имя разрешается напрямую, а полученный адрес получает служебное закрепление: защита открывает к нему только
    /// TCP на порт ссылки через основной адаптер, остальной трафик к адресу идёт по общей политике. Адрес лежащего
    /// дополнительного туннеля получает и маршрут через основной адаптер (<see cref="StrandedRevocationAddresses"/>).
    /// Подходящее правило пользователя важнее служебного, в том числе правило родительского домена.
    /// </summary>
    /// <returns>Имена, для которых добавлен служебный маршрут.</returns>
    private HashSet<string> AddRevocationDomainRoutes(List<DomainRoute> routes)
    {
        var added = new HashSet<string>(StringComparer.Ordinal);
        foreach (var host in RevocationHostsNeeded())
        {
            var suffix = SettingsSerializer.NormalizeSuffix(host);
            if (!IsRevocationHost(host) || MatchingDomainRule(host) is not null || routes.Exists(r => r.Suffix == suffix))
            {
                continue;
            }

            var route = DomainDnsRoute(RouteTarget.Direct);
            // Только само имя узла: его поддомены - обычные имена, они идут по политике.
            routes.Add(new DomainRoute(suffix, RouteTarget.Direct, route, PinAddresses: true, Unavailable: route is null, ExactName: true));
            added.Add(suffix);
        }

        return added;
    }

    private DnsRoute? DomainDnsRoute(RouteTarget target)
    {
        if (target.Kind == TargetKind.Direct)
        {
            return Facts.Primary is { } primary ? new DnsRoute(ServiceDnsAddresses().Select(Endpoint).ToList(), primary.InterfaceIndex) : null;
        }

        var carrier = Carriers(target).Select(id => Facts.Tunnels.GetValueOrDefault(id)).FirstOrDefault(t => t?.Luid is not null);
        return carrier is null ? null : TunnelDnsRoute(carrier);
    }

    private void SetProxyConfiguration(DnsProxyConfiguration configuration)
    {
        // Сеть сменилась при тех же адаптере и DNS-адресах (другой Wi-Fi с тем же 192.168.1.1): ответы прежней
        // сети про её внутренние зоны к новой не относятся, поэтому смена сети тоже сбрасывает кеш.
        if (Facts.AppliedDnsConfiguration is { } applied && SameConfiguration(applied, configuration)
            && Facts.NetworkFingerprint == _dnsCacheNetwork)
        {
            return;
        }

        _dnsCacheNetwork = Facts.NetworkFingerprint;
        _deps.DnsProxy.Configuration = configuration;
        Facts.AppliedDnsConfiguration = configuration;
        Facts.DnsMode = configuration.Mode;

        // Путь разрешения сменился: ответы прежнего пути к новому не относятся (split-DNS).
        _deps.DnsProxy.ClearCache();
        _deps.Dns.FlushCache();
    }

    /// <summary>Сеть (<see cref="CoordinatorFacts.NetworkFingerprint"/>), при которой кеш посредника последний раз сброшен.</summary>
    private string? _dnsCacheNetwork;

    private static bool SameConfiguration(DnsProxyConfiguration a, DnsProxyConfiguration b) =>
        a.Mode == b.Mode && Describe(a.Tunnel) == Describe(b.Tunnel) && Describe(a.Direct) == Describe(b.Direct)
        && Describe(a.Local) == Describe(b.Local) && a.LocalSuffixes.SequenceEqual(b.LocalSuffixes)
        && DescribeDomains(a) == DescribeDomains(b);

    private static string Describe(DnsRoute? route) => route is null ? "" : route.InterfaceIndex + ":" + string.Join(",", route.Servers);

    private static string DescribeDomains(DnsProxyConfiguration configuration) =>
        string.Join("|", configuration.DomainRoutes.Select(d => d.Suffix + ">" + d.Target + ">" + d.PinAddresses + ">" + d.Unavailable + ">" + d.ExactName + ">" + Describe(d.Route)));

    private void RestoreAllDns()
    {
        foreach (var backup in _deps.DnsBackups.Load().Values)
        {
            try
            {
                if (_deps.Dns.Restore(backup.InterfaceGuid, backup) == DnsRestoreOutcome.Incomplete)
                {
                    // На адаптере остался ::1 без посредника: без копии исходные IPv6 DNS уже не вернуть.
                    _deps.Logger.LogWarning("IPv6 DNS адаптера {Interface} не восстановлены, резервная копия сохранена", backup.InterfaceGuid);
                    continue;
                }
            }
            catch (NativeCallException ex) when (ex.Code == 2)
            {
                // Интерфейс исчез — возвращать нечего.
            }

            _deps.DnsBackups.Remove(backup.InterfaceGuid);
        }

        _deps.Dns.FlushCache();
    }

    /// <summary>Обнаружение обрывов и подхват соединений своей телефонной книги. true — состояние изменилось.</summary>
    private async Task<bool> MonitorConnectionsAsync(CancellationToken cancellationToken)
    {
        var changed = false;
        foreach (var tunnel in Facts.Tunnels.Values.ToList())
        {
            changed |= await MonitorConnectionAsync(tunnel, cancellationToken);
        }

        return changed;
    }

    /// <summary>Сколько тиков подряд «подключается» ещё не считается обрывом: RAS успевает пересогласовать канал.</summary>
    private const int ConnectingTicksAllowed = 2;

    /// <summary>Событие завершения в этом окне вокруг своего RasHangUp записи — след своего разрыва, а не решения пользователя.</summary>
    private static readonly TimeSpan OwnHangUpWindow = TimeSpan.FromSeconds(3);

    private async Task<bool> MonitorConnectionAsync(TunnelFacts tunnel, CancellationToken cancellationToken)
    {
        if (tunnel.Connection is not { } handle)
        {
            return false;
        }

        var status = _deps.Ras.GetStatus(handle);
        if (status == RasConnectionStatus.Connected)
        {
            tunnel.ConnectingTicks = 0;
            tunnel.Statistics = _deps.Ras.GetStatistics(handle);
            return await CheckAdapterPresentAsync(tunnel, handle, cancellationToken);
        }

        if (status == RasConnectionStatus.Connecting && ++tunnel.ConnectingTicks <= ConnectingTicksAllowed)
        {
            return false;
        }

        tunnel.ConnectingTicks = 0;
        var since = tunnel.SessionStartedUtc ?? _deps.Time.GetUtcNow().AddMinutes(-1);
        // Событие раньше начала сеанса относится к прошлому соединению записи (например, к своему разрыву перед переподключением).
        var termination = _deps.RasTerminationReason(since, tunnel.EntryName) is { } found && found.TimeUtc >= since ? found : (RasTermination?)null;
        var reason = termination?.Code;
        _deps.Logger.LogWarning("RAS handle {Handle} ({Name}): состояние {Status}, код завершения {Reason}", handle, tunnel.Name, status, reason);

        // 631 пишет и наш собственный RasHangUp этой записи: событие рядом с ним по времени — обрыв, а не решение пользователя.
        var ownHangUp = termination is { } ended && tunnel.LastOwnHangUpUtc is { } own
            && (ended.TimeUtc - own).Duration() <= OwnHangUpWindow;
        if (status != RasConnectionStatus.Gone)
        {
            // Разорванное или зависшее соединение держит запись RAS, пока его не отпустить: без RasHangUp
            // следующий дозвон упрётся в занятую запись.
            await ReleaseDeadConnectionAsync(tunnel, handle, cancellationToken);
        }

        if (reason == UserDisconnectReason && !ownHangUp && !_settings.AutoConnect)
        {
            OnExternalDisconnect(tunnel);
        }
        else
        {
            OnConnectionLost(tunnel, "соединение VPN разорвано" + (reason is { } code ? $" (код {code})" : ""));
        }

        return true;
    }

    /// <summary>Сколько RAS-соединение может считаться подключённым без своего интерфейса, прежде чем оно переподключается.</summary>
    internal static readonly TimeSpan AdapterMissingTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// RAS сообщает «подключено», а интерфейса PPP нет: не появился после дозвона или исчез. Пока срок не вышел,
    /// интерфейс ищется на каждой сверке; потом соединение разрывается и идёт обычное переподключение —
    /// иначе туннель без маршрутов так и числился бы поднятым.
    /// </summary>
    private async Task<bool> CheckAdapterPresentAsync(TunnelFacts tunnel, RasConnectionHandle handle, CancellationToken cancellationToken)
    {
        if (tunnel.Adapter is not null)
        {
            tunnel.AdapterMissingSinceUtc = null;
            return false;
        }

        var now = _deps.Time.GetUtcNow();
        tunnel.AdapterMissingSinceUtc ??= now;
        if (now - tunnel.AdapterMissingSinceUtc.Value < AdapterMissingTimeout)
        {
            return false;
        }

        _deps.Logger.LogWarning("RAS handle {Handle} ({Name}): интерфейс туннеля не найден за {Seconds} с", handle, tunnel.Name, AdapterMissingTimeout.TotalSeconds);
        await ReleaseDeadConnectionAsync(tunnel, handle, cancellationToken);
        OnConnectionLost(tunnel, "интерфейс VPN не найден в системе");
        return true;
    }

    private async Task ReleaseDeadConnectionAsync(TunnelFacts tunnel, RasConnectionHandle handle, CancellationToken cancellationToken)
    {
        try
        {
            tunnel.LastOwnHangUpUtc = _deps.Time.GetUtcNow();
            await _deps.Ras.HangUpAsync(handle, cancellationToken);
        }
        catch (Exception ex) when (ex is NativeCallException or InvalidOperationException or IOException or TimeoutException)
        {
            // Остаток уберёт следующий дозвон этой записи.
            _deps.Logger.LogWarning(ex, "RasHangUp разорванного соединения {Name} не удался", tunnel.Name);
        }
    }

    /// <summary>
    /// Подхват соединений своей телефонной книги по именам записей. Соединение, поднятое с другими
    /// параметрами безопасности, чем в профиле сейчас, не подхватывается: оно разрывается, чтобы
    /// следующий дозвон прошёл по актуальным настройкам.
    /// </summary>
    private async Task<bool> AdoptConnectionsAsync(CancellationToken cancellationToken)
    {
        var adopted = false;
        var own = _deps.Ras.FindOwnConnections();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { Connection: null, Dialing: false } && VpnProtocols.UsesRas(t.Protocol)))
        {
            var match = own.FirstOrDefault(c => string.Equals(c.EntryName, tunnel.EntryName, StringComparison.OrdinalIgnoreCase));
            if (match is null || _deps.Ras.GetStatus(match.Handle) != RasConnectionStatus.Connected)
            {
                continue;
            }

            if (!MatchesCurrentProfile(tunnel))
            {
                tunnel.LastOwnHangUpUtc = _deps.Time.GetUtcNow();
                await _deps.Ras.HangUpAsync(match.Handle, cancellationToken);
                Journal("Сведения", $"Соединение «{tunnel.Name}» разорвано: оно было поднято с другими параметрами входа.");
                continue;
            }

            AttachTunnel(tunnel, match.Handle);
            Journal("Сведения", $"Подхвачено существующее соединение «{tunnel.Name}».");
            adopted = true;
        }

        return adopted;
    }

    /// <summary>Отпечаток параметров подключения совпадает с тем, с которым соединение поднимали.</summary>
    private bool MatchesCurrentProfile(TunnelFacts tunnel)
    {
        if (_settings.Profile(tunnel.ProfileId) is not { } profile)
        {
            return false;
        }

        var recorded = _state.Servers.FirstOrDefault(s => s.ProfileId == tunnel.ProfileId)?.Fingerprint;
        return recorded is { } fingerprint
            ? fingerprint == VpnProtocols.ConnectionKey(profile)
            : profile.Protocol == VpnProtocol.Sstp && profile.AuthMethod == AuthMethod.MsChapV2;
    }

    /// <summary>ERROR_USER_DISCONNECTION: соединение разорвал пользователь, а не сеть.</summary>
    private const uint UserDisconnectReason = 631;

    /// <summary>
    /// VPN отключили не мы (меню сети Windows, rasdial): защита сохраняется, повторов нет — пользователь сам
    /// решил отключиться. Переподключение — командой «Подключить» (или автоматически, если включено автоподключение).
    /// </summary>
    private void OnExternalDisconnect(TunnelFacts tunnel)
    {
        tunnel.ResetConnection(_deps.Time.GetUtcNow());
        tunnel.ExternallyDisconnected = true;
        if (EssentialTunnels().Exists(t => t != tunnel && t.IsUp))
        {
            // Отключили один из туннелей, а «остальной интернет» по-прежнему идёт через другой: гасить всё
            // незачем. Этот туннель не дозванивается до «Подключить»; его трафик заблокирован, как при обрыве.
            Journal("Ошибка", $"«{tunnel.Name}» отключён из меню сети Windows или другой программой. Остальные подключения работают; «Подключить» — чтобы поднять его снова.");
            return;
        }

        _state = _state with { Intent = Intent.Protected };
        _deps.Stores.SaveState(_state);
        Journal("Ошибка", $"«{tunnel.Name}» отключён из меню сети Windows или другой программой. Защита сохранена; «Подключить» — чтобы подключиться снова.");
    }

    /// <summary>
    /// Обрыв соединения. Счётчик попыток обнуляет только проверенный сеанс, продержавшийся не меньше минуты:
    /// иначе «дозвон — обрыв через несколько секунд — дозвон» шёл бы без пауз, занимая службу.
    /// </summary>
    private void OnConnectionLost(TunnelFacts tunnel, string reason)
    {
        var now = _deps.Time.GetUtcNow();
        var stable = tunnel.WasStableSession(now);
        tunnel.ResetConnection(now);
        var next = stable ? "" : string.Create(CultureInfo.InvariantCulture,
            $" Следующая попытка через {ScheduleRetry(tunnel, now).TotalSeconds:F0} с.");
        Journal("Ошибка", $"Обрыв «{tunnel.Name}»: {reason}. Трафик этого туннеля заблокирован до переподключения.{next}");
    }

    private void AttachTunnel(TunnelFacts tunnel, RasConnectionHandle handle)
    {
        var projection = _deps.Ras.GetProjection(handle);
        var adapter = FindRasAdapter(tunnel, projection.ClientAddress, _deps.Inventory.Capture());
        _deps.Logger.LogInformation("Туннель {Name}: handle {Handle}, адрес {Address}, интерфейс {Interface} LUID {Luid} индекс {Index} up {Up}",
            tunnel.Name, handle, Ipv4.Format(projection.ClientAddress), adapter?.Name, adapter?.Luid, adapter?.InterfaceIndex, adapter?.IsUp);
        tunnel.Connection = handle;
        tunnel.Adapter = adapter;
        tunnel.AdapterMissingSinceUtc = null;
        // Для подхваченного соединения начало сеанса — по статистике RAS, а не по времени подхвата.
        tunnel.SessionStartedUtc ??= _deps.Time.GetUtcNow() - (_deps.Ras.GetStatistics(handle)?.Duration ?? TimeSpan.Zero);
        tunnel.EverConnected = true;
        tunnel.ResetVerification();
        // Новый сеанс — новый счёт проб: пробовать его начинаем сразу и с полного числа попыток.
        tunnel.NextVerifyAt = _deps.Time.GetUtcNow();
    }

    private bool DetectNetworkChange()
    {
        var snapshot = _deps.Inventory.Capture();
        var fingerprint = Fingerprint(snapshot);
        var changed = fingerprint != Facts.NetworkFingerprint;
        if (changed && fingerprint != _tracedFingerprint && _deps.Logger.IsEnabled(LogLevel.Debug))
        {
            // Одна строка на новое состояние сети, а не на каждый тик до его применения.
            _tracedFingerprint = fingerprint;
            _deps.Logger.LogDebug("Сеть изменилась: {Adapters}", NetworkSummary(snapshot));
        }

        return changed;
    }

    /// <summary>Последнее описанное в подробном журнале состояние сети.</summary>
    private string? _tracedFingerprint;

    /// <summary>«Wi-Fi[12] 192.168.1.5 шлюз 192.168.1.1 DNS 192.168.1.1; …» — поднятые адаптеры с адресами.</summary>
    private static string NetworkSummary(NetSnapshot snapshot) =>
        string.Join("; ", snapshot.Adapters.Where(a => a.IsUp && a.Addresses.Count > 0).OrderBy(a => a.Luid).Select(a => string.Create(CultureInfo.InvariantCulture,
            $"{a.Name}[{a.InterfaceIndex}] {string.Join(",", a.Addresses.Select(Ipv4.Format))} шлюз {(a.DefaultGateway is { } g ? Ipv4.Format(g) : "—")} метрика {a.DefaultRouteMetric?.ToString(CultureInfo.InvariantCulture) ?? "—"} DNS {string.Join(",", a.DnsServers.Select(Ipv4.Format))}")));

    private bool DetectBfeRestart()
    {
        var pid = _deps.BfeProcessId();
        if (pid == 0 || pid == Facts.BfeProcessId)
        {
            return false;
        }

        var restarted = Facts.BfeProcessId != 0;
        Facts.BfeProcessId = pid;
        if (restarted)
        {
            Journal("Ошибка", "Служба BFE перезапущена: static-фильтры пересоздаются.");
            _deps.Wfp.Reopen();
            Facts.AppliedFilters.Clear();
            Facts.ForceProtection = true;
        }

        return restarted;
    }

    private async Task HangUpAsync(TunnelFacts tunnel, string reason, CancellationToken cancellationToken)
    {
        if (tunnel.Connection is { } handle)
        {
            tunnel.LastOwnHangUpUtc = _deps.Time.GetUtcNow();
            await _deps.Ras.HangUpAsync(handle, cancellationToken);
        }

        StopAnyConnect(tunnel);
        Journal("Сведения", $"Соединение «{tunnel.Name}» разорвано: {reason}.");
        tunnel.Connection = null;
        tunnel.Session = null;
        tunnel.Adapter = null;
        tunnel.AdapterMissingSinceUtc = null;
        tunnel.ResetVerification();
        tunnel.SessionStartedUtc = null;
        tunnel.Statistics = null;
        Facts.AppliedFilters.Remove(FilterGroup.Runtime);
        EnsureRoutesSafe();
    }

    /// <summary>Политика уже собрана и защита не снята: маршруты и фильтры имеет смысл обновлять.</summary>
    private bool ProtectionActive => Facts.Policy is not null && _state.Intent != Intent.Off;

    private void EnsureRoutesSafe()
    {
        if (ProtectionActive)
        {
            var previousProgress = _workProgress;
            try
            {
                var timing = new ApplyTiming();
                SetProgress("Подготовка правил разделения трафика", 20);
                CompilePolicy();
                timing.Mark("политика");
                SetProgress("Применение сетевой защиты (WFP)", 25);
                EnsureProtection();
                timing.Mark("WFP");
                SetProgress("Применение маршрутов", 65);
                EnsureRoutes();
                CompletePins(applied: true);
                timing.Mark("маршруты");
                SetProgress("Настройка DNS", 85);
                SetProxyConfiguration(BuildProxyConfiguration());
                timing.Mark("DNS-посредник");
                timing.ReportIfSlow(_deps.Logger, "Обновление политики и маршрутов заняло");
            }
            finally
            {
                _workProgress = previousProgress;
            }
        }
    }

    private static string Fingerprint(NetSnapshot snapshot) =>
        string.Join(";", snapshot.Adapters.Where(a => a.IsUp && a.Addresses.Count > 0).OrderBy(a => a.Luid)
            .Select(a => string.Create(CultureInfo.InvariantCulture, $"{a.Luid}/{a.DefaultGateway}/{string.Join(",", a.Addresses)}")));

    private static List<uint> ParseAddresses(string text) =>
        text.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)
            .Select(s => Ipv4.TryParse(s, out var v) ? (uint?)v : null)
            .OfType<uint>()
            .Where(a => !SpecialRanges.Loopback.Contains(a))
            .ToList();

    private static IPEndPoint Endpoint(uint address) => new(Ipv4.ToAddress(address), 53);
}
