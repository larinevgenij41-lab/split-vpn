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
        var profiles = ActiveProfiles;
        var anchorProfile = _settings.PrimaryProfile ?? (profiles.Count > 0 ? profiles[0] : null);
        var pinned = anchorProfile?.PrimaryAdapter == AdapterSelection.Pinned ? anchorProfile.PinnedInterfaceGuid : null;
        var tunnelLuids = TunnelLuids();
        var result = PrimaryAdapterSelector.Select(
            snapshot.Adapters.Where(a => !tunnelLuids.Contains(a.Luid)).ToList(),
            pinned,
            anchorProfile?.AllowFallbackWhenPinnedMissing ?? false);
        if (result.Adapter?.Luid != Facts.Primary?.Luid)
        {
            Journal("Сведения", result.Adapter is null
                ? "Основной адаптер недоступен: трафик заблокирован до появления сети."
                : $"Основной адаптер: {result.Adapter.Name}.");
        }

        Facts.Primary = result.Adapter;
        Facts.NetworkFingerprint = Fingerprint(snapshot);
        Facts.Conflicts = PrimaryAdapterSelector.PublicOnLinkConflicts(snapshot.Adapters.Where(a => !tunnelLuids.Contains(a.Luid)))
            .Select(c => (c.Adapter.Name, c.Prefix)).ToList();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.Adapter is not null))
        {
            tunnel.Adapter = snapshot.Adapters.FirstOrDefault(a => a.Luid == tunnel.Adapter!.Luid) ?? tunnel.Adapter;
        }

        // Адаптер Wintun мог не попасть в снимок в момент события Established: ищем его по LUID сеанса.
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { Adapter: null, AnyConnect.Established: true }))
        {
            tunnel.Adapter = snapshot.Adapters.FirstOrDefault(a => a.Luid == tunnel.AnyConnect!.Luid);
        }

        _snapshot = snapshot;
    }

    private NetSnapshot? _snapshot;

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
        Bypass = _bypass.ActiveSet,
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
            Protocol = tunnel.Protocol,
            ServesDefault = carriers.Contains(tunnel.ProfileId),
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
            desired.AddRange(AllServerAddresses().Select(a => new RouteKey(new Ipv4Cidr(a, 32), gateway, primary.Luid)));

            // Прямые маршруты нужны только чтобы пробить дыры в паре /1: без неё прямой трафик и так
            // уходит по системному маршруту по умолчанию.
            if (_settings.DefaultTarget.IsVpn)
            {
                desired.AddRange(BaseRouteCidrs(Facts.Policy!.DirectRouteCidrs).Select(c => new RouteKey(c, gateway, primary.Luid)));
            }

            desired.AddRange(PinnedCidrs(RouteTarget.Direct).Select(c => new RouteKey(c, gateway, primary.Luid)));
        }

        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.Luid is not null))
        {
            // Интерфейс туннеля мог исчезнуть раньше, чем RAS сообщил об обрыве: маршрут на него не добавить.
            var luid = tunnel.Luid!.Value;
            if (_snapshot?.Adapters.Any(a => a.Luid == luid) != true)
            {
                continue;
            }

            if (tunnel.ProfileId == halfRouteTunnel)
            {
                desired.AddRange(HalfRoutes.Select(c => new RouteKey(c, 0, luid)));
            }
            else
            {
                desired.AddRange(BaseRouteCidrs(Facts.Policy!.RouteCidrsFor(tunnel.ProfileId)).Select(c => new RouteKey(c, 0, luid)));
            }

            desired.AddRange(PinnedCidrs(RouteTarget.Tunnel(tunnel.ProfileId)).Select(c => new RouteKey(c, 0, luid)));
        }

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

    private IEnumerable<Ipv4Cidr> BaseRouteCidrs(IReadOnlyList<Ipv4Cidr> cidrs) =>
        cidrs.Where(c => c.PrefixLength != 32 || !Facts.Policy!.IsPinned(c.Network));

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
                var guid = tunnel.Adapter!.InterfaceGuid;
                if (InterfaceDnsOps.IsLoopback(_deps.Dns.ReadNameServer(guid)) && _deps.Dns.Ipv6LoopbackMatches(guid))
                {
                    continue;
                }

                _deps.Dns.ApplyLoopback(guid);
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
            // IPv4 уже на посреднике, но ::1 мог не встать, если слушатель на [::1]:53 появился позже
            // (без слушателя IPv6 адаптера не трогается). Без копии исходного DNS 127.0.0.1 — собственный
            // резолвер пользователя: адаптер не трогаем.
            if (_deps.DnsBackups.Load().ContainsKey(interfaceGuid) && !_deps.Dns.Ipv6LoopbackMatches(interfaceGuid))
            {
                _deps.Dns.ApplyLoopback(interfaceGuid);
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
            _deps.DnsBackups.Upsert(_deps.Dns.Capture(interfaceGuid, null));
        }

        _deps.Dns.ApplyLoopback(interfaceGuid);
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

        var original = SplitSuffixes(backup.SearchList);
        var gateway = Facts.Tunnels.Values
            .Where(t => t is { IsUp: true, Session: not null })
            .SelectMany(t => t.Session!.SplitDns)
            .Select(s => s.Trim().TrimEnd('.'))
            .Where(s => s.Length > 0);
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
            LocalSuffixes = _settings.LocalDnsSuffixes,
            Local = local,
            DomainRoutes = BuildDomainRoutes(),
        };

        if (DnsAnchor is { } anchor)
        {
            return configuration with { Mode = DnsProxyMode.Online, Tunnel = TunnelDnsRoute(anchor) };
        }

        // «Остальной интернет» напрямую — не обрыв: DNS идёт исходным путём, иначе без опорного туннеля не разрешается ни одно имя.
        var directAllowed = _settings.DefaultTarget.Kind == TargetKind.Direct
            || _settings.DnsDirectOnOutage
            || (_settings.OutageMode == OutageMode.AllowAll && _state.Intent == Intent.Connected);
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
    private List<DomainRoute> BuildDomainRoutes()
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
        AddRevocationDomainRoutes(routes);
        return routes;
    }

    /// <summary>
    /// Узлы проверки отзыва сертификата сервера. Перед подключением Windows идёт к ним за списком отзыва,
    /// а за kill switch наружу открыты только разрешённые адреса — и исправный сертификат отклоняется с
    /// «проверка отзыва недоступна» (0x80092013). Имя разрешается напрямую, полученный адрес закрепляется
    /// и получает разрешающий фильтр. Подходящее правило пользователя важнее служебного, в том числе правило родительского домена.
    /// </summary>
    private void AddRevocationDomainRoutes(List<DomainRoute> routes)
    {
        foreach (var host in Facts.Tunnels.Values.SelectMany(t => t.RevocationHosts).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var suffix = SettingsSerializer.NormalizeSuffix(host);
            if (!IsRevocationHost(host) || MatchingDomainRule(host) is not null || routes.Exists(r => r.Suffix == suffix))
            {
                continue;
            }

            var route = DomainDnsRoute(RouteTarget.Direct);
            // Только само имя узла: его поддомены — обычные имена, они идут по политике.
            routes.Add(new DomainRoute(suffix, RouteTarget.Direct, route, PinAddresses: true, Unavailable: route is null, ExactName: true));
        }
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
        if (Facts.AppliedDnsConfiguration is { } applied && SameConfiguration(applied, configuration))
        {
            return;
        }

        _deps.DnsProxy.Configuration = configuration;
        Facts.AppliedDnsConfiguration = configuration;
        Facts.DnsMode = configuration.Mode;

        // Путь разрешения сменился: ответы прежнего пути к новому не относятся (split-DNS).
        _deps.DnsProxy.ClearCache();
        _deps.Dns.FlushCache();
    }

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
                _deps.Dns.Restore(backup.InterfaceGuid, backup);
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
            return false;
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
        var adapter = _deps.Inventory.Capture().Adapters.FirstOrDefault(a => a.Addresses.Contains(projection.ClientAddress));
        _deps.Logger.LogInformation("Туннель {Name}: handle {Handle}, адрес {Address}, интерфейс {Interface} LUID {Luid} индекс {Index} up {Up}",
            tunnel.Name, handle, Ipv4.Format(projection.ClientAddress), adapter?.Name, adapter?.Luid, adapter?.InterfaceIndex, adapter?.IsUp);
        tunnel.Connection = handle;
        tunnel.Adapter = adapter;
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
