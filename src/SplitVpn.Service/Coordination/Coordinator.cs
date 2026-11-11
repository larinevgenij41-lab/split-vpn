using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Единственный владелец системных изменений. Все события (IPC, таймер, результат дозвона, база)
/// проходят через один канал и обрабатываются последовательно; после каждого вызывается сверка
/// намерения пользователя с фактическим состоянием системы.
/// </summary>
public sealed partial class Coordinator
{
    public static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan FullReconcileInterval = TimeSpan.FromSeconds(60);

    private readonly ServiceDependencies _deps;
    // Номера общие для срока жизни координатора: пересозданный профиль не принимает старый ответ.
    private int _attemptGeneration;
    private readonly GeoManager _geo;

    /// <summary>Список обхода блокировок: то же устройство, что у RU-базы, своё хранилище и настройки.</summary>
    private readonly GeoManager _bypass;

    /// <summary>Обновление самой программы: проверка выпусков, загрузка установщика, подготовка установки.</summary>
    private readonly UpdateManager _update;

    /// <summary>
    /// Настройки заменяются только целиком (запись неизменяемая), поэтому ссылка читается и вне очереди актора:
    /// запрос настроек интерфейса не ждёт долгую сверку.
    /// </summary>
    private volatile AppSettings _settings;
    private ServiceStateFile _state;

    public Coordinator(ServiceDependencies deps)
    {
        _deps = deps;
        // Повреждённый служебный файл не мешает запуску: хранилище откладывает его копию и работает со
        // значениями по умолчанию, а находка идёт в журнал событий сразу и в предупреждения статуса — пока
        // служба не перезапущена.
        deps.CorruptFiles.Reported = file => Journal("Ошибка", file.Describe() + ". Причина: " + file.Error);
        deps.Stores.OnCorrupt = deps.CorruptFiles.Add;
        deps.DnsBackups.OnCorrupt = deps.CorruptFiles.Add;
        _settings = deps.Stores.LoadSettings(out _);
        _state = deps.Stores.LoadState();
        _geo = new GeoManager(deps);
        _bypass = new GeoManager(deps, GeoListKind.Bypass);
        _update = new UpdateManager(deps);
    }

    internal CoordinatorFacts Facts { get; } = new();

    internal AppSettings Settings => _settings;

    internal ServiceStateFile State => _state;

    internal async Task StartupAsync(CancellationToken cancellationToken)
    {
        if (_deps.Stores.Migrated)
        {
            Journal("Сведения", "Настройки переведены на новую схему; прежний файл сохранён как " + Path.GetFileName(_deps.Stores.PreviousSchemaBackup) + ".");
        }

        SetProgress("Загрузка настроек и списков адресов", 0);
        // Шаги независимы: сбой одного (файл занят антивирусом) не должен до перезапуска службы оставлять
        // без RU-базы, списка обхода, итога обновления или автоподключения.
        StartupStep("загрузка RU-базы", _geo.LoadActive);
        StartupStep("загрузка списка обхода", _bypass.LoadActive);
        StartupStep("состояние обновления программы", () => _update.StartUp(this));
        StartupStep("автоподключение", ApplyAutoConnect);
        Journal("Сведения", _state.ProtectionSuspended
            ? "Служба запущена; защита приостановлена командой восстановления сети."
            : $"Служба запущена; намерение: {_state.Intent}.");
        RefreshReadSnapshot();
        Facts.ForceProtection = true;
        await ReconcileAsync(cancellationToken);
        _started = true;
        RefreshReadSnapshot();
    }

    internal async Task TickAsync(CancellationToken cancellationToken)
    {
        var now = _deps.Time.GetUtcNow();
        // Каждый шаг тика изолирован: исключение в одном (сбой опроса RAS, чтения адаптеров) не отменяет
        // остальные, иначе одна ошибка останавливала бы и сверку, и обновление списков, и проверку выпусков.
        // Сбой шага считается изменением: сверка всё равно пройдёт и проверит фактическое состояние.
        var changed = await TickStepAsync("проверка соединений", () => MonitorConnectionsAsync(cancellationToken), cancellationToken)
            | TickStep("смена сети", DetectNetworkChange, cancellationToken)
            | TickStep("перезапуск BFE", DetectBfeRestart, cancellationToken)
            | TickStep("истёкшие закрепления", () => DropExpiredPins(now), cancellationToken);
        TickStep("проверка конфликтов", () => { CheckConflictsAfterNetworkChange(now); return false; }, cancellationToken);
        // Отсчёт от последней полной сверки, а не от любой: частые обычные сверки (повторы дозвона, истечение
        // закреплений) иначе откладывали бы проверку фильтров и маршрутов, изменённых извне, бесконечно.
        var periodic = now - Facts.LastForcedReconcile >= FullReconcileInterval;

        // После неполного применения сверка повторяется с растущей паузой (2→4→…→60 с), иначе служба
        // перебирает все фильтры BFE каждые 2 с. Изменения в сети и периодическая сверка паузу не ждут.
        var paused = Facts.PartialError is not null && now < Facts.PartialErrorRetryAt;
        if (changed || periodic || Facts.ReconcilePending || (!paused && (Facts.PartialError is not null || DialDue(now) || VerifyDue(now))))
        {
            Facts.ForceProtection |= periodic;
            if (_deps.Logger.IsEnabled(LogLevel.Debug))
            {
                _deps.Logger.LogDebug("Сверка: {Reasons}", string.Join(", ", new[]
                {
                    changed ? "изменились сеть, соединения или BFE" : null,
                    periodic ? "периодическая" : null,
                    Facts.ReconcilePending ? "назначена" : null,
                    !paused && Facts.PartialError is not null ? "повтор после ошибки: " + Facts.PartialError : null,
                    !paused && DialDue(now) ? "пора дозвона" : null,
                    !paused && VerifyDue(now) ? "проверка туннеля" : null,
                }.OfType<string>()));
            }

            await TickStepAsync("сверка", async () => { await ReconcileAsync(cancellationToken); return false; }, cancellationToken);
        }

        await TickStepAsync("списки стран", async () => { await _geo.TickAsync(this, cancellationToken); return false; }, cancellationToken);
        await TickStepAsync("списки обхода", async () => { await _bypass.TickAsync(this, cancellationToken); return false; }, cancellationToken);
        await TickStepAsync("обновления", async () => { await _update.TickAsync(this, cancellationToken); return false; }, cancellationToken);
    }

    private void StartupStep(string name, Action step)
    {
        try
        {
            step();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _deps.Logger.LogError(ex, "Запуск службы: шаг «{Step}» не выполнен", name);
            Journal("Ошибка", $"Запуск службы: шаг «{name}» не выполнен ({ex.Message}), остальные выполнены.");
        }
    }

    private bool TickStep(string name, Func<bool> step, CancellationToken cancellationToken)
    {
        try
        {
            return step();
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return TickStepFailed(name, ex);
        }
    }

    private async Task<bool> TickStepAsync(string name, Func<Task<bool>> step, CancellationToken cancellationToken)
    {
        try
        {
            return await step();
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return TickStepFailed(name, ex);
        }
    }

    private bool TickStepFailed(string name, Exception ex)
    {
        _deps.Logger.LogError(ex, "Тик службы: сбой шага «{Step}»; остальные шаги выполняются", name);
        // Шаг мог прерваться посреди применения: следующая сверка проверит всё, а не только изменения.
        Facts.ForceProtection = true;
        return true;
    }

    internal void Journal(string level, string text)
    {
        _deps.Journal.Add(level, text);
        _deps.Logger.Log(level is "Ошибка" or "Предупреждение" ? LogLevel.Warning : LogLevel.Information, "{Event}", text);
    }

    /// <summary>Профили, которые служба поднимает: опорный первым.</summary>
    internal IReadOnlyList<ConnectionProfile> ActiveProfiles => _settings.ActiveProfiles;

    /// <summary>
    /// Туннель, чей DNS используется по умолчанию: первый поднятый среди несущих «остальной интернет». DNS идёт
    /// тем же путём, что и трафик: «остальной интернет» напрямую — DNS провайдера, его туннель лежит — правила
    /// обрыва. DNS чужого туннеля давал бы адреса, подобранные для другой страны или сети, и медленные сайты.
    /// Исключение — «Блокировать»: у остального трафика пути нет, а имена сайтов из правил по адресам (без правила
    /// для домена) разрешать нужно, и они разрешаются через опорный туннель, как раньше.
    /// </summary>
    internal TunnelFacts? DnsAnchor =>
        DefaultCarriers.Select(id => Facts.Tunnels.GetValueOrDefault(id)).FirstOrDefault(t => t?.Luid is not null)
        ?? (_settings.DefaultTarget.Kind == TargetKind.Block
            ? Facts.Tunnels.Values.FirstOrDefault(t => t.Luid is not null && t.Role == ProfileRole.Primary)
                ?? Facts.Tunnels.Values.FirstOrDefault(t => t.Luid is not null && t.Protocol != VpnProtocol.AnyConnect)
            : null);

    /// <summary>Профили, которым назначен «остальной интернет»: один туннель или участники группы.</summary>
    internal IReadOnlyList<Guid> DefaultCarriers => Carriers(_settings.DefaultTarget);

    /// <summary>Профили, стоящие за целью: сам туннель или участники группы в порядке предпочтения.</summary>
    internal IReadOnlyList<Guid> Carriers(RouteTarget target)
    {
        if (target.IsTunnel(out var tunnel))
        {
            return [tunnel];
        }

        return target.IsGroup(out var group) ? _settings.Group(group)?.Members ?? [] : [];
    }

    /// <summary>
    /// Годные участники групп на текущий момент: при распределении — все поднятые, при резервировании —
    /// первый поднятый. Пустой список означает, что группа недоступна целиком.
    /// </summary>
    internal IReadOnlyList<TunnelGroup> ResolveGroups()
    {
        var groups = new List<TunnelGroup>(_settings.Groups.Count);
        foreach (var group in _settings.Groups)
        {
            var up = group.Members.Where(id => Facts.Tunnels.GetValueOrDefault(id)?.Luid is not null).ToList();
            groups.Add(new TunnelGroup(group.Id, group.Mode == BalanceMode.Failover ? up.Take(1).ToList() : up));
        }

        return groups;
    }

    internal ConnectionState DeriveState()
    {
        if (_state.ProtectionSuspended || _state.Intent != Intent.Connected)
        {
            if (Facts.PartialError is not null && !_state.ProtectionSuspended)
            {
                return ConnectionState.PartiallyApplied;
            }

            var externally = Facts.Tunnels.Values.Any(t => t.ExternallyDisconnected);
            return externally && _state.Intent == Intent.Protected ? ConnectionState.DisconnectedExternally : ConnectionState.Disconnected;
        }

        return DeriveConnectedState();
    }

    /// <summary>
    /// Общее состояние при включённом VPN — по туннелям, от которых зависит «остальной интернет»: один туннель
    /// или участники группы (достаточно одного поднятого). Если остальной интернет идёт не в VPN — по опорному.
    /// Сбой дополнительного туннеля виден в его строке и в тексте ошибки, но не превращает всё в «Ошибку».
    /// </summary>
    private ConnectionState DeriveConnectedState()
    {
        if (Facts.PartialError is not null)
        {
            return ConnectionState.PartiallyApplied;
        }

        var tunnels = EssentialTunnels();
        if (tunnels.Count == 0)
        {
            return ConnectionState.Error;
        }

        if (tunnels.Exists(t => t.IsUp))
        {
            return tunnels.Exists(t => t.IsUp && t.Verified) ? ConnectionState.Connected : ConnectionState.ApplyingRoutes;
        }

        // Всё, что несёт «остальной интернет», положено пользователем: никто не подключается, а трафик
        // заблокирован защитой. «Подключение» здесь было бы неправдой.
        if (tunnels.TrueForAll(t => t.Paused))
        {
            return ConnectionState.TrafficBlocked;
        }

        if (tunnels.TrueForAll(t => t.BlockingError != ErrorCategory.None))
        {
            return ConnectionState.Error;
        }

        if (tunnels.Exists(t => t.PasswordRequired && t.BlockingError == ErrorCategory.None))
        {
            return ConnectionState.PasswordRequired;
        }

        if (Facts.Primary is null)
        {
            return ConnectionState.TrafficBlocked;
        }

        return tunnels.Exists(t => t.EverConnected) ? ConnectionState.Reconnecting : ConnectionState.Connecting;
    }

    /// <summary>Туннели, определяющие общее состояние: носители «остального интернета», иначе опорный, иначе все.</summary>
    private List<TunnelFacts> EssentialTunnels()
    {
        var carriers = DefaultCarriers.Select(id => Facts.Tunnels.GetValueOrDefault(id)).OfType<TunnelFacts>().ToList();
        if (carriers.Count > 0)
        {
            return carriers;
        }

        var primary = Facts.Tunnels.Values.Where(t => t.Role == ProfileRole.Primary).ToList();
        return primary.Count > 0 ? primary : Facts.Tunnels.Values.ToList();
    }

    /// <summary>Все существующие туннели из списка положены пользователем; пустой список - нет.</summary>
    private bool AllPaused(IEnumerable<Guid> profiles)
    {
        var tunnels = profiles.Select(id => Facts.Tunnels.GetValueOrDefault(id)).OfType<TunnelFacts>().ToList();
        return tunnels.Count > 0 && tunnels.TrueForAll(t => t.Paused);
    }

    /// <summary>
    /// Трафик недоступного туннеля или группы идёт напрямую. «Разрешить всё» действует только для «остального
    /// интернета» и только при обрыве: носители, положенные пользователем, - не обрыв, их трафик заблокирован,
    /// как и назначения остальных туннелей (см. FilterPlanBuilder.IsOutage).
    /// </summary>
    private bool DirectOnOutage(Guid tunnelOrGroup) =>
        _settings.OutageMode == OutageMode.AllowAll && _state.Intent == Intent.Connected && !AllPaused(DefaultCarriers)
        && DefaultCarriers.All(id => Facts.Tunnels.GetValueOrDefault(id) is not { IsUp: true })
        && (DefaultCarriers.Contains(tunnelOrGroup) || (_settings.DefaultTarget.IsGroup(out var group) && group == tunnelOrGroup));

    internal StatusDto BuildStatus()
    {
        var geoState = _geo.StoreState;
        var anchor = DnsAnchor ?? Facts.Tunnels.Values.FirstOrDefault();
        return new StatusDto
        {
            Progress = CurrentProgress(ConnectionProgress()),
            ContractVersion = IpcNames.ContractVersion,
            VerboseUntilUtc = _deps.Verbose?.UntilUtc,
            // До конца первой сверки факты о туннелях ещё не собраны: вместо «Ошибки» — подготовка защиты.
            State = !_started && !_state.ProtectionSuspended && _state.Intent != Intent.Off ? ConnectionState.PreparingProtection : DeriveState(),
            Intent = _state.Intent,
            ProtectionActive = !_state.ProtectionSuspended && _state.Intent != Intent.Off,
            ProtectionSuspended = _state.ProtectionSuspended,
            OutageMode = _settings.OutageMode,
            DefaultTargetName = _settings.TargetName(_settings.DefaultTarget),
            GeoTargetName = _settings.TargetName(_geo.HasBase ? _settings.GeoTarget : _settings.DefaultTarget),
            Tunnels = BuildTunnelStatus(),
            ProfileName = anchor?.Name,
            Protocol = anchor is null ? null : _settings.Profile(anchor.ProfileId)?.Protocol,
            AuthMethod = anchor is null ? null : _settings.Profile(anchor.ProfileId)?.AuthMethod,
            PrimaryAdapterName = Facts.Primary?.Name,
            VpnAddress = anchor?.Adapter is { Addresses.Count: > 0 } adapter ? Ipv4.Format(adapter.Addresses[0]) : null,
            TunnelAddress = anchor?.Adapter?.Name,
            ServerAddress = string.Join(", ", (anchor?.ServerAddresses ?? []).Select(Ipv4.Format)),
            SessionStartedUtc = anchor?.SessionStartedUtc,
            BytesSent = (ulong)Facts.Tunnels.Values.Sum(t => (long)(t.Statistics?.BytesSent ?? 0)),
            BytesReceived = (ulong)Facts.Tunnels.Values.Sum(t => (long)(t.Statistics?.BytesReceived ?? 0)),
            ErrorCategory = FirstError(t => t.BlockingError) != ErrorCategory.None ? FirstError(t => t.BlockingError) : FirstError(t => t.LastErrorCategory),
            ErrorText = Facts.PartialError ?? Facts.ConfigError ?? Facts.Tunnels.Values.Select(t => t.LastErrorText).FirstOrDefault(t => t is not null),
            ErrorCode = Facts.Tunnels.Values.Select(t => t.LastErrorCode).FirstOrDefault(c => c is not null),
            // Расшифровка — того же туннеля, чей текст ошибки показан: у сбоя применения и настроек её нет.
            ErrorHelp = Facts.PartialError is null && Facts.ConfigError is null ? FirstTunnelHelp() : null,
            DnsViaProvider = Facts.DnsMode == Windows.Dns.DnsProxyMode.DirectAllowed,
            Ipv6Restricted = true,
            GeoRevision = geoState.Active,
            GeoDownloadedUtc = _geo.ActiveRevision?.DownloadedUtc,
            GeoV4Count = _geo.ActiveRevision?.V4Count ?? 0,
            GeoV6Count = _geo.ActiveRevision?.V6Count ?? 0,
            GeoPendingRevision = geoState.Pending,
            GeoPendingReason = geoState.PendingReason,
            GeoLastCheckUtc = geoState.LastCheckUtc,
            GeoNextCheckUtc = geoState.NextCheckUtc,
            GeoLastResult = geoState.LastResult,
            GeoSkippedCount = geoState.Skipped.Count,
            Bypass = BuildListStatus(_bypass),
            Update = _update.BuildStatus(),
            Warnings = BuildWarnings(),
        };
    }

    private ErrorCategory FirstError(Func<TunnelFacts, ErrorCategory> select) =>
        Facts.Tunnels.Values.Select(select).FirstOrDefault(c => c != ErrorCategory.None);

    private List<TunnelStatusDto> BuildTunnelStatus()
    {
        var carriers = DefaultCarriers;
        return ActiveProfiles
            .Where(profile => Facts.Tunnels.ContainsKey(profile.Id))
            .Select(profile => BuildTunnelStatus(profile, Facts.Tunnels[profile.Id], carriers))
            .ToList();
    }

    private TunnelStatusDto BuildTunnelStatus(ConnectionProfile profile, TunnelFacts tunnel, IReadOnlyList<Guid> carriers) =>
        new()
        {
            ProfileId = tunnel.ProfileId,
            Name = tunnel.Name,
            Role = tunnel.Role,
            // Протокол и способ входа — из профиля: иначе у AnyConnect в отчёте и CLI стоял бы SSTP.
            Protocol = profile.Protocol,
            AuthMethod = profile.AuthMethod,
            State = TunnelState(tunnel),
            IsAnchor = carriers.Contains(tunnel.ProfileId),
            Paused = tunnel.Paused,
            VpnAddress = tunnel.Adapter is { Addresses.Count: > 0 } a ? Ipv4.Format(a.Addresses[0]) : null,
            AdapterName = tunnel.Adapter?.Name,
            ServerAddress = string.Join(", ", tunnel.ServerAddresses.Select(Ipv4.Format)),
            SessionStartedUtc = tunnel.SessionStartedUtc,
            BytesSent = tunnel.Statistics?.BytesSent ?? 0,
            BytesReceived = tunnel.Statistics?.BytesReceived ?? 0,
            ErrorCategory = tunnel.BlockingError != ErrorCategory.None ? tunnel.BlockingError : tunnel.LastErrorCategory,
            ErrorText = tunnel.LastErrorText,
            ErrorCode = tunnel.LastErrorCode,
            ErrorHelp = ErrorHelp(profile, tunnel),
            ServerCertificate = tunnel.ServerCertificate,
            SignIn = SignInPromptOf(tunnel),
            ServerNetworks = ServerNetworksOf(tunnel),
        };

    private ConnectionState TunnelState(TunnelFacts tunnel)
    {
        if (_state.ProtectionSuspended || _state.Intent != Intent.Connected)
        {
            return tunnel.ExternallyDisconnected && _state.Intent == Intent.Protected
                ? ConnectionState.DisconnectedExternally
                : ConnectionState.Disconnected;
        }

        // Положенный туннель не подключается и не чинится: показывать «Подключение» или прежнюю ошибку — врать.
        if (tunnel.Paused)
        {
            return ConnectionState.Disconnected;
        }

        if (tunnel.BlockingError != ErrorCategory.None)
        {
            return ConnectionState.Error;
        }

        if (tunnel.ExternallyDisconnected)
        {
            return ConnectionState.DisconnectedExternally;
        }

        if (tunnel.PasswordRequired)
        {
            return ConnectionState.PasswordRequired;
        }

        if (tunnel.IsUp)
        {
            return tunnel.Verified ? ConnectionState.Connected : ConnectionState.ApplyingRoutes;
        }

        if (Facts.Primary is null)
        {
            return ConnectionState.TrafficBlocked;
        }

        return tunnel.EverConnected ? ConnectionState.Reconnecting : ConnectionState.Connecting;
    }

    private List<StatusWarning> BuildWarnings()
    {
        var warnings = new List<StatusWarning>();
        foreach (var file in _deps.CorruptFiles.All)
        {
            warnings.Add(new StatusWarning("data-corrupt", file.Describe(), null));
        }

        if (!_geo.HasBase)
        {
            warnings.Add(new StatusWarning("no-geo", "RU-база не загружена: российские адреса идут туда же, куда остальной интернет.", "geo-update"));
        }

        if (_state is { Intent: Intent.Connected, ProtectionSuspended: false }
            && ActiveProfiles.Select(p => Facts.Tunnels.GetValueOrDefault(p.Id)).FirstOrDefault(t => t is { PasswordRequired: true, BlockingError: ErrorCategory.None, Paused: false }) is { } waiting)
        {
            // Опорный туннель лежит: защита при обрыве блокирует DNS и трафик, и страница входа не откроется.
            // Об этом нужно сказать сразу — иначе вход выглядит просто сломанным.
            var blockedByOutage = waiting.Protocol == VpnProtocol.AnyConnect && Facts.DnsMode == Windows.Dns.DnsProxyMode.Offline;
            warnings.Add(waiting.Protocol == VpnProtocol.AnyConnect
                ? new StatusWarning("sign-in-required", $"Требуется вход в «{waiting.Name}»."
                    + (blockedByOutage
                        ? " Опорное подключение не поднято, и защита при обрыве блокирует остальной трафик: страница входа может не открыться."
                            + " Поднимите опорное подключение, снимите защиту или включите «Разрешать DNS напрямую при обрыве» в «Защите и DNS»."
                        : ""), "sign-in")
                : new StatusWarning("password-required", $"Требуется пароль для «{waiting.Name}».", "enter-password"));
        }

        if (Facts.RussianTargetUnreachable && _state is { Intent: Intent.Connected, ProtectionSuspended: false })
        {
            warnings.Add(new StatusWarning("russian-target-direct",
                $"Российская контрольная цель {_settings.CheckTargets.Russian} недоступна напрямую: проверьте прямой доступ у провайдера — туннель при этом работает.", null));
        }

        if (Facts.PinnedAdapterMissing && _state.Intent == Intent.Connected)
        {
            warnings.Add(Facts.PinnedAdapterOffline is { } offline
                ? new StatusWarning("pinned-adapter-offline",
                    $"Ждём подключения закреплённого адаптера «{offline}» к сети: VPN поднимется, когда он подключится. До этого трафик заблокирован.", null)
                : new StatusWarning("pinned-adapter-missing",
                    (Facts.PinnedAdapterDisconnected is { } disconnected
                        ? $"Закреплённый основной адаптер «{disconnected}» не подключён к сети (выключен или без кабеля): VPN не поднимается, трафик заблокирован."
                        : "Закреплённый основной адаптер не найден (например, после сброса сети Windows): VPN не поднимается, трафик заблокирован.")
                    + " Выберите адаптер заново в настройках подключения или включите переход на другой адаптер.", null));
        }

        if (_geo.StoreState is { Pending: not null } geoState)
        {
            warnings.Add(new StatusWarning("geo-pending", "Новая RU-база ждёт подтверждения: " + geoState.PendingReason, "geo-review"));
        }

        foreach (var (adapter, prefix) in Facts.Conflicts)
        {
            warnings.Add(new StatusWarning("public-onlink", $"Интерфейс «{adapter}» использует публичную сеть {prefix}: доступ к ней зависит от настройки «Локальный доступ».", null));
        }

        warnings.AddRange(OnLinkRuleWarnings());
        warnings.AddRange(SkippedSettingsWarnings());

        if (_state is { Intent: Intent.Connected, ProtectionSuspended: false })
        {
            warnings.AddRange(GroupWarnings());
            warnings.AddRange(PausedWarnings());
        }

        warnings.AddRange(BypassWarnings());
        warnings.AddRange(UpdateWarnings());
        warnings.AddRange(CertificateWarnings());
        warnings.AddRange(Facts.ConflictWarnings);
        if (!_state.ProtectionSuspended && _state.Intent != Intent.Off)
        {
            warnings.Add(new StatusWarning("ipv6-restricted", "IPv6 ограничен: публичный IPv6 блокируется, пока включена защита.", null));
        }
        return warnings;
    }

    /// <summary>
    /// Правило на сеть своего адаптера молча не действует: её адреса остаются в локальной сети. Так бывает,
    /// когда удалённая сеть за VPN совпадает с домашней — человек должен узнать об этом из программы.
    /// </summary>
    private IEnumerable<StatusWarning> OnLinkRuleWarnings()
    {
        var onLink = RangeSet.From(OnLinkPrefixes());
        if (onLink.Count == 0)
        {
            yield break;
        }

        // Неразобранные правила здесь не нужны: о них говорит SkippedSettingsWarnings.
        var (rules, _) = SettingsSerializer.ParseRules(_settings.Rules);
        foreach (var rule in rules.Where(r => r.Target.Kind != TargetKind.Direct && onLink.Overlaps(r.Cidr.ToRange())))
        {
            yield return new StatusWarning("rule-onlink",
                $"Правило {rule.Cidr} пересекается с сетью своего адаптера: для её адресов правило не действует, они остаются в локальной сети.", null);
        }
    }

    /// <summary>О каких пропущенных записях настроек уже сказано в журнале: сверка идёт каждые 60 с, запись — одна.</summary>
    private readonly ConcurrentDictionary<string, bool> _reportedSkippedSettings = new(StringComparer.Ordinal);

    /// <summary>
    /// Записи настроек, которые служба не разобрала (например, адрес с ведущими нулями после ужесточения
    /// разбора IPv4), пропускаются, а не роняют сверку: остальная политика продолжает действовать.
    /// </summary>
    private IEnumerable<string> SkippedSettings()
    {
        var (_, errors) = SettingsSerializer.ParseRules(_settings.Rules);
        foreach (var error in errors)
        {
            yield return "Правило пропущено: " + error;
        }

        foreach (var text in _settings.UpstreamDns.Where(text => !Ipv4.TryParse(text, out _)))
        {
            yield return $"Адрес DNS через VPN «{text}» не разобран и пропущен.";
        }
    }

    private IEnumerable<StatusWarning> SkippedSettingsWarnings() =>
        SkippedSettings().Select(text => new StatusWarning("settings-skipped", text, null));

    /// <summary>Пропущенные записи настроек — в журнал, о каждой однократно.</summary>
    private void ReportSkippedSettings()
    {
        foreach (var text in SkippedSettings())
        {
            if (_reportedSkippedSettings.TryAdd(text, true))
            {
                Journal("Предупреждение", text);
            }
        }
    }

    /// <summary>Адреса DNS через VPN из настроек; неразобранные пропускаются (о них — ReportSkippedSettings).</summary>
    private List<uint> UpstreamDnsAddresses()
    {
        var result = new List<uint>(_settings.UpstreamDns.Count);
        foreach (var text in _settings.UpstreamDns)
        {
            if (Ipv4.TryParse(text, out var address))
            {
                result.Add(address);
            }
        }

        return result;
    }

    /// <summary>
    /// Туннели, положенные пользователем. Про носителя «остального интернета» говорится отдельно: его отключение
    /// оставляет без интернета вообще, и человек должен понимать, что это сделал он, а не поломка.
    /// </summary>
    private IEnumerable<StatusWarning> PausedWarnings()
    {
        var carriers = DefaultCarriers;
        foreach (var tunnel in ActiveProfiles.Select(p => Facts.Tunnels.GetValueOrDefault(p.Id)).OfType<TunnelFacts>().Where(t => t.Paused))
        {
            yield return new StatusWarning("tunnel-paused",
                $"Подключение «{tunnel.Name}» отключено вами: назначенный ему трафик заблокирован."
                + (carriers.Contains(tunnel.ProfileId) ? " Остальной интернет не работает, пока вы не включите его обратно." : ""),
                null);
        }
    }

    /// <summary>
    /// Группы, в которых поднята не вся команда: сколько доступно и что стало с трафиком. Группа без живых
    /// участников — отдельный текст: её трафик заблокирован (или идёт напрямую при «Разрешить всё»).
    /// </summary>
    private IEnumerable<StatusWarning> GroupWarnings()
    {
        foreach (var group in _settings.Groups.Where(g => g.Members.Count > 0))
        {
            var up = group.Members.Count(id => Facts.Tunnels.GetValueOrDefault(id)?.Luid is not null);
            if (up == group.Members.Count)
            {
                continue;
            }

            var outcome = up == 0
                ? DirectOnOutage(group.Id) ? "её трафик идёт напрямую." : "её трафик заблокирован до переподключения."
                : group.Mode == BalanceMode.Distribute ? "нагрузка перераспределена."
                : Facts.Tunnels.GetValueOrDefault(group.Members[0])?.Luid is not null ? "резервное подключение недоступно." : "трафик идёт через резервное подключение.";
            yield return new StatusWarning("group-degraded",
                string.Create(CultureInfo.InvariantCulture, $"В группе «{group.Name}» доступно {up} из {group.Members.Count}: {outcome}"), null);
        }
    }

    /// <summary>
    /// Кому-то пора дозваниваться. Туннели, которым дозвон сейчас запрещён, исключены намеренно: у них
    /// <c>NextDialAt</c> в прошлом навсегда, и без этого тик гонял бы полную сверку каждые две секунды, пока
    /// пользователь не вмешается. Это положенный туннель, туннель с блокирующей ошибкой (пароль, сертификат) или
    /// без сохранённого пароля, а также любой туннель без основного адаптера. Снятие каждого запрета само
    /// назначает сверку: команда пользователя применяется, новый адаптер замечается как изменение сети.
    /// </summary>
    private bool DialDue(DateTimeOffset now) =>
        _state.Intent == Intent.Connected && !Facts.ProfileTestRunning && Facts.Primary is not null
        && Facts.Tunnels.Values.Any(t => t.Connection is null && VpnProtocols.UsesRas(t.Protocol)
            && !t.Dialing && !t.Paused && !t.ExternallyDisconnected && now >= t.NextDialAt
            && t.BlockingError == ErrorCategory.None && !t.PasswordRequired
            && (t.ServerAddresses.Count > 0 || (!t.ServerResolving && now >= t.NextServerResolveAt)));

    /// <summary>
    /// Туннель поднят, но ещё не проверен, и подошёл срок следующей пробы. Дозвона такому туннелю не нужно,
    /// поэтому <see cref="DialDue"/> его не видит — без отдельного условия пауза между пробами не кончалась бы.
    /// </summary>
    private bool VerifyDue(DateTimeOffset now) =>
        _state.Intent == Intent.Connected && !Facts.ProfileTestRunning
        && Facts.Tunnels.Values.Any(t => t.IsUp && !t.Verified && !t.Verifying && now >= t.NextVerifyAt);

    private static readonly TimeSpan AutoConnectBootWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ConflictCheckInterval = TimeSpan.FromMinutes(5);

    /// <summary>Разброс, с которым совпадают два замера времени загрузки: часы системы могут подвести их за 10 минут окна.</summary>
    private static readonly TimeSpan BootTimeTolerance = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Автоподключение при запуске Windows: только сразу после загрузки (перезапуск службы намерение не меняет),
    /// один раз за загрузку, только с сохранёнными паролями и не после команды восстановления сети.
    /// </summary>
    private void ApplyAutoConnect()
    {
        var profiles = _settings.ActiveProfiles;
        var eligible = _settings.AutoConnect && !_state.ProtectionSuspended && _state.Intent != Intent.Connected
            && _deps.SystemUptime() < AutoConnectBootWindow
            && profiles.Count > 0
            && profiles.All(p => !VpnProtocols.NeedsPassword(p.AuthMethod) || (p.SavePassword && _deps.Secrets.Contains(p.Id)))
            && profiles.All(p => !VpnProtocols.NeedsPreSharedKey(p) || _deps.Secrets.Contains(p.Id, SecretKind.PreSharedKey));
        if (!eligible)
        {
            return;
        }

        // Автоподключение применяется один раз за загрузку: иначе перезапуск службы в первые 10 минут после
        // включения компьютера отменил бы команду «Отключить», которую пользователь только что дал.
        var boot = BootTime();
        if (_state.AutoConnectBootUtc is { } applied && (boot - applied).Duration() <= BootTimeTolerance)
        {
            return;
        }

        _state = _state with { Intent = Intent.Connected, AutoConnectBootUtc = boot };
        _deps.Stores.SaveState(_state);
        Journal("Сведения", "Автоподключение при запуске Windows.");
    }

    /// <summary>Время загрузки системы, округлённое до минуты: признак текущей загрузки в файле состояния.</summary>
    private DateTimeOffset BootTime()
    {
        var boot = _deps.Time.GetUtcNow() - _deps.SystemUptime();
        return new DateTimeOffset(boot.UtcDateTime.AddTicks(-(boot.UtcDateTime.Ticks % TimeSpan.TicksPerMinute)), TimeSpan.Zero);
    }

    /// <summary>
    /// Детектор конфликтов раз в 5 минут; новые конфликты — в журнал событий. Неудачная проверка туннеля
    /// запускает его сразу (force): иначе причина — чужое VPN-подключение — появлялась бы через несколько минут
    /// после начала цикла переподключений. Детектор перечисляет все фильтры WFP и маршруты системы (сотни
    /// миллисекунд), поэтому работает в фоновой задаче, а очередь актора получает только результат.
    /// </summary>
    private bool CheckConflicts(DateTimeOffset now, bool force = false)
    {
        if (Facts.ConflictCheckRunning || (!force && now - Facts.LastConflictCheck < ConflictCheckInterval))
        {
            return false;
        }

        Facts.LastConflictCheck = now;
        // В фоновую задачу уходят только значения: Facts принадлежат очереди актора.
        var tunnels = Facts.Tunnels.Values
            .Where(t => t.Luid is not null)
            .Select(t => new Windows.Diagnostics.ConflictTunnel(t.Luid!.Value, t.Name))
            .ToList();
        var inputs = new Windows.Diagnostics.ConflictInputs(tunnels, ConflictServers(), ConflictResolver());
        // Признак ставится, когда входные данные собраны: сбой их сборки (файл копии DNS занят) иначе оставил бы
        // его навсегда, и проверка конфликтов не шла бы до перезапуска службы.
        Facts.ConflictCheckRunning = true;
        var detect = _deps.DetectConflicts;
        _ = Task.Run(async () =>
        {
            IReadOnlyList<StatusWarning>? found = null;
            try
            {
                found = detect(inputs);
            }
            catch (Exception ex)
            {
                // Любой сбой детектора — просто непроверенные конфликты: очередь обязана получить ответ,
                // иначе флаг работы не снимется и детектор больше не запустится.
                _deps.Logger.LogWarning(ex, "Детектор конфликтов недоступен");
            }

            await EnqueueAsync("Conflicts", () =>
            {
                OnConflictsDetected(found);
                return Task.CompletedTask;
            });
        });
        return true;
    }

    /// <summary>Не чаще этого детектор запускается по уведомлениям о смене сети.</summary>
    internal static readonly TimeSpan NetworkChangeConflictCheckInterval = TimeSpan.FromSeconds(10);

    /// <summary>Сколько детектор ждёт разрешения одного имени сервера.</summary>
    private static readonly TimeSpan ConflictResolveTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Чужое VPN-подключение Windows поднимает свой интерфейс, и об этом приходит уведомление о смене сети.
    /// Детектор по нему запускается сразу (не чаще раза в 10 с), а не через 5 минут обычного интервала:
    /// иначе подключение Windows к тому же серверу минутами рвало бы связь без объяснения. Запрос, который
    /// не удалось выполнить сейчас (детектор уже работает или 10 с не прошли), ждёт следующего тика.
    /// </summary>
    private void CheckConflictsAfterNetworkChange(DateTimeOffset now)
    {
        if (Interlocked.Exchange(ref _conflictCheckRequested, 0) == 0)
        {
            CheckConflicts(now);
            return;
        }

        var due = now - Facts.LastConflictCheck >= NetworkChangeConflictCheckInterval;
        if (!CheckConflicts(now, force: due))
        {
            Volatile.Write(ref _conflictCheckRequested, 1);
        }
    }

    /// <summary>Серверы подключений службы: имя узла из профиля и адреса, в которые он разрешился.</summary>
    private List<Windows.Diagnostics.ConflictServer> ConflictServers()
    {
        var servers = new List<Windows.Diagnostics.ConflictServer>();
        foreach (var profile in ActiveProfiles.Where(p => p.Protocol != VpnProtocol.AnyConnect))
        {
            if (!TryParseServer(profile, out var server))
            {
                continue;
            }

            var tunnel = Facts.Tunnels.GetValueOrDefault(profile.Id);
            IReadOnlyList<uint> addresses = tunnel is null ? [] : ServerAddressesOf(tunnel).Distinct().ToList();
            servers.Add(new Windows.Diagnostics.ConflictServer(profile.Name, server.Host, addresses, profile.Id));
        }

        return servers;
    }

    /// <summary>
    /// Разрешение имён для детектора через DNS основного адаптера, как у адресов серверов. Значения берутся
    /// здесь, в очереди актора; детектор вызывает функцию в своей фоновой задаче. Без основного адаптера имена
    /// не разрешаются.
    /// </summary>
    private Func<string, IReadOnlyList<uint>>? ConflictResolver()
    {
        if (Facts.Primary is not { } primary)
        {
            return null;
        }

        var resolver = _deps.Resolver;
        var dns = ServiceDnsAddresses();
        var index = primary.InterfaceIndex;
        var logger = _deps.Logger;
        return host =>
        {
            try
            {
                using var timeout = new CancellationTokenSource(ConflictResolveTimeout);
                return resolver.ResolveAsync(host, dns, index, timeout.Token).WaitAsync(timeout.Token).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                // Имя не разрешилось: подключение сравнивается без него, как с сервером другого имени.
                logger.LogDebug(ex, "Детектор конфликтов: имя {Host} не разрешено", host);
                return [];
            }
        };
    }

    private void OnConflictsDetected(IReadOnlyList<StatusWarning>? found)
    {
        Facts.ConflictCheckRunning = false;
        if (found is null)
        {
            return;
        }

        foreach (var warning in found.Where(w => Facts.ConflictWarnings.All(old => old.Text != w.Text)))
        {
            Journal("Предупреждение", "Конфликт: " + warning.Text);
        }

        Facts.ConflictWarnings = found;
        AppendConflictCauses();
    }
}

/// <summary>Факты о системе, которые координатор знает на текущий момент.</summary>
internal sealed class CoordinatorFacts
{
    public AdapterCandidate? Primary { get; set; }

    public string NetworkFingerprint { get; set; } = "";

    public IReadOnlyList<(string Adapter, Ipv4Cidr Prefix)> Conflicts { get; set; } = [];

    /// <summary>Туннели по идентификатору профиля.</summary>
    public Dictionary<Guid, TunnelFacts> Tunnels { get; } = [];

    public CompiledPolicy? Policy { get; set; }

    /// <summary>
    /// Применённые закрепления из правил для доменов: набор, по которому собраны последняя политика,
    /// её маршруты и фильтры. Меняется только в очереди актора; желаемый набор живёт в координаторе.
    /// </summary>
    public Dictionary<uint, PinnedRoute> Pinned { get; } = [];

    /// <summary>
    /// Применённые служебные закрепления узлов проверки отзыва: адрес и имена узлов, которые на него указали.
    /// Они не входят в политику (адрес не уходит напрямую целиком), а открывают только порт ссылки в защите.
    /// </summary>
    public Dictionary<uint, HashSet<string>> RevocationPins { get; } = [];

    public string? PartialError { get; set; }

    /// <summary>Команда прервана отменой клиента: ближайший тик выполняет полную сверку, хотя ошибки нет.</summary>
    public bool ReconcilePending { get; set; }

    /// <summary>
    /// Последняя сверка довела политику, фильтры WFP и маршруты до конца. Сбой позже (DNS, дозвоны) её не
    /// отменяет: по этому признаку, а не по любому PartialError, решается, применилась ли новая база адресов.
    /// </summary>
    public bool PolicyApplied { get; set; }

    /// <summary>Когда повторять сверку после неполного применения: до этого момента тик её не запускает.</summary>
    public DateTimeOffset PartialErrorRetryAt { get; set; }

    /// <summary>Пауза перед повтором сверки: растёт 2→4→…→60 с и сбрасывается успешной сверкой.</summary>
    public TimeSpan PartialErrorDelay { get; set; }

    /// <summary>Настройки не позволяют подключиться (например, не включено ни одно подключение).</summary>
    public string? ConfigError { get; set; }

    /// <summary>Пароли, запомненные до перезапуска службы: у каждого профиля свой, ввод одного не стирает другой.</summary>
    public Dictionary<Guid, char[]> MemoryPasswords { get; } = [];

    /// <summary>Профили AnyConnect, для которых пользователь начал вход: только им служба запускает помощника.</summary>
    public HashSet<Guid> SignInApproved { get; } = [];


    public Dictionary<Core.Protection.FilterGroup, (IReadOnlyList<Core.Protection.FilterSpec> Specs, int Count)> AppliedFilters { get; } = [];

    public string AppliedRoutes { get; set; } = "";

    public Windows.Dns.DnsProxyConfiguration? AppliedDnsConfiguration { get; set; }

    public Windows.Dns.DnsProxyMode DnsMode { get; set; } = Windows.Dns.DnsProxyMode.Offline;

    public bool ForceProtection { get; set; }

    public DateTimeOffset LastFullReconcile { get; set; }

    /// <summary>Начало последней сверки с полной проверкой фильтров и маршрутов (ForceProtection).</summary>
    public DateTimeOffset LastForcedReconcile { get; set; }

    public uint BfeProcessId { get; set; }

    /// <summary>Идёт пробное подключение профиля (фоновая задача): обычный дозвон не начинается.</summary>
    public bool ProfileTestRunning
    {
        get => Volatile.Read(ref _profileTestRunning);
        set => Volatile.Write(ref _profileTestRunning, value);
    }

    private bool _profileTestRunning;

    public IReadOnlyList<Core.Ipc.StatusWarning> ConflictWarnings { get; set; } = [];

    public DateTimeOffset LastConflictCheck { get; set; }

    /// <summary>Детектор конфликтов работает в фоновой задаче; второй не запускается, пока не пришёл результат.</summary>
    public bool ConflictCheckRunning { get; set; }

    /// <summary>Когда полная сверка последний раз пересчитала фильтры группы Direct в BFE.</summary>
    public DateTimeOffset LastDirectFilterCheck { get; set; }

    /// <summary>Российская контрольная цель не ответила напрямую при пройденной иностранной: туннель не виноват.</summary>
    public bool RussianTargetUnreachable { get; set; }

    /// <summary>Подключение закреплено за адаптером, которого нет в системе: трафик заблокирован.</summary>
    public bool PinnedAdapterMissing { get; set; }

    /// <summary>
    /// Имя закреплённого адаптера, который есть в системе, но не подключён к сети (Wi-Fi подключается после запуска
    /// Windows или переподключается); null - адаптера нет вовсе или он подключён.
    /// </summary>
    public string? PinnedAdapterOffline { get; set; }

    /// <summary>С какого момента закреплённый адаптер есть в системе, но не подключён к сети; null - его нет или он подключён.</summary>
    public DateTimeOffset? PinnedAdapterOfflineSinceUtc { get; set; }

    /// <summary>
    /// Имя закреплённого адаптера, который не подключён к сети дольше <see cref="Coordinator.PinnedOfflineGrace"/>:
    /// это уже не ожидание, а выключенный адаптер или вынутый кабель.
    /// </summary>
    public string? PinnedAdapterDisconnected { get; set; }

    /// <summary>О каком состоянии закреплённого адаптера уже написана ошибка в журнале.</summary>
    public PinnedMissingReport PinnedMissingReported { get; set; }
}

/// <summary>Причина, по которой закреплённый основной адаптер не выбран.</summary>
internal enum PinnedMissingReport
{
    None,

    /// <summary>Адаптера нет в системе.</summary>
    Gone,

    /// <summary>Адаптер есть, но давно не подключён к сети.</summary>
    Disconnected,
}
