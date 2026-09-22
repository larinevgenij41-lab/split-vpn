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

        _geo.LoadActive();
        _bypass.LoadActive();
        _update.StartUp(this);
        ApplyAutoConnect();
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
        var changed = MonitorConnections() | DetectNetworkChange() | DetectBfeRestart() | DropExpiredPins(now);
        CheckConflicts(now);
        var periodic = now - Facts.LastFullReconcile >= FullReconcileInterval;

        // После неполного применения сверка повторяется с растущей паузой (2→4→…→60 с), иначе служба
        // перебирает все фильтры BFE каждые 2 с. Изменения в сети и периодическая сверка паузу не ждут.
        var paused = Facts.PartialError is not null && now < Facts.PartialErrorRetryAt;
        if (changed || periodic || (!paused && (Facts.PartialError is not null || DialDue(now) || VerifyDue(now))))
        {
            Facts.ForceProtection |= periodic;
            await ReconcileAsync(cancellationToken);
        }

        await _geo.TickAsync(this, cancellationToken);
        await _bypass.TickAsync(this, cancellationToken);
        await _update.TickAsync(this, cancellationToken);
    }

    internal void Journal(string level, string text)
    {
        _deps.Journal.Add(level, text);
        _deps.Logger.Log(level is "Ошибка" or "Предупреждение" ? LogLevel.Warning : LogLevel.Information, "{Event}", text);
    }

    /// <summary>Профили, которые служба поднимает: опорный первым.</summary>
    internal IReadOnlyList<ConnectionProfile> ActiveProfiles => _settings.ActiveProfiles;

    /// <summary>Туннель, чей DNS используется по умолчанию: первый поднятый среди несущих «остальной интернет».</summary>
    internal TunnelFacts? DnsAnchor =>
        DefaultCarriers.Select(id => Facts.Tunnels.GetValueOrDefault(id)).FirstOrDefault(t => t?.Luid is not null)
        ?? Facts.Tunnels.Values.FirstOrDefault(t => t.Luid is not null && t.Role == ProfileRole.Primary)
        ?? Facts.Tunnels.Values.FirstOrDefault(t => t.Luid is not null && t.Protocol != VpnProtocol.AnyConnect);

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

    internal StatusDto BuildStatus()
    {
        var geoState = _geo.StoreState;
        var anchor = DnsAnchor ?? Facts.Tunnels.Values.FirstOrDefault();
        return new StatusDto
        {
            ContractVersion = IpcNames.ContractVersion,
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
            && ActiveProfiles.Select(p => Facts.Tunnels.GetValueOrDefault(p.Id)).FirstOrDefault(t => t is { PasswordRequired: true, BlockingError: ErrorCategory.None }) is { } waiting)
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

        if (_geo.StoreState is { Pending: not null } geoState)
        {
            warnings.Add(new StatusWarning("geo-pending", "Новая RU-база ждёт подтверждения: " + geoState.PendingReason, "geo-review"));
        }

        foreach (var (adapter, prefix) in Facts.Conflicts)
        {
            warnings.Add(new StatusWarning("public-onlink", $"Интерфейс «{adapter}» использует публичную сеть {prefix}: доступ к ней зависит от настройки «Локальный доступ».", null));
        }

        if (_state is { Intent: Intent.Connected, ProtectionSuspended: false })
        {
            warnings.AddRange(GroupWarnings());
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
                ? _settings.OutageMode == OutageMode.AllowAll ? "её трафик идёт напрямую." : "её трафик заблокирован до переподключения."
                : group.Mode == BalanceMode.Distribute ? "нагрузка перераспределена."
                : Facts.Tunnels.GetValueOrDefault(group.Members[0])?.Luid is not null ? "резервное подключение недоступно." : "трафик идёт через резервное подключение.";
            yield return new StatusWarning("group-degraded",
                string.Create(CultureInfo.InvariantCulture, $"В группе «{group.Name}» доступно {up} из {group.Members.Count}: {outcome}"), null);
        }
    }

    private bool DialDue(DateTimeOffset now) =>
        _state.Intent == Intent.Connected && !Facts.ProfileTestRunning
        && Facts.Tunnels.Values.Any(t => t.Connection is null && VpnProtocols.UsesRas(t.Protocol) && !t.Dialing && !t.ExternallyDisconnected && now >= t.NextDialAt);

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
    /// после начала цикла переподключений.
    /// </summary>
    private void CheckConflicts(DateTimeOffset now, bool force = false)
    {
        if (!force && now - Facts.LastConflictCheck < ConflictCheckInterval)
        {
            return;
        }

        Facts.LastConflictCheck = now;
        IReadOnlyList<StatusWarning> found;
        try
        {
            found = _deps.DetectConflicts(Facts.Tunnels.Values
                .Where(t => t.Luid is not null)
                .Select(t => new Windows.Diagnostics.ConflictTunnel(t.Luid!.Value, t.Name))
                .ToList());
        }
        catch (Exception ex) when (ex is Windows.Native.NativeCallException or InvalidOperationException or UnauthorizedAccessException or IOException)
        {
            _deps.Logger.LogWarning(ex, "Детектор конфликтов недоступен");
            return;
        }

        foreach (var warning in found.Where(w => Facts.ConflictWarnings.All(old => old.Text != w.Text)))
        {
            Journal("Предупреждение", "Конфликт: " + warning.Text);
        }

        Facts.ConflictWarnings = found;
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

    public string? PartialError { get; set; }

    /// <summary>Когда повторять сверку после неполного применения: до этого момента тик её не запускает.</summary>
    public DateTimeOffset PartialErrorRetryAt { get; set; }

    /// <summary>Пауза перед повтором сверки: растёт 2→4→…→60 с и сбрасывается успешной сверкой.</summary>
    public TimeSpan PartialErrorDelay { get; set; }

    /// <summary>Настройки не позволяют подключиться (например, не включено ни одно подключение).</summary>
    public string? ConfigError { get; set; }

    public char[]? MemoryPassword { get; set; }

    public Guid? MemoryPasswordProfile { get; set; }

    /// <summary>Профили AnyConnect, для которых пользователь начал вход: только им служба запускает помощника.</summary>
    public HashSet<Guid> SignInApproved { get; } = [];


    public Dictionary<Core.Protection.FilterGroup, (string Fingerprint, int Count)> AppliedFilters { get; } = [];

    public string AppliedRoutes { get; set; } = "";

    public Windows.Dns.DnsProxyConfiguration? AppliedDnsConfiguration { get; set; }

    public Windows.Dns.DnsProxyMode DnsMode { get; set; } = Windows.Dns.DnsProxyMode.Offline;

    public bool ForceProtection { get; set; }

    public DateTimeOffset LastFullReconcile { get; set; }

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

    /// <summary>Российская контрольная цель не ответила напрямую при пройденной иностранной: туннель не виноват.</summary>
    public bool RussianTargetUnreachable { get; set; }
}
