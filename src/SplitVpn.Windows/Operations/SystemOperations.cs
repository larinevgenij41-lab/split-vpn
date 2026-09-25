using System.Net;
using System.Net.Sockets;
using Microsoft.Win32;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;
using SplitVpn.Windows.Security;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Windows.Operations;

public sealed class SystemNetInventory : INetInventory
{
    public NetSnapshot Capture() => NetInventory.Capture();

    public IReadOnlyList<uint> DhcpDnsServers(Guid interfaceGuid)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + interfaceGuid.ToString("B"));
        var text = key?.GetValue("DhcpNameServer") as string ?? "";
        return text.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)
            .Select(s => Ipv4.TryParse(s, out var v) ? (uint?)v : null)
            .OfType<uint>()
            .ToList();
    }
}

public sealed class SystemRouteOps : IRouteOps
{
    public RouteApplyResult Reconcile(IReadOnlyCollection<RouteKey> desired) => RouteOps.Reconcile(desired);
}

/// <summary>
/// Фильтры группы помечаются префиксом имени «[группа]», поэтому после перезапуска службы группу
/// можно найти и заменить без сохранённых идентификаторов.
/// </summary>
public sealed class SystemWfpOps : IWfpOps
{
    private readonly Func<IWfpSession> _openSession;

    public SystemWfpOps(WfpIdentity identity) : this(() => new WfpSession(identity)) { }

    internal SystemWfpOps(Func<IWfpSession> openSession) => _openSession = openSession;

    /// <summary>
    /// Идентификаторы фильтров небольших групп: по ним установленное проверяется точечно, без перечисления
    /// всех фильтров системы. Пусто, пока группа не заменялась и полного подсчёта ещё не было.
    /// </summary>
    private readonly Dictionary<FilterGroup, IReadOnlyList<ulong>> _ids = [];
    private Dictionary<FilterSpec, IReadOnlyList<ulong>>? _dynamic;
    private bool _dynamicNeedsRepair;
    private IWfpSession? _session;
    internal const int MaxPointChecks = 256;

    public IReadOnlyDictionary<FilterGroup, int> ReplaceGroups(IReadOnlyDictionary<FilterGroup, IReadOnlyList<FilterSpec>> groups)
    {
        ArgumentNullException.ThrowIfNull(groups);
        if (groups.Count == 0)
        {
            return new Dictionary<FilterGroup, int>();
        }

        var session = Session();
        session.EnsureProvider();
        var needListing = groups.Count != 1 || !groups.ContainsKey(FilterGroup.Dynamic) || _dynamic is null;
        var installed = needListing ? session.ListFilters() : null;
        if (installed is not null && _dynamic is not null
            && !SameDynamicIds(installed.Where(f => f.Name.StartsWith(Prefix(FilterGroup.Dynamic), StringComparison.Ordinal)).Select(f => f.Id)))
        {
            InvalidateDynamic();
        }
        var counts = new Dictionary<FilterGroup, int>();
        var changedIds = new Dictionary<FilterGroup, IReadOnlyList<ulong>>();
        Dictionary<FilterSpec, IReadOnlyList<ulong>>? nextDynamic = null;
        // И маршрутизирующие запреты, и разрешения переходят на новую политику одним commit.
        session.InTransaction(() =>
        {
            foreach (var (group, specs) in groups)
            {
                var prefix = Prefix(group);
                var own = installed?.Where(f => f.Name.StartsWith(prefix, StringComparison.Ordinal)).ToList();
                var named = specs.Select(s => s with { Name = InstalledName(group, s) }).ToList();
                if (group == FilterGroup.Direct)
                {
                    counts[group] = ReplaceByDifference(session, own!, named);
                    continue;
                }

                if (group == FilterGroup.Dynamic)
                {
                    // Если перечисление обнаружило дрейф, кеш уже сброшен до транзакции.
                    nextDynamic = ReplaceDynamic(session, named, _dynamic, own?.Select(f => f.Id) ?? []);
                    var dynamicIds = nextDynamic.Values.SelectMany(ids => ids).ToArray();
                    changedIds[group] = dynamicIds;
                    counts[group] = dynamicIds.Length;
                    continue;
                }

                session.DeleteFilters(own?.Select(f => f.Id) ?? _ids[group]);
                var added = session.AddFilters(named, persistent: group == FilterGroup.Base, indexed: false);
                changedIds[group] = added;
                counts[group] = added.Count;
            }
        });
        // Abort не должен оставить в кеше идентификаторы незафиксированных объектов.
        foreach (var (group, ids) in changedIds)
        {
            _ids[group] = ids;
        }

        if (nextDynamic is not null)
        {
            _dynamic = nextDynamic;
            _dynamicNeedsRepair = false;
        }

        return counts;
    }

    /// <summary>У прямого запрета имя учитывает интерфейс: разностная замена сравнивает имена и веса.</summary>
    internal static string InstalledName(FilterGroup group, FilterSpec spec)
    {
        var binding = group == FilterGroup.Direct
            ? string.Join(",", spec.Conditions.OfType<LocalInterfaceCondition>().Select(c =>
                FormattableString.Invariant($"{c.Luid}:{c.NotEqual}")))
            : "";
        return Prefix(group) + spec.Name + (binding.Length > 0 ? " [interface " + binding + "]" : "");
    }

    /// <summary>
    /// Прямые диапазоны RU-базы — десятки тысяч фильтров: полная замена занимает секунды и держит очередь службы.
    /// Имя задаёт диапазон и интерфейс, но один spec установлен на нескольких слоях. Неполный или неверный
    /// комплект пересоздаётся целиком; исправные диапазоны сохраняются.
    /// </summary>
    private static int ReplaceByDifference(IWfpSession session, List<WfpFilterInfo> installed, List<FilterSpec> named)
    {
        var difference = PlanDirectDifference(installed, named);
        if (difference.Stale.Count == 0 && difference.Missing.Count == 0)
        {
            return difference.KeptCount;
        }

        session.DeleteFilters(difference.Stale);
        var added = session.AddFilters(difference.Missing, persistent: false, indexed: true).Count;
        return difference.KeptCount + added;
    }

    private static Dictionary<FilterSpec, IReadOnlyList<ulong>> ReplaceDynamic(
        IWfpSession session, IReadOnlyList<FilterSpec> named,
        Dictionary<FilterSpec, IReadOnlyList<ulong>>? cached, IEnumerable<ulong> installed)
    {
        var next = new Dictionary<FilterSpec, IReadOnlyList<ulong>>(FilterSpecComparer.Instance);
        var wanted = named.ToHashSet(FilterSpecComparer.Instance);
        session.DeleteFilters(cached is null ? installed
            : cached.Where(p => !wanted.Contains(p.Key)).SelectMany(p => p.Value));
        var missing = new List<FilterSpec>();
        foreach (var spec in named)
        {
            if (cached is not null && cached.TryGetValue(spec, out var ids))
            {
                next.Add(spec with { Conditions = spec.Conditions.ToArray() }, ids);
            }
            else
            {
                missing.Add(spec);
            }
        }

        // Один пакет сохраняет кеш нативных условий WfpOps на всё добавление.
        var added = session.AddFilters(missing, persistent: false, indexed: false);
        var offset = 0;
        foreach (var spec in missing)
        {
            var count = WfpOps.LayersOf(spec.Family).Count;
            var ids = new ulong[count];
            for (var i = 0; i < count; i++)
            {
                ids[i] = added[offset++];
            }

            next.Add(spec with { Conditions = spec.Conditions.ToArray() }, ids);
        }

        return next;
    }

    private bool SameDynamicIds(IEnumerable<ulong> installed) => _dynamic is not null
        && _dynamic.Values.SelectMany(ids => ids).ToHashSet().SetEquals(installed);

    private void InvalidateDynamic()
    {
        _dynamic = null;
        _dynamicNeedsRepair = true;
    }

    /// <summary>План без нативных вызовов: отсутствие одной копии нельзя принимать за новый эталон количества.</summary>
    internal static (IReadOnlyList<ulong> Stale, IReadOnlyList<FilterSpec> Missing, int KeptCount) PlanDirectDifference(
        IReadOnlyList<WfpFilterInfo> installed, IReadOnlyList<FilterSpec> named)
    {
        var wanted = named.ToDictionary(s => s.Name, StringComparer.Ordinal);
        var complete = new HashSet<string>(StringComparer.Ordinal);
        var stale = new List<ulong>();
        var keptCount = 0;
        foreach (var group in installed.GroupBy(f => f.Name, StringComparer.Ordinal))
        {
            var copies = group.ToArray();
            if (wanted.TryGetValue(group.Key, out var spec) && HasCompleteLayers(copies, spec))
            {
                complete.Add(group.Key);
                keptCount += copies.Length;
            }
            else
            {
                stale.AddRange(copies.Select(f => f.Id));
            }
        }

        return (stale, named.Where(s => !complete.Contains(s.Name)).ToList(), keptCount);
    }

    private static bool HasCompleteLayers(WfpFilterInfo[] copies, FilterSpec spec)
    {
        var layers = WfpOps.LayersOf(spec.Family);
        return copies.Length == layers.Count
            && layers.All(layer => copies.Count(f => f.Layer == layer && f.Weight == spec.Weight && !f.Persistent) == 1);
    }

    public IReadOnlyDictionary<FilterGroup, int> InstalledCounts(bool includeDirect)
    {
        var small = Enum.GetValues<FilterGroup>().Where(g => g != FilterGroup.Direct).ToList();
        if (includeDirect || small.Any(g => !_ids.ContainsKey(g))
            || small.Sum(g => _ids[g].Count) > MaxPointChecks)
        {
            return CountAll(includeDirect);
        }

        var session = Session();
        var counts = small.ToDictionary(g => g, g => _ids[g].Count(session.FilterExists));
        if (_dynamic is not null && counts[FilterGroup.Dynamic] != _ids[FilterGroup.Dynamic].Count)
        {
            InvalidateDynamic();
        }

        if (_dynamicNeedsRepair)
        {
            counts[FilterGroup.Dynamic] = -1;
        }

        return counts;
    }

    /// <summary>Подсчёт перечислением всех фильтров; попутно запоминает идентификаторы небольших групп.</summary>
    private Dictionary<FilterGroup, int> CountAll(bool includeDirect)
    {
        var filters = Session().ListFilters();
        var result = new Dictionary<FilterGroup, int>();
        foreach (var group in Enum.GetValues<FilterGroup>())
        {
            var own = filters.Where(f => f.Name.StartsWith(Prefix(group), StringComparison.Ordinal)).Select(f => f.Id).ToList();
            var dynamicDrift = group == FilterGroup.Dynamic && _dynamic is not null && !SameDynamicIds(own);
            if (dynamicDrift)
            {
                InvalidateDynamic();
            }
            if (group != FilterGroup.Direct)
            {
                _ids[group] = own;
            }

            if (includeDirect || group != FilterGroup.Direct)
            {
                result[group] = group == FilterGroup.Dynamic && _dynamicNeedsRepair ? -1 : own.Count;
            }
        }

        return result;
    }

    public void RemoveAll()
    {
        Session().DeleteAll();
        _ids.Clear();
        _dynamic = null;
        _dynamicNeedsRepair = false;
    }

    public void Reopen()
    {
        _session?.Dispose();
        _session = null;
        _ids.Clear();
        _dynamic = null;
        _dynamicNeedsRepair = false;
    }

    public void Dispose() => Reopen();

    private static string Prefix(FilterGroup group) => "[" + group + "] ";

    private IWfpSession Session() => _session ??= _openSession();
}

public sealed class SystemDnsOps : IDnsOps
{
    public string ReadNameServer(Guid interfaceGuid) => InterfaceDnsOps.Read(interfaceGuid, ipv6: false).NameServer;

    public InterfaceDnsBackup Capture(Guid interfaceGuid, InterfaceDnsBackup? previous) =>
        InterfaceDnsOps.Capture(interfaceGuid, previous, DateTimeOffset.UtcNow);

    public void ApplyLoopback(Guid interfaceGuid) => InterfaceDnsOps.ApplyLoopback(interfaceGuid);

    public string ReadSearchList(Guid interfaceGuid) => InterfaceDnsOps.Read(interfaceGuid, ipv6: false).SearchList;

    public void SetSearchList(Guid interfaceGuid, string searchList) => InterfaceDnsOps.SetSearchList(interfaceGuid, searchList);

    public void ClearNameServer(Guid interfaceGuid)
    {
        InterfaceDnsOps.SetNameServer(interfaceGuid, "", ipv6: false);
        InterfaceDnsOps.SetNameServer(interfaceGuid, "", ipv6: true);
    }

    public DnsRestoreOutcome Restore(Guid interfaceGuid, InterfaceDnsBackup? backup) => InterfaceDnsOps.Restore(interfaceGuid, backup);

    public void FlushCache() => InterfaceDnsOps.FlushResolverCache();
}

public sealed class SystemRasOps(string phonebookPath) : IRasOps
{
    /// <summary>Подготовленные записи: у каждого профиля своя запись и своя конфигурация EAP.</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Prepared> _prepared = new(StringComparer.OrdinalIgnoreCase);

    private sealed record Prepared(ConnectionProfile Profile, byte[]? EapConfiguration);

    public void SaveEntry(string entryName, ConnectionProfile profile, ReadOnlySpan<char> preSharedKey)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.Protocol == VpnProtocol.L2tpIpsec)
        {
            using var parameters = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\RasMan\Parameters");
            if (parameters?.GetValue("ProhibitIpSec") is int value && value != 0)
            {
                throw new InvalidOperationException("Windows запрещает IPsec для L2TP (ProhibitIpSec). Незащищённый L2TP не поддерживается.");
            }
        }

        VpnCertificates.Validate(profile);
        var config = VpnProtocols.IsEap(profile.AuthMethod) ? EapNative.Configuration(profile) : null;
        DeleteEntry(entryName);
        RasPhonebook.Save(phonebookPath, new RasEntrySpec(entryName, profile.Server)
        {
            Protocol = profile.Protocol, AuthMethod = profile.AuthMethod, IpsecAuthentication = profile.IpsecAuthentication,
        });
        try
        {
            if (VpnProtocols.NeedsPreSharedKey(profile))
            {
                if (preSharedKey.IsEmpty)
                {
                    throw new InvalidOperationException("Введите ключ IPsec в настройках подключения.");
                }

                RasPhonebook.SetPreSharedKey(phonebookPath, entryName, preSharedKey);
            }

            if (config is not null)
            {
                RasPhonebook.SetEapConfiguration(phonebookPath, entryName, config);
            }

            _prepared[entryName] = new Prepared(profile, config);
        }
        catch
        {
            DeleteEntry(entryName);
            throw;
        }
    }

    public void DeleteEntry(string entryName)
    {
        if (File.Exists(phonebookPath))
        {
            RasPhonebook.Delete(phonebookPath, entryName);
        }

        _prepared.TryRemove(entryName, out _);
    }

    public IReadOnlyList<string> EntryNames() => RasPhonebook.EnumerateEntryNames(phonebookPath);

    public async Task<RasDialResult> DialAsync(string entryName, string userName, ReadOnlyMemory<char> password, string? domain, CancellationToken cancellationToken)
    {
        if (!_prepared.TryGetValue(entryName, out var prepared))
        {
            throw new InvalidOperationException("Запись подключения не подготовлена.");
        }

        var identity = prepared.EapConfiguration is null ? null : EapNative.Identity(prepared.Profile, prepared.EapConfiguration, password.Span);
        try
        {
            return await RasClient.DialAsync(phonebookPath, entryName, userName, password, domain, TimeSpan.FromSeconds(60), cancellationToken,
                identity, prepared.Profile.AuthMethod is AuthMethod.EapTls or AuthMethod.MachineCertificate);
        }
        finally
        {
            if (identity is not null)
            {
                Array.Clear(identity);
            }
        }
    }

    public Task HangUpAsync(RasConnectionHandle handle, CancellationToken cancellationToken) => RasClient.HangUpAsync(handle, cancellationToken);

    public RasConnectionStatus GetStatus(RasConnectionHandle handle) => RasClient.GetStatus(handle).Status;

    public IReadOnlyList<RasActiveConnection> FindOwnConnections() =>
        RasClient.EnumerateConnections().Where(c => RasClient.SamePhonebook(c.Phonebook, phonebookPath)).ToList();

    public RasProjection GetProjection(RasConnectionHandle handle) => RasClient.GetProjection(handle);

    public RasStatistics? GetStatistics(RasConnectionHandle handle)
    {
        try
        {
            return RasClient.GetStatistics(handle);
        }
        catch (Native.NativeCallException)
        {
            return null;
        }
    }
}

public sealed class SystemSecretOps(string path, Action<CorruptFile>? onCorrupt = null) : ISecretOps
{
    private readonly SecretStore _store = new(path) { OnCorrupt = onCorrupt };
    private readonly SecretStore _keys = new(path + ".ipsec") { OnCorrupt = onCorrupt };
    private SecretStore Store(SecretKind kind) => kind == SecretKind.Password ? _store : _keys;

    public char[]? TryLoad(Guid profileId, SecretKind kind = SecretKind.Password) => Store(kind).TryLoad(profileId);

    public void Save(Guid profileId, ReadOnlySpan<char> password, SecretKind kind = SecretKind.Password) => Store(kind).Save(profileId, password);

    public void Delete(Guid profileId, SecretKind kind = SecretKind.Password) => Store(kind).Delete(profileId);

    public bool Contains(Guid profileId, SecretKind kind = SecretKind.Password) => Store(kind).Contains(profileId);
}

public sealed class SystemResolver : IResolver
{
    public Task<IReadOnlyList<uint>> ResolveAsync(string host, IReadOnlyList<uint> servers, uint? interfaceIndex, CancellationToken cancellationToken) =>
        BootstrapResolver.ResolveAsync(host, servers, interfaceIndex, cancellationToken);
}

/// <summary>Посредник на 127.0.0.1:53 с кешем в памяти.</summary>
public sealed class SystemDnsProxy : IDnsProxy, IAsyncDisposable
{
    private readonly DnsCache _cache = new(TimeProvider.System);
    private DnsProxyServer? _server;
    private IPinnedRouteSink? _routeSink;

    /// <summary>Ставится до Start: посредник передаёт приёмнику адреса из правил для доменов.</summary>
    public IPinnedRouteSink? RouteSink
    {
        get => _routeSink;
        set
        {
            _routeSink = value;
            if (_server is not null)
            {
                _server.RouteSink = value;
            }
        }
    }

    public DnsProxyConfiguration Configuration
    {
        get => _server?.Configuration ?? new DnsProxyConfiguration();
        set
        {
            if (_server is not null)
            {
                _server.Configuration = value;
            }
        }
    }

    public DnsProxyStats Stats => _server?.Stats ?? new DnsProxyStats(0, 0, 0, 0, 0);

    public bool IsRunning => _server is not null;

    public void Start()
    {
        if (_server is not null)
        {
            return;
        }

        var server = new DnsProxyServer(IPAddress.Loopback, _cache) { RouteSink = _routeSink };
        server.Start();
        _server = server;
    }

    public void Pin(string name, IReadOnlyList<uint> addresses, TimeSpan? lifetime = null) => _cache.Pin(name, addresses, lifetime);

    public void RetainPins(IEnumerable<string> permanentNames) => _cache.RetainPins(permanentNames);

    public void ClearCache() => _cache.Clear();

    public async ValueTask DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }
}

public sealed class SystemProbeOps : IProbeOps
{
    public async Task<TcpProbeResult> TcpAsync(uint remote, ushort port, uint? localAddress, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            if (localAddress is { } local)
            {
                // Строгая модель хоста: сокет, привязанный к адресу туннеля, уходит только через него.
                socket.Bind(new IPEndPoint(Ipv4.ToAddress(local), 0));
            }

            await socket.ConnectAsync(new IPEndPoint(Ipv4.ToAddress(remote), port), cts.Token);
            var endpoint = (IPEndPoint?)socket.LocalEndPoint;
            return new TcpProbeResult(true, endpoint is null ? null : Ipv4.ToUInt(endpoint.Address), null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new TcpProbeResult(false, null, "таймаут");
        }
        catch (SocketException ex)
        {
            return new TcpProbeResult(false, null, ex.SocketErrorCode.ToString());
        }
    }

    public Task<ServerCertificateFacts?> ServerCertificateAsync(uint remote, ushort port, string? host, TimeSpan timeout, CancellationToken cancellationToken) =>
        ServerCertificateProbe.TryProbeAsync(remote, port, host, timeout, cancellationToken);

    public BestRoute? FindBestRoute(uint destination) => RouteOps.FindBestRoute(destination);
}
