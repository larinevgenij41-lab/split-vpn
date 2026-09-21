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
public sealed class SystemWfpOps(WfpIdentity identity) : IWfpOps
{
    private WfpEngine? _engine;

    public int ReplaceGroup(FilterGroup group, IReadOnlyList<FilterSpec> specs)
    {
        ArgumentNullException.ThrowIfNull(specs);
        var engine = Engine();
        WfpOps.EnsureProviderAndSubLayer(engine, identity, persistent: true);
        var prefix = Prefix(group);
        var installed = WfpOps.ListFilters(engine, identity).Where(f => f.Name.StartsWith(prefix, StringComparison.Ordinal)).ToList();
        var named = specs.Select(s => s with { Name = prefix + s.Name }).ToList();
        if (group == FilterGroup.Direct)
        {
            return ReplaceByDifference(engine, installed, named);
        }

        var added = 0;
        engine.InTransaction(e =>
        {
            WfpOps.DeleteFilters(e, installed.Select(f => f.Id));
            added = WfpOps.AddFilters(e, identity, named, persistent: group == FilterGroup.Base, indexed: false).Count;
        });
        return added;
    }

    /// <summary>
    /// Прямые диапазоны RU-базы — десятки тысяч фильтров: полная замена занимает секунды и держит очередь службы.
    /// Имя фильтра этой группы однозначно задаёт диапазон, поэтому меняются только исчезнувшие и новые диапазоны.
    /// </summary>
    private int ReplaceByDifference(WfpEngine engine, List<WfpFilterInfo> installed, List<FilterSpec> named)
    {
        var wanted = named.ToDictionary(s => s.Name, StringComparer.Ordinal);
        var stale = installed.Where(f => !wanted.TryGetValue(f.Name, out var spec) || spec.Weight != f.Weight).Select(f => f.Id).ToList();
        var kept = installed.Where(f => wanted.TryGetValue(f.Name, out var spec) && spec.Weight == f.Weight).ToList();
        var present = kept.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        var missing = named.Where(s => !present.Contains(s.Name)).ToList();
        if (stale.Count == 0 && missing.Count == 0)
        {
            return kept.Count;
        }

        var added = 0;
        engine.InTransaction(e =>
        {
            WfpOps.DeleteFilters(e, stale);
            added = WfpOps.AddFilters(e, identity, missing, persistent: false, indexed: true).Count;
        });
        return kept.Count + added;
    }

    public IReadOnlyDictionary<FilterGroup, int> InstalledCounts()
    {
        var filters = WfpOps.ListFilters(Engine(), identity);
        return Enum.GetValues<FilterGroup>().ToDictionary(g => g, g => filters.Count(f => f.Name.StartsWith(Prefix(g), StringComparison.Ordinal)));
    }

    public void RemoveAll() => WfpOps.DeleteAll(Engine(), identity);

    public void Reopen()
    {
        _engine?.Dispose();
        _engine = null;
    }

    public void Dispose() => Reopen();

    private static string Prefix(FilterGroup group) => "[" + group + "] ";

    private WfpEngine Engine() => _engine ??= WfpEngine.Open(dynamicSession: false);
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

    public void Pin(string name, IReadOnlyList<uint> addresses) => _cache.Pin(name, addresses);

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
