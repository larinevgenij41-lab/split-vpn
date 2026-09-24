using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Protection;
using SplitVpn.Core.State;
using SplitVpn.Core.Update;
using SplitVpn.Service;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Мир фейков: сеть с Wi-Fi и Radmin, туннели появляются после успешного дозвона. Туннелей может быть
/// несколько: номер («слот») закрепляется за записью телефонной книги в порядке её создания.
/// </summary>
internal sealed class FakeWorld : IDisposable
{
    public const ulong WiFiLuid = 8;
    public const ulong RadminLuid = 19;
    public const ulong TunnelLuid = 56;

    public static readonly Guid WiFiGuid = Guid.NewGuid();
    public static readonly Guid TunnelGuid = FakeInventory.TunnelGuid(0);
    public static readonly uint WiFiAddress = Ipv4.Parse("192.168.1.100");
    public static readonly uint TunnelAddress = FakeInventory.TunnelAddress(0);
    public static readonly uint Gateway = Ipv4.Parse("192.168.1.1");
    public static readonly uint Server = Ipv4.Parse("203.0.113.10");
    public static readonly uint SecondServer = Ipv4.Parse("203.0.113.77");

    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-service-tests", Guid.NewGuid().ToString("N"));

    public FakeWorld()
    {
        Directory.CreateDirectory(_root);
        Paths = new ServicePaths(_root);
        Inventory = new FakeInventory();
        Ras = new FakeRas(Inventory);
        Routes.Ras = Ras;
        Probes.Inventory = Inventory;
    }

    public ServicePaths Paths { get; }

    public FakeTimeProvider Time { get; } = new(new DateTimeOffset(2026, 9, 13, 10, 0, 0, TimeSpan.Zero));

    public FakeInventory Inventory { get; }

    public FakeRoutes Routes { get; } = new();

    public FakeWfp Wfp { get; } = new();

    public FakeDns Dns { get; } = new();

    public FakeRas Ras { get; }

    public FakeSecrets Secrets { get; } = new();

    public FakeResolver Resolver { get; } = new();

    public FakeAnyConnect AnyConnect { get; } = new();

    public FakeProxy Proxy { get; } = new();

    public FakeProbes Probes { get; } = new();

    public EventJournal Journal => _journal ??= new EventJournal(Time);

    private EventJournal? _journal;

    /// <summary>Код завершения RAS из «журнала»: 631 — отключил пользователь.</summary>
    public uint? TerminationReason { get; set; }

    public TimeSpan Uptime { get; set; } = TimeSpan.FromHours(3);

    public bool Metered { get; set; }

    public List<SplitVpn.Core.Ipc.StatusWarning> Conflicts { get; } = [];

    /// <summary>Сколько раз запускался детектор конфликтов и с какими туннелями — последний раз.</summary>
    public int ConflictChecks { get; private set; }

    public IReadOnlyList<SplitVpn.Windows.Diagnostics.ConflictTunnel> ConflictTunnels { get; private set; } = [];

    /// <summary>Журнал службы; по умолчанию ничего не пишет.</summary>
    public Microsoft.Extensions.Logging.ILogger Logger { get; set; } = NullLogger.Instance;

    /// <summary>Ответы на запросы обновлений; по умолчанию сеть недоступна.</summary>
    public HttpMessageHandler? HttpHandler { get; set; }

    /// <summary>Версия «установленной» программы: по ней служба решает, что предлагать и что установилось.</summary>
    public Version ProductVersion { get; set; } = new(0, 8, 0);

    /// <summary>Проверка подписи манифеста; по умолчанию принимает всё — подпись проверяют свои тесты.</summary>
    public IManifestVerifier ManifestVerifier { get; set; } = new AcceptingVerifier();

    /// <summary>Коды завершения установщика по номеру процесса: чем закончился запущенный msiexec.</summary>
    public Dictionary<int, int?> ProcessExitCodes { get; } = [];

    public List<int> WatchedProcesses { get; } = [];

    public ServiceDependencies Dependencies() => new()
    {
        Stores = new ServiceStores(Paths),
        Inventory = Inventory,
        Routes = Routes,
        Wfp = Wfp,
        Dns = Dns,
        DnsBackups = new DnsBackupStore(Paths.DnsBackup),
        Ras = Ras,
        Secrets = Secrets,
        Resolver = Resolver,
        AnyConnect = AnyConnect,
        DnsProxy = Proxy,
        Probes = Probes,
        Http = HttpHandler is null ? new HttpClient() : new HttpClient(HttpHandler),
        Time = Time,
        Journal = Journal,
        Logger = Logger,
        ServiceExecutablePath = @"C:\Program Files\SplitVpn\SplitVpn.Service.exe",
        Random = new Random(1),
        RasTerminationReason = _ => TerminationReason,
        SystemUptime = () => Uptime,
        IsMeteredNetwork = () => Metered,
        DetectConflicts = _ => Conflicts.ToList(),
        ProductVersion = ProductVersion,
        ManifestVerifier = ManifestVerifier,
        WaitForProcessAsync = (id, _) =>
        {
            WatchedProcesses.Add(id);
            return Task.FromResult(ProcessExitCodes.TryGetValue(id, out var code) ? code : null);
        },
    };

    /// <summary>Подпись принимается без проверки: тесты планировщика не занимаются криптографией.</summary>
    private sealed class AcceptingVerifier : IManifestVerifier
    {
        public string? Verify(byte[] manifest, byte[] signature, string? keyId) => null;
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}

internal sealed class FakeInventory : INetInventory
{
    private static readonly Guid[] TunnelGuids = [Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()];

    private readonly Lock _lock = new();
    private readonly HashSet<int> _present = [];

    /// <summary>Номера поднятых туннелей. Дозвоны идут параллельно, поэтому доступ под замком.</summary>
    public IReadOnlyCollection<int> PresentTunnels
    {
        get
        {
            lock (_lock)
            {
                return _present.ToList();
            }
        }
    }

    public void AddTunnel(int slot)
    {
        lock (_lock)
        {
            _present.Add(slot);
        }
    }

    public void RemoveTunnel(int slot)
    {
        lock (_lock)
        {
            _present.Remove(slot);
        }
    }

    public bool WiFiUp { get; set; } = true;

    /// <summary>«Ворота» для долгой работы: снимок сети ждёт, пока тест их не откроет.</summary>
    public ManualResetEventSlim? CaptureGate { get; set; }

    /// <summary>Снимок сети дошёл до ворот.</summary>
    public TaskCompletionSource CaptureEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public static Guid TunnelGuid(int slot) => TunnelGuids[slot];

    public static ulong TunnelLuid(int slot) => FakeWorld.TunnelLuid + (ulong)slot;

    public static uint TunnelAddress(int slot) => Ipv4.Parse("192.168.44.20") + (uint)slot;

    /// <summary>Совместимость с тестами про один туннель.</summary>
    public bool TunnelPresent
    {
        get => PresentTunnels.Contains(0);
        set
        {
            if (value)
            {
                AddTunnel(0);
            }
            else
            {
                RemoveTunnel(0);
            }
        }
    }

    public NetSnapshot Capture()
    {
        if (CaptureGate is { } gate)
        {
            CaptureEntered.TrySetResult();
            gate.Wait(TimeSpan.FromSeconds(30));
        }

        var adapters = new List<AdapterCandidate>
        {
            new()
            {
                InterfaceGuid = FakeWorld.WiFiGuid, Luid = FakeWorld.WiFiLuid, InterfaceIndex = 8, Name = "Беспроводная сеть", IfType = 71,
                IsHardware = true, IsUp = WiFiUp, DefaultGateway = FakeWorld.Gateway, DefaultRouteMetric = 35,
                OnLinkPrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")], Addresses = [FakeWorld.WiFiAddress], DnsServers = [FakeWorld.Gateway],
            },
            new()
            {
                InterfaceGuid = Guid.NewGuid(), Luid = FakeWorld.RadminLuid, InterfaceIndex = 19, Name = "Radmin VPN", IfType = 6,
                IsUp = true, DefaultGateway = Ipv4.Parse("26.0.0.1"), DefaultRouteMetric = 9257,
                OnLinkPrefixes = [Ipv4Cidr.Parse("26.0.0.0/8")], Addresses = [Ipv4.Parse("26.185.67.105")],
            },
        };
        foreach (var slot in PresentTunnels.Order())
        {
            adapters.Add(new AdapterCandidate
            {
                InterfaceGuid = TunnelGuid(slot),
                Luid = TunnelLuid(slot),
                InterfaceIndex = (uint)(56 + slot),
                Name = "Раздельный VPN " + slot,
                IfType = 23,
                IsUp = true,
                Addresses = [TunnelAddress(slot)],
                DnsServers = [Ipv4.Parse("198.51.100.50") + (uint)slot],
            });
        }

        return new NetSnapshot(adapters, []);
    }

    public IReadOnlyList<uint> DhcpDnsServers(Guid interfaceGuid) => interfaceGuid == FakeWorld.WiFiGuid ? [FakeWorld.Gateway] : [];
}

internal sealed class FakeRoutes : IRouteOps
{
    public HashSet<RouteKey> Current { get; } = [];

    public int FailNext { get; set; }

    public FakeRas? Ras { get; set; }

    public bool ServerRouteLostWhileConnected { get; private set; }

    public RouteApplyResult Reconcile(IReadOnlyCollection<RouteKey> desired)
    {
        if (FailNext > 0)
        {
            FailNext--;
            return new RouteApplyResult(0, 0, 1, TimeSpan.Zero, ["сбой"]);
        }

        // Как в реальной системе: без маршрута /32 к серверу SSTP-сессия уходит в туннель и рвётся.
        if (Ras?.Connected == true && !desired.Any(r => r.Destination == new Ipv4Cidr(FakeWorld.Server, 32)))
        {
            Ras.Drop();
            ServerRouteLostWhileConnected = true;
        }

        var added = desired.Count(r => !Current.Contains(r));
        var removed = Current.Count(r => !desired.Contains(r));
        Current.Clear();
        Current.UnionWith(desired);
        return new RouteApplyResult(added, removed, 0, TimeSpan.Zero, []);
    }

    public bool HasHalfRoutesOn(ulong luid) =>
        Current.Any(r => r.InterfaceLuid == luid && r.Destination == Ipv4Cidr.Parse("0.0.0.0/1"));

    public IEnumerable<Ipv4Cidr> On(ulong luid) => Current.Where(r => r.InterfaceLuid == luid).Select(r => r.Destination);
}

internal sealed class FakeWfp : IWfpOps
{
    public Dictionary<FilterGroup, IReadOnlyList<FilterSpec>> Groups { get; } = [];

    public int FailNextReplace { get; set; }

    public int Replacements { get; private set; }

    public int Reopens { get; private set; }

    public int ReplaceGroup(FilterGroup group, IReadOnlyList<FilterSpec> specs)
    {
        if (FailNextReplace > 0)
        {
            FailNextReplace--;
            throw new NativeCallException("FwpmTransactionCommit0", 0x80320017);
        }

        Groups[group] = specs;
        Replacements++;
        return specs.Count;
    }

    /// <summary>Сколько раз подсчёт включал группу Direct (полное перечисление фильтров).</summary>
    public int DirectCounts { get; private set; }

    public IReadOnlyDictionary<FilterGroup, int> InstalledCounts(bool includeDirect)
    {
        DirectCounts += includeDirect ? 1 : 0;
        return Groups.Where(g => includeDirect || g.Key != FilterGroup.Direct).ToDictionary(g => g.Key, g => g.Value.Count);
    }

    /// <summary>Удаление одного фильтра извне (дрейф).</summary>
    public void RemoveOne(FilterGroup group) => Groups[group] = Groups[group].Skip(1).ToList();

    public void RemoveAll() => Groups.Clear();

    public void Reopen() => Reopens++;

    public void Dispose()
    {
    }

    public bool HasTunnelPermit => TunnelPermits > 0;

    public int TunnelPermits => Groups.TryGetValue(FilterGroup.Runtime, out var runtime)
        ? runtime.Count(f => f.Weight == FilterPlanBuilder.WeightTunnel && f.Action == FilterAction.Permit)
        : 0;

    public IReadOnlyList<FilterSpec> Group(FilterGroup group) => Groups.GetValueOrDefault(group, []);
}

internal sealed class FakeDns : IDnsOps
{
    public Dictionary<Guid, string> NameServers { get; } = [];

    public Dictionary<Guid, string> SearchLists { get; } = [];

    public int Flushes { get; private set; }

    public string ReadSearchList(Guid interfaceGuid) => SearchLists.GetValueOrDefault(interfaceGuid, "");

    public void SetSearchList(Guid interfaceGuid, string searchList) => SearchLists[interfaceGuid] = searchList;

    public string ReadNameServer(Guid interfaceGuid)
    {
        if (NameServers.TryGetValue(interfaceGuid, out var stored))
        {
            return stored;
        }

        for (var slot = 0; slot < 3; slot++)
        {
            if (interfaceGuid == FakeInventory.TunnelGuid(slot))
            {
                return Ipv4.Format(Ipv4.Parse("198.51.100.50") + (uint)slot) + " 198.51.100.60";
            }
        }

        return "";
    }

    public InterfaceDnsBackup Capture(Guid interfaceGuid, InterfaceDnsBackup? previous)
    {
        var current = ReadNameServer(interfaceGuid);
        var original = InterfaceDnsOps.IsLoopback(current) ? previous?.NameServerV4 ?? "" : current;
        return new InterfaceDnsBackup(interfaceGuid, original, "", "", 0, DateTimeOffset.UnixEpoch, ReadSearchList(interfaceGuid));
    }

    public void ApplyLoopback(Guid interfaceGuid) => NameServers[interfaceGuid] = "127.0.0.1";

    public void ClearNameServer(Guid interfaceGuid) => NameServers[interfaceGuid] = "";

    public DnsRestoreOutcome Restore(Guid interfaceGuid, InterfaceDnsBackup? backup)
    {
        if (backup is not null)
        {
            SearchLists[interfaceGuid] = backup.SearchList;
        }

        if (!InterfaceDnsOps.IsLoopback(ReadNameServer(interfaceGuid)))
        {
            return DnsRestoreOutcome.ChangedByUser;
        }

        NameServers[interfaceGuid] = backup?.NameServerV4 ?? "";
        return DnsRestoreOutcome.Restored;
    }

    public void FlushCache() => Flushes++;
}

internal sealed class FakeRas(FakeInventory inventory) : IRasOps
{
    private const int HandleBase = 0x5150;

    private readonly Lock _lock = new();
    private readonly Dictionary<string, int> _slots = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _connected = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Общая очередь ответов на дозвон; пусто — успех.</summary>
    public Queue<RasDialResult> Results { get; } = new();

    /// <summary>Ответы для конкретной записи (по имени профиля, в порядке дозвона).</summary>
    public Dictionary<string, Queue<RasDialResult>> ResultsByEntry { get; } = new(StringComparer.OrdinalIgnoreCase);

    public int Dials { get; private set; }

    public string? SavedServer { get; private set; }

    public List<string> DeletedEntries { get; } = [];

    /// <summary>Последний профиль и ключ IPsec, с которыми готовили запись.</summary>
    public ConnectionProfile? SavedProfile { get; private set; }

    public string? SavedKey { get; private set; }

    public bool Connected => ConnectedEntries.Count > 0;

    public IReadOnlyCollection<string> ConnectedEntries
    {
        get
        {
            lock (_lock)
            {
                return _connected.ToList();
            }
        }
    }

    public int Slot(string entryName)
    {
        lock (_lock)
        {
            if (!_slots.TryGetValue(entryName, out var slot))
            {
                slot = _slots.Count;
                _slots[entryName] = slot;
            }

            return slot;
        }
    }

    public void SaveEntry(string entryName, ConnectionProfile profile, ReadOnlySpan<char> preSharedKey)
    {
        var key = preSharedKey.ToString();
        lock (_lock)
        {
            _entries[entryName] = profile.Server;
            SavedServer = profile.Server;
            SavedProfile = profile;
            SavedKey = key;
        }

        Slot(entryName);
    }

    public void DeleteEntry(string entryName)
    {
        lock (_lock)
        {
            _entries.Remove(entryName);
            DeletedEntries.Add(entryName);
        }
    }

    public IReadOnlyList<string> EntryNames()
    {
        lock (_lock)
        {
            return _entries.Keys.ToList();
        }
    }

    /// <summary>
    /// Придерживает дозвон указанной записи, пока тест её не отпустит: так проверяется очерёдность подъёма
    /// и то, что положенный на ходу туннель не присоединяется.
    /// </summary>
    public Dictionary<string, TaskCompletionSource> Gates { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Записи в порядке начала дозвона: по нему проверяется очерёдность подъёма.</summary>
    public List<string> DialOrder { get; } = [];

    public async Task<RasDialResult> DialAsync(string entryName, string userName, ReadOnlyMemory<char> password, string? domain, CancellationToken cancellationToken)
    {
        TaskCompletionSource? gate;
        lock (_lock)
        {
            // Счётчик растёт в момент начала дозвона: задвижка держит уже начатый дозвон, а не отменяет его.
            Dials++;
            DialOrder.Add(entryName);
            gate = Gates.GetValueOrDefault(entryName);
        }

        if (gate is not null)
        {
            await gate.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
        }

        var slot = Slot(entryName);
        RasDialResult result;
        lock (_lock)
        {
            var queue = ResultsByEntry.GetValueOrDefault(entryName);
            result = queue is { Count: > 0 } ? queue.Dequeue()
                : Results.Count > 0 ? Results.Dequeue()
                : new RasDialResult(true, null, 0, null);
            if (result.Success)
            {
                _connected.Add(entryName);
            }
        }

        if (result.Success)
        {
            inventory.AddTunnel(slot);
        }

        return result with { Handle = result.Success ? new RasConnectionHandle(HandleBase + slot) : null };
    }

    public Task HangUpAsync(RasConnectionHandle handle, CancellationToken cancellationToken)
    {
        Drop(EntryOf(handle));
        return Task.CompletedTask;
    }

    /// <summary>Обрыв всех соединений со стороны сети.</summary>
    public void Drop()
    {
        foreach (var entry in ConnectedEntries)
        {
            Drop(entry);
        }
    }

    /// <summary>Обрыв одного соединения со стороны сети.</summary>
    public void Drop(string? entryName)
    {
        if (entryName is null)
        {
            return;
        }

        bool removed;
        lock (_lock)
        {
            removed = _connected.Remove(entryName);
        }

        if (removed)
        {
            inventory.RemoveTunnel(Slot(entryName));
        }
    }

    public RasConnectionStatus GetStatus(RasConnectionHandle handle)
    {
        var entry = EntryOf(handle);
        lock (_lock)
        {
            return entry is not null && _connected.Contains(entry) ? RasConnectionStatus.Connected : RasConnectionStatus.Gone;
        }
    }

    public IReadOnlyList<RasActiveConnection> FindOwnConnections() => ConnectedEntries
        .Select(e => new RasActiveConnection(new RasConnectionHandle(HandleBase + Slot(e)), e, "x.pbk", Guid.Empty))
        .ToList();

    public RasProjection GetProjection(RasConnectionHandle handle) =>
        new(FakeInventory.TunnelAddress((int)(handle.Value - HandleBase)), Ipv4.Parse("192.168.44.1"));

    public RasStatistics? GetStatistics(RasConnectionHandle handle) => new(1000, 2000, TimeSpan.FromSeconds(5));

    private string? EntryOf(RasConnectionHandle handle)
    {
        lock (_lock)
        {
            return _slots.FirstOrDefault(p => HandleBase + p.Value == handle.Value).Key;
        }
    }
}

internal sealed class FakeSecrets : ISecretOps
{
    public Dictionary<Guid, string> Saved { get; } = [];
    public Dictionary<Guid, string> Keys { get; } = [];
    private Dictionary<Guid, string> Store(SecretKind kind) => kind == SecretKind.Password ? Saved : Keys;

    public char[]? TryLoad(Guid profileId, SecretKind kind = SecretKind.Password) => Store(kind).TryGetValue(profileId, out var value) ? value.ToCharArray() : null;

    public void Save(Guid profileId, ReadOnlySpan<char> password, SecretKind kind = SecretKind.Password) => Store(kind)[profileId] = password.ToString();

    public void Delete(Guid profileId, SecretKind kind = SecretKind.Password) => Store(kind).Remove(profileId);

    public bool Contains(Guid profileId, SecretKind kind = SecretKind.Password) => Store(kind).ContainsKey(profileId);
}

internal sealed class FakeResolver : IResolver
{
    public IReadOnlyList<uint> Answer { get; set; } = [FakeWorld.Server];

    /// <summary>Ответы по именам хостов; если имени нет — общий Answer.</summary>
    public Dictionary<string, IReadOnlyList<uint>> Answers { get; } = new(StringComparer.OrdinalIgnoreCase);

    public int Calls { get; private set; }

    public Task<IReadOnlyList<uint>> ResolveAsync(string host, IReadOnlyList<uint> servers, uint? interfaceIndex, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(Answers.GetValueOrDefault(host, Answer));
    }
}

internal sealed class FakeProxy : IDnsProxy
{
    public DnsProxyConfiguration Configuration { get; set; } = new();

    public IPinnedRouteSink? RouteSink { get; set; }

    public DnsProxyStats Stats => new(0, 0, 0, 0, 0);

    public bool IsRunning { get; private set; }

    public Dictionary<string, IReadOnlyList<uint>> Pinned { get; } = [];

    public void Start() => IsRunning = true;

    public Dictionary<string, TimeSpan?> PinLifetimes { get; } = [];

    public void Pin(string name, IReadOnlyList<uint> addresses, TimeSpan? lifetime = null)
    {
        Pinned[name] = addresses;
        PinLifetimes[name] = lifetime;
    }

    public void RetainPins(IEnumerable<string> permanentNames)
    {
        var keep = permanentNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var name in Pinned.Keys.Where(n => PinLifetimes.GetValueOrDefault(n) is null && !keep.Contains(n)).ToList())
        {
            Pinned.Remove(name);
            PinLifetimes.Remove(name);
        }
    }

    public void ClearCache()
    {
    }
}

internal sealed class FakeProbes : IProbeOps
{
    public bool TunnelWorks { get; set; } = true;

    /// <summary>Доступна ли российская контрольная цель напрямую: false воспроизводит сеть, где 77.88.55.242 не отвечает.</summary>
    public bool RussianWorks { get; set; } = true;

    public FakeInventory? Inventory { get; set; }

    /// <summary>
    /// Придерживает пробу, пока тест её не отпустит: так воспроизводится таймаут сокета и проверяется,
    /// что очередь актора его не ждёт. null — проба отвечает сразу.
    /// </summary>
    public TaskCompletionSource? Gate { get; set; }

    public async Task<TcpProbeResult> TcpAsync(uint remote, ushort port, uint? localAddress, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (Gate is { } gate)
        {
            await gate.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
        }

        // Иностранная цель по умолчанию — 1.1.1.1, российская — 77.88.55.242.
        var foreign = remote == Ipv4.Parse("1.1.1.1");
        if (foreign)
        {
            return TunnelWorks
                ? new TcpProbeResult(true, localAddress ?? FakeWorld.TunnelAddress, null)
                : new TcpProbeResult(false, null, "таймаут");
        }

        return RussianWorks
            ? new TcpProbeResult(true, localAddress ?? FakeWorld.WiFiAddress, null)
            : new TcpProbeResult(false, null, "таймаут");
    }

    /// <summary>Что «предъявляет» сервер по TLS: тест задаёт это сам; null — сервер не отвечает по TLS.</summary>
    public ServerCertificateFacts? ServerCertificate { get; set; }

    public int ServerCertificateCalls { get; private set; }

    public TaskCompletionSource<ServerCertificateFacts?>? CertificateResult { get; set; }

    public Task<ServerCertificateFacts?> ServerCertificateAsync(uint remote, ushort port, string? host, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ServerCertificateCalls++;
        return CertificateResult?.Task ?? Task.FromResult(ServerCertificate);
    }

    public BestRoute? FindBestRoute(uint destination) => null;
}

/// <summary>
/// Помощники AnyConnect: тест сам «присылает» события от имени процесса и видит отправленные команды.
/// </summary>
internal sealed class FakeAnyConnect : IAnyConnectOps
{
    public List<FakeAnyConnectSession> Sessions { get; } = [];

    public FakeAnyConnectSession? Last => Sessions.Count > 0 ? Sessions[^1] : null;

    public bool FailStart { get; set; }

    public IAnyConnectSession Start(Action<SplitVpn.Core.OpenConnect.HelperEvent> onEvent)
    {
        if (FailStart)
        {
            throw new FileNotFoundException("Не найден помощник AnyConnect.");
        }

        var session = new FakeAnyConnectSession(onEvent);
        Sessions.Add(session);
        return session;
    }
}

internal sealed class FakeAnyConnectSession(Action<SplitVpn.Core.OpenConnect.HelperEvent> onEvent) : IAnyConnectSession
{
    public List<SplitVpn.Core.OpenConnect.HelperCommand> Commands { get; } = [];

    public bool Disposed { get; private set; }

    public void Emit(SplitVpn.Core.OpenConnect.HelperEvent helperEvent) => onEvent(helperEvent);

    public bool Send(SplitVpn.Core.OpenConnect.HelperCommand command)
    {
        if (Disposed)
        {
            return false;
        }

        Commands.Add(command);
        return true;
    }

    public void Dispose() => Disposed = true;
}
