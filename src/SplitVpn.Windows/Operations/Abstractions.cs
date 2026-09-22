using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Windows.Operations;

// Узкие интерфейсы системных операций: координатор службы работает только через них,
// тесты подменяют их фейками с внедрением отказов.

public interface INetInventory
{
    NetSnapshot Capture();

    /// <summary>DNS от DHCP из реестра — не меняется, когда на интерфейсе стоит наш loopback.</summary>
    IReadOnlyList<uint> DhcpDnsServers(Guid interfaceGuid);
}

public interface IRouteOps
{
    RouteApplyResult Reconcile(IReadOnlyCollection<RouteKey> desired);
}

public interface IWfpOps : IDisposable
{
    /// <summary>Заменяет группу фильтров одной транзакцией; возвращает число объектов WFP в группе.</summary>
    int ReplaceGroup(FilterGroup group, IReadOnlyList<FilterSpec> specs);

    /// <summary>Число установленных объектов WFP по группам: расхождение означает изменение извне.</summary>
    IReadOnlyDictionary<FilterGroup, int> InstalledCounts();

    /// <summary>Удаляет все объекты провайдера (фильтры, sublayer, провайдер).</summary>
    void RemoveAll();

    /// <summary>Переоткрыть сессию BFE после ошибки или перезапуска службы BFE.</summary>
    void Reopen();
}

public interface IDnsOps
{
    string ReadNameServer(Guid interfaceGuid);

    InterfaceDnsBackup Capture(Guid interfaceGuid, InterfaceDnsBackup? previous);

    void ApplyLoopback(Guid interfaceGuid);

    string ReadSearchList(Guid interfaceGuid);

    void SetSearchList(Guid interfaceGuid, string searchList);

    void ClearNameServer(Guid interfaceGuid);

    DnsRestoreOutcome Restore(Guid interfaceGuid, InterfaceDnsBackup? backup);

    void FlushCache();
}

public interface IRasOps
{
    /// <summary>Создаёт или обновляет запись телефонной книги; у каждого профиля своя запись.</summary>
    void SaveEntry(string entryName, ConnectionProfile profile, ReadOnlySpan<char> preSharedKey);

    void DeleteEntry(string entryName);

    /// <summary>Имена всех записей своей телефонной книги.</summary>
    IReadOnlyList<string> EntryNames();

    Task<RasDialResult> DialAsync(string entryName, string userName, ReadOnlyMemory<char> password, string? domain, CancellationToken cancellationToken);

    Task HangUpAsync(RasConnectionHandle handle, CancellationToken cancellationToken);

    RasConnectionStatus GetStatus(RasConnectionHandle handle);

    /// <summary>Активные соединения своей телефонной книги (подхват после перезапуска).</summary>
    IReadOnlyList<RasActiveConnection> FindOwnConnections();

    RasProjection GetProjection(RasConnectionHandle handle);

    RasStatistics? GetStatistics(RasConnectionHandle handle);
}

public interface ISecretOps
{
    char[]? TryLoad(Guid profileId, SecretKind kind = SecretKind.Password);

    void Save(Guid profileId, ReadOnlySpan<char> password, SecretKind kind = SecretKind.Password);

    void Delete(Guid profileId, SecretKind kind = SecretKind.Password);

    bool Contains(Guid profileId, SecretKind kind = SecretKind.Password);
}

public interface IResolver
{
    Task<IReadOnlyList<uint>> ResolveAsync(string host, IReadOnlyList<uint> servers, uint? interfaceIndex, CancellationToken cancellationToken);
}

public interface IDnsProxy
{
    DnsProxyConfiguration Configuration { get; set; }

    /// <summary>Приёмник адресов, полученных по правилам для доменов.</summary>
    IPinnedRouteSink? RouteSink { get; set; }

    DnsProxyStats Stats { get; }

    bool IsRunning { get; }

    void Start();

    void Pin(string name, IReadOnlyList<uint> addresses);

    void ClearCache();
}

public sealed record TcpProbeResult(bool Connected, uint? LocalAddress, string? Error);

public interface IProbeOps
{
    /// <summary>Проба TCP; localAddress привязывает сокет к адресу туннеля — тогда ответ уходит только через него.</summary>
    Task<TcpProbeResult> TcpAsync(uint remote, ushort port, uint? localAddress, TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>
    /// Что за сертификат предъявляет сервер и куда ведёт проверка его отзыва. null — сервер не ответил
    /// по TLS (другой протокол, недоступен). Сеанс не устанавливается: проба только смотрит.
    /// </summary>
    Task<ServerCertificateFacts?> ServerCertificateAsync(uint remote, ushort port, string? host, TimeSpan timeout, CancellationToken cancellationToken);

    BestRoute? FindBestRoute(uint destination);
}

/// <summary>Процессы-помощники AnyConnect: один процесс — один сеанс шлюза.</summary>
public interface IAnyConnectOps
{
    /// <summary>
    /// Запускает помощника. События приходят из фонового потока; последнее всегда TerminatedEvent — помощник
    /// прислал его сам или завершился без него.
    /// </summary>
    IAnyConnectSession Start(Action<Core.OpenConnect.HelperEvent> onEvent);
}

public interface IAnyConnectSession : IDisposable
{
    /// <summary>Отправляет команду; false — канал уже закрыт.</summary>
    bool Send(Core.OpenConnect.HelperCommand command);
}

public enum SecretKind { Password, PreSharedKey }
