using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Policy;

namespace SplitVpn.Windows.Dns;

public enum DnsProxyMode
{
    /// <summary>Upstream через туннель.</summary>
    Online,

    /// <summary>Туннеля нет: только кеш и закреплённые записи.</summary>
    Offline,

    /// <summary>Туннеля нет, пользователь разрешил DNS напрямую: исходный DNS через основной адаптер.</summary>
    DirectAllowed,
}

/// <summary>Маршрут пересылки: список серверов и интерфейс, через который им отправлять запросы.</summary>
public sealed record DnsRoute(IReadOnlyList<IPEndPoint> Servers, uint? InterfaceIndex);

/// <summary>
/// Правило для домена: имена под этим суффиксом разрешаются по своему пути, а полученные адреса
/// закрепляются за целью на время TTL ответа. Без закрепления (суффиксы шлюза AnyConnect) правило только
/// выбирает DNS-сервер, а трафик идёт по политике. Unavailable — цель правила существует, но сейчас
/// недоступна: такое имя не разрешается вовсе, чтобы не уйти к чужому DNS.
/// </summary>
public sealed record DomainRoute(string Suffix, RouteTarget Target, DnsRoute? Route, bool PinAddresses = true, bool Unavailable = false);

/// <summary>Куда отправлять запрос; Unavailable — отвечать отказом, не обращаясь к общему upstream.</summary>
internal sealed record DnsRouteChoice(DnsRoute? Route, bool Unavailable);

/// <summary>Имя разрешено по правилу для домена: адреса нужно закрепить за целью.</summary>
public sealed record PinnedRouteNotice(string Name, string Suffix, RouteTarget Target, IReadOnlyList<uint> Addresses, TimeSpan Ttl);

/// <summary>Приёмник закреплений: служба ставит маршруты и фильтры на полученные адреса.</summary>
public interface IPinnedRouteSink
{
    /// <summary>
    /// Ответ DNS ждёт применения маршрута: иначе первое соединение уйдёт не туда. false — применение не
    /// подтверждено, и посредник обязан ответить отказом, а не адресом без защиты.
    /// </summary>
    ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken);
}

public sealed record DnsProxyConfiguration
{
    public DnsProxyMode Mode { get; init; } = DnsProxyMode.Offline;

    public DnsRoute? Tunnel { get; init; }

    public DnsRoute? Direct { get; init; }

    public IReadOnlyList<string> LocalSuffixes { get; init; } = [];

    public DnsRoute? Local { get; init; }

    /// <summary>Правила для доменов; при совпадении нескольких выигрывает самый длинный суффикс.</summary>
    public IReadOnlyList<DomainRoute> DomainRoutes { get; init; } = [];
}

public sealed record DnsProxyStats(long Queries, long CacheHits, long Pinned, long Forwarded, long Failures);

/// <summary>
/// Локальный DNS-посредник для системного резолвера. Имена в журнал не пишутся.
/// </summary>
public sealed class DnsProxyServer : IAsyncDisposable
{
    private const int MaxUdpMessage = 4096;
    private static readonly TimeSpan PinnedTtl = TimeSpan.FromMinutes(5);

    /// <summary>Границы срока жизни закрепления по правилу для домена.</summary>
    public static readonly TimeSpan MinRouteTtl = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan MaxRouteTtl = TimeSpan.FromHours(1);

    /// <summary>
    /// Сколько запросов посредник обрабатывает одновременно. Локальная программа может слать их без
    /// ограничения: без предела растут память, сокеты upstream и очередь службы.
    /// </summary>
    public const int MaxConcurrentQueries = 256;

    /// <summary>Сколько соединений TCP обслуживается одновременно.</summary>
    public const int MaxTcpClients = 64;

    /// <summary>Предел на всё обслуживание TCP-клиента: заголовок, тело, ответ.</summary>
    public static readonly TimeSpan TcpRequestTimeout = TimeSpan.FromSeconds(10);

    private readonly DnsCache _cache;
    private readonly IPAddress _listenAddress;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Task> _loops = [];
    private readonly Lock _workGate = new();
    private readonly HashSet<Task> _workers = [];
    private Task? _disposeTask;
    private readonly SemaphoreSlim _concurrency = new(MaxConcurrentQueries);
    private readonly SemaphoreSlim _tcpClients = new(MaxTcpClients);

    /// <summary>Одинаковые запросы в полёте объединяются: очередь у upstream не растёт от повторов.</summary>
    private readonly ConcurrentDictionary<string, Task<byte[]?>> _inFlight = new(StringComparer.Ordinal);

    private DnsProxyConfiguration _configuration = new();
    private Socket? _udp;
    private TcpListener? _tcp;
    private long _queries;
    private long _cacheHits;
    private long _pinned;
    private long _forwarded;
    private long _failures;

    public DnsProxyServer(IPAddress listenAddress, DnsCache cache)
    {
        _listenAddress = listenAddress;
        _cache = cache;
    }

    public DnsProxyConfiguration Configuration
    {
        get => Volatile.Read(ref _configuration);
        set => Volatile.Write(ref _configuration, value ?? throw new ArgumentNullException(nameof(value)));
    }

    public DnsProxyStats Stats => new(
        Interlocked.Read(ref _queries),
        Interlocked.Read(ref _cacheHits),
        Interlocked.Read(ref _pinned),
        Interlocked.Read(ref _forwarded),
        Interlocked.Read(ref _failures));

    /// <summary>Кому сообщать об адресах, полученных по правилам для доменов.</summary>
    public IPinnedRouteSink? RouteSink { get; set; }

    public bool TcpListening => _tcp is not null;

    /// <summary>Занимает UDP-порт 53 эксклюзивно; TCP не обязателен и повторяется в фоне.</summary>
    public void Start() => Start(53);

    /// <summary>Случайный локальный порт в тестах позволяет не затрагивать системный DNS.</summary>
    internal IPEndPoint? ListenEndPoint => _udp?.LocalEndPoint as IPEndPoint;

    internal void Start(int port)
    {
        lock (_workGate)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (_udp is not null)
            {
                throw new InvalidOperationException("DNS-посредник уже запущен.");
            }

            var endpoint = new IPEndPoint(_listenAddress, port);
            var socket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
            try
            {
                socket.Bind(endpoint);
            }
            catch
            {
                socket.Dispose();
                throw;
            }

            _udp = socket;
            endpoint = (IPEndPoint)socket.LocalEndPoint!;
            _loops.Add(Task.Run(() => UdpLoopAsync(socket, _stop.Token)));
            _loops.Add(Task.Run(() => TcpStartLoopAsync(endpoint, _stop.Token)));
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_workGate)
        {
            return new ValueTask(_disposeTask ??= DisposeCoreAsync());
        }
    }

    private async Task DisposeCoreAsync()
    {
        await _stop.CancelAsync();
        _udp?.Dispose();
        _tcp?.Stop();
        await Task.WhenAll(_loops.Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default)));
        // Приём уже завершён: новых обработчиков не будет. Сначала они вернут разрешения
        // семафоров и закроют клиентские сокеты, затем можно освобождать общие ресурсы.
        Task[] workers;
        lock (_workGate)
        {
            workers = _workers.ToArray();
        }

        await Task.WhenAll(workers);
        await Task.WhenAll(_inFlight.Values);
        // TCP мог стартовать одновременно с отменой, после первого Stop выше.
        _tcp?.Stop();
        _concurrency.Dispose();
        _tcpClients.Dispose();
        _stop.Dispose();
    }

    private void RunWorker(Func<Task> action)
    {
        var worker = Task.Run(async () =>
        {
            try
            {
                await action();
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _failures);
                System.Diagnostics.Trace.TraceError("Ошибка обработчика DNS: {0}", ex.GetType().Name);
            }
        });
        lock (_workGate)
        {
            _workers.Add(worker);
        }

        _ = RemoveCompletedWorkerAsync(worker);
    }

    private async Task RemoveCompletedWorkerAsync(Task worker)
    {
        await worker;
        lock (_workGate)
        {
            _workers.Remove(worker);
        }
    }

    /// <summary>Обработка одного запроса; открыто для тестов.</summary>
    public async Task<byte[]?> HandleAsync(byte[] query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        Interlocked.Increment(ref _queries);
        if (!DnsMessage.TryReadQuestion(query, out var question))
        {
            return null;
        }

        var pinned = TryAnswerPinned(query, question);
        if (pinned is not null)
        {
            Interlocked.Increment(ref _pinned);
            return pinned;
        }

        var configuration = Configuration;
        var domain = MatchDomain(configuration, question.Name);
        if (domain?.Target.Kind == TargetKind.Block)
        {
            // Имя заблокировано правилом: отвечаем «такого имени нет», upstream не трогаем.
            return DnsMessage.BuildEmptyResponse(query, rcode: 3);
        }

        var choice = SelectRoute(configuration, question.Name, domain);
        if (choice.Unavailable)
        {
            // Правило есть, но его туннель не поднят. Общий DNS дал бы ответ чужого вида и увёл бы частное
            // имя к провайдеру или в другой VPN; кеш прежнего пути здесь тоже не годится.
            Interlocked.Increment(ref _failures);
            return DnsMessage.BuildServerFailure(query);
        }

        var offline = configuration.Mode == DnsProxyMode.Offline;
        var context = Context(choice.Route);
        var id = DnsMessage.GetId(query);

        // Пути нет вовсе (аварийный режим): выбирать контекст не из чего — годится любой известный ответ.
        var cached = _cache.TryGet(question, context, id, offline)
            ?? (choice.Route is null ? _cache.TryGetAnyPath(question, id) : null);
        if (cached is not null && (offline || !IsStale(cached)))
        {
            Interlocked.Increment(ref _cacheHits);
            return await AnnounceAsync(configuration, domain, question, cached, query, cancellationToken);
        }

        var response = choice.Route is null ? null : await ForwardAsync(query, question, context, choice.Route);
        if (response is null)
        {
            Interlocked.Increment(ref _failures);
            // Путь не ответил: просроченный ответ того же пути лучше отказа, но не старше предельного
            // возраста. Ответ чужого пути здесь не годится — он может быть про другую сеть.
            var stale = _cache.TryGet(question, context, id, offline: true)
                ?? (choice.Route is null ? _cache.TryGetAnyPath(question, id) : null);
            return stale is null ? DnsMessage.BuildServerFailure(query)
                : await AnnounceAsync(configuration, domain, question, stale, query, cancellationToken);
        }

        Interlocked.Increment(ref _forwarded);
        if (ReferenceEquals(Configuration, configuration))
        {
            // Пока шёл запрос, настройки могли смениться: ответ прежнего пути в новый кеш не кладётся.
            _cache.Put(question, context, response);
        }

        return await AnnounceAsync(configuration, domain, question, response, query, cancellationToken);
    }

    /// <summary>
    /// Сообщает службе адреса имени, подпадающего под правило для домена, и возвращает ответ только после
    /// подтверждённого применения. Не подтверждено — отказ: адрес без маршрута ушёл бы мимо назначенного пути.
    /// </summary>
    private async Task<byte[]> AnnounceAsync(
        DnsProxyConfiguration configuration,
        DomainRoute? domain,
        DnsQuestion question,
        byte[] response,
        byte[] query,
        CancellationToken cancellationToken)
    {
        if (domain is not { PinAddresses: true } || RouteSink is null || question.Type != DnsMessage.TypeA || DnsMessage.GetRcode(response) != 0)
        {
            return response;
        }

        var addresses = DnsMessage.ReadAddresses(response, question.Name);
        if (addresses.Count == 0)
        {
            return response;
        }

        if (ReferenceEquals(Configuration, configuration))
        {
            try
            {
                var ttl = RouteTtl(response);
                var started = System.Diagnostics.Stopwatch.GetTimestamp();
                if (await RouteSink.ObserveAsync(new PinnedRouteNotice(question.Name, domain.Suffix, domain.Target, addresses, ttl), cancellationToken))
                {
                    // Маршрут уже стареет, пока ответ ждёт очередь. Клиентский кеш не должен пережить
                    // закрепление, даже если upstream прислал суточный TTL или разные TTL записей.
                    var remaining = ttl - System.Diagnostics.Stopwatch.GetElapsedTime(started);
                    if (DnsMessage.CapTtls(response, (uint)Math.Max(0, remaining.TotalSeconds)))
                    {
                        return response;
                    }
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
            {
                // Служба останавливается: закрепление не применить.
            }
        }

        Interlocked.Increment(ref _failures);
        return DnsMessage.BuildServerFailure(query);
    }

    private static TimeSpan RouteTtl(byte[] response)
    {
        var seconds = DnsMessage.GetMinTtl(response) ?? 0;
        return TimeSpan.FromSeconds(Math.Clamp(seconds, MinRouteTtl.TotalSeconds, MaxRouteTtl.TotalSeconds));
    }

    /// <summary>
    /// Пересылка с объединением одинаковых запросов в полёте. Ответ у каждого клиента свой: идентификатор
    /// принадлежит его запросу.
    /// </summary>
    private async Task<byte[]?> ForwardAsync(byte[] query, DnsQuestion question, string context, DnsRoute route)
    {
        var key = string.Join('|', question.Name, question.Type, question.Class, context);
        var shared = await ShareAsync(key, query, route);
        if (shared is null)
        {
            return null;
        }

        var copy = shared.ToArray();
        DnsMessage.SetId(copy, DnsMessage.GetId(query));
        return copy;
    }

    private Task<byte[]?> ShareAsync(string key, byte[] query, DnsRoute route)
    {
        if (_inFlight.TryGetValue(key, out var running))
        {
            return running;
        }

        var completion = new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var work = _inFlight.GetOrAdd(key, completion.Task);
        if (!ReferenceEquals(work, completion.Task))
        {
            return work;
        }

        _ = Task.Run(async () =>
        {
            byte[]? result = null;
            try
            {
                result = await DnsForwarder.ForwardAsync(query, route.Servers, route.InterfaceIndex, DnsForwarder.DefaultTimeout, _stop.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException or ObjectDisposedException)
            {
                // Остановка службы или обрыв пути: ожидающие получат отказ, а не зависнут.
            }
            finally
            {
                _inFlight.TryRemove(key, out _);
                completion.TrySetResult(result);
            }
        });
        return completion.Task;
    }

    /// <summary>Путь разрешения: ответы разных серверов и интерфейсов нельзя смешивать в одном кеше.</summary>
    private static string Context(DnsRoute? route) =>
        route is null ? "" : route.InterfaceIndex + ":" + string.Join(",", route.Servers);

    /// <summary>Правило для домена с самым длинным подходящим суффиксом.</summary>
    internal static DomainRoute? MatchDomain(DnsProxyConfiguration configuration, string name)
    {
        DomainRoute? best = null;
        foreach (var domain in configuration.DomainRoutes)
        {
            if ((best is null || domain.Suffix.Length > best.Suffix.Length) && IsUnderSuffix(name, domain.Suffix))
            {
                best = domain;
            }
        }

        return best;
    }

    internal static DnsRouteChoice SelectRoute(DnsProxyConfiguration configuration, string name) =>
        SelectRoute(configuration, name, MatchDomain(configuration, name));

    private static DnsRouteChoice SelectRoute(DnsProxyConfiguration configuration, string name, DomainRoute? domain)
    {
        string? local = null;
        if (configuration.Local is not null)
        {
            foreach (var suffix in configuration.LocalSuffixes)
            {
                if ((local is null || suffix.Length > local.Length) && IsUnderSuffix(name, suffix))
                {
                    local = suffix;
                }
            }
        }

        // Из двух совпавших суффиксов выигрывает более длинный; при равенстве — правило для домена.
        if (local is not null && (domain is null || local.Length > domain.Suffix.Length))
        {
            return new DnsRouteChoice(configuration.Local, false);
        }

        if (domain is not null)
        {
            if (domain.Route is { } route)
            {
                return new DnsRouteChoice(route, false);
            }

            if (domain.Unavailable)
            {
                return new DnsRouteChoice(null, true);
            }
        }

        return new DnsRouteChoice(configuration.Mode switch
        {
            DnsProxyMode.Online => configuration.Tunnel,
            DnsProxyMode.DirectAllowed => configuration.Direct,
            _ => null,
        }, false);
    }

    private static bool IsUnderSuffix(string name, string suffix)
    {
        var trimmed = suffix.AsSpan().Trim('.');
        return trimmed.Length > 0
            && name.AsSpan().EndsWith(trimmed, StringComparison.OrdinalIgnoreCase)
            && (name.Length == trimmed.Length || name[name.Length - trimmed.Length - 1] == '.');
    }

    private static bool IsStale(byte[] response) => DnsMessage.GetMinTtl(response) is null or 0;

    private byte[]? TryAnswerPinned(byte[] query, DnsQuestion question)
    {
        if (!_cache.TryGetPinned(question.Name, out var addresses))
        {
            return null;
        }

        return question.Type == DnsMessage.TypeA
            ? DnsMessage.BuildAddressResponse(query, addresses, (uint)PinnedTtl.TotalSeconds)
            : DnsMessage.BuildEmptyResponse(query);
    }

    private async Task UdpLoopAsync(Socket socket, CancellationToken token)
    {
        var buffer = new byte[MaxUdpMessage];
        while (!token.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await socket.ReceiveFromAsync(buffer, new IPEndPoint(_listenAddress.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0), token);
            }
            catch (SocketException)
            {
                // ICMP port unreachable от клиента приходит как ошибка приёма — продолжаем.
                continue;
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }

            if (!_concurrency.Wait(0, CancellationToken.None))
            {
                // Предел одновременных запросов: пакет отбрасывается, клиент повторит. Копить работу нельзя.
                Interlocked.Increment(ref _failures);
                continue;
            }

            var query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            RunWorker(() => ReplyUdpAsync(socket, query, received.RemoteEndPoint, token));
        }
    }

    private async Task ReplyUdpAsync(Socket socket, byte[] query, EndPoint client, CancellationToken token)
    {
        try
        {
            var response = await HandleAsync(query, token);
            if (response is not null)
            {
                await socket.SendToAsync(response, client, token);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            Interlocked.Increment(ref _failures);
        }
        finally
        {
            _concurrency.Release();
        }
    }

    private async Task TcpStartLoopAsync(IPEndPoint endpoint, CancellationToken token)
    {
        while (!token.IsCancellationRequested && _tcp is null)
        {
            try
            {
                var listener = new TcpListener(endpoint) { ExclusiveAddressUse = true };
                listener.Start();
                _tcp = listener;
                await TcpAcceptLoopAsync(listener, token);
                return;
            }
            catch (SocketException)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), token).ContinueWith(_ => { }, TaskScheduler.Default);
            }
        }
    }

    private async Task TcpAcceptLoopAsync(TcpListener listener, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            if (!_tcpClients.Wait(0, CancellationToken.None))
            {
                // Предел соединений: лишние закрываются сразу, иначе программа удержит их все.
                Interlocked.Increment(ref _failures);
                client.Dispose();
                continue;
            }

            RunWorker(() => ServeTcpAsync(client, token));
        }
    }

    /// <summary>
    /// Обслуживание одного TCP-клиента под общим дедлайном: местная программа может открыть соединение
    /// и не прислать заголовок — без предела такие соединения копились бы до остановки службы.
    /// </summary>
    private async Task ServeTcpAsync(TcpClient client, CancellationToken token)
    {
        using (client)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TcpRequestTimeout);
            try
            {
                var stream = client.GetStream();
                var header = new byte[2];
                await stream.ReadExactlyAsync(header, deadline.Token);
                var length = BinaryPrimitives.ReadUInt16BigEndian(header);
                if (length is 0 or > MaxUdpMessage)
                {
                    Interlocked.Increment(ref _failures);
                    return;
                }

                var query = new byte[length];
                await stream.ReadExactlyAsync(query, deadline.Token);
                var response = await HandleAsync(query, deadline.Token) ?? DnsMessage.BuildServerFailure(query);
                var framed = new byte[response.Length + 2];
                BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)response.Length);
                response.CopyTo(framed, 2);
                await stream.WriteAsync(framed, deadline.Token);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or FormatException)
            {
                Interlocked.Increment(ref _failures);
            }
            finally
            {
                _tcpClients.Release();
            }
        }
    }
}
