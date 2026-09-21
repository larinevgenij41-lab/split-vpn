using System.Buffers.Binary;
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
/// выбирает DNS-сервер, а трафик идёт по политике.
/// </summary>
public sealed record DomainRoute(string Suffix, RouteTarget Target, DnsRoute? Route, bool PinAddresses = true);

/// <summary>Имя разрешено по правилу для домена: адреса нужно закрепить за целью.</summary>
public sealed record PinnedRouteNotice(string Name, RouteTarget Target, IReadOnlyList<uint> Addresses, TimeSpan Ttl);

/// <summary>Приёмник закреплений: служба ставит маршруты и фильтры на полученные адреса.</summary>
public interface IPinnedRouteSink
{
    /// <summary>Ответ DNS ждёт применения маршрута: иначе первое соединение уйдёт не туда.</summary>
    ValueTask ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken);
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

    private readonly DnsCache _cache;
    private readonly IPAddress _listenAddress;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Task> _loops = [];
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
    public void Start()
    {
        var endpoint = new IPEndPoint(_listenAddress, 53);
        _udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
        _udp.Bind(endpoint);
        _loops.Add(Task.Run(() => UdpLoopAsync(_udp, _stop.Token)));
        _loops.Add(Task.Run(() => TcpStartLoopAsync(endpoint, _stop.Token)));
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _udp?.Dispose();
        _tcp?.Stop();
        await Task.WhenAll(_loops.Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default)));
        _stop.Dispose();
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

        var offline = configuration.Mode != DnsProxyMode.Online;
        var cached = _cache.TryGet(question, DnsMessage.GetId(query), offline);
        if (cached is not null && (offline || !IsStale(cached)))
        {
            Interlocked.Increment(ref _cacheHits);
            await AnnounceAsync(domain, question, cached, cancellationToken);
            return cached;
        }

        var route = SelectRoute(configuration, question.Name);
        var response = route is null ? null : await DnsForwarder.ForwardAsync(query, route.Servers, route.InterfaceIndex, DnsForwarder.DefaultTimeout, cancellationToken);
        if (response is null)
        {
            Interlocked.Increment(ref _failures);
            return cached ?? DnsMessage.BuildServerFailure(query);
        }

        Interlocked.Increment(ref _forwarded);
        _cache.Put(question, response);
        await AnnounceAsync(domain, question, response, cancellationToken);
        return response;
    }

    /// <summary>Сообщает службе адреса имени, подпадающего под правило для домена.</summary>
    private async Task AnnounceAsync(DomainRoute? domain, DnsQuestion question, byte[] response, CancellationToken cancellationToken)
    {
        if (domain is not { PinAddresses: true } || RouteSink is null || question.Type != DnsMessage.TypeA || DnsMessage.GetRcode(response) != 0)
        {
            return;
        }

        var addresses = DnsMessage.ReadAddresses(response);
        if (addresses.Count == 0)
        {
            return;
        }

        var seconds = DnsMessage.GetMinTtl(response) ?? 0;
        var ttl = TimeSpan.FromSeconds(Math.Clamp(seconds, MinRouteTtl.TotalSeconds, MaxRouteTtl.TotalSeconds));
        try
        {
            await RouteSink.ObserveAsync(new PinnedRouteNotice(question.Name, domain.Target, addresses, ttl), cancellationToken);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            Interlocked.Increment(ref _failures);
        }
    }

    /// <summary>Правило для домена с самым длинным подходящим суффиксом.</summary>
    internal static DomainRoute? MatchDomain(DnsProxyConfiguration configuration, string name) => configuration.DomainRoutes
        .Where(d => IsUnderSuffix(name, d.Suffix))
        .OrderByDescending(d => d.Suffix.Length)
        .FirstOrDefault();

    internal static DnsRoute? SelectRoute(DnsProxyConfiguration configuration, string name)
    {
        var local = configuration.Local is null
            ? null
            : configuration.LocalSuffixes.Where(s => IsUnderSuffix(name, s)).OrderByDescending(s => s.Length).FirstOrDefault();
        var domain = MatchDomain(configuration, name);

        // Из двух совпавших суффиксов выигрывает более длинный; при равенстве — правило для домена.
        if (local is not null && (domain is null || local.Length > domain.Suffix.Length))
        {
            return configuration.Local;
        }

        if (domain?.Route is { } route)
        {
            return route;
        }

        return configuration.Mode switch
        {
            DnsProxyMode.Online => configuration.Tunnel,
            DnsProxyMode.DirectAllowed => configuration.Direct,
            _ => null,
        };
    }

    private static bool IsUnderSuffix(string name, string suffix)
    {
        var trimmed = suffix.Trim('.').ToLowerInvariant();
        return trimmed.Length > 0 && (name == trimmed || name.EndsWith("." + trimmed, StringComparison.Ordinal));
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

            var query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            _ = Task.Run(() => ReplyUdpAsync(socket, query, received.RemoteEndPoint, token), token);
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

            _ = Task.Run(() => ServeTcpAsync(client, token), token);
        }
    }

    private async Task ServeTcpAsync(TcpClient client, CancellationToken token)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var header = new byte[2];
                await stream.ReadExactlyAsync(header, token);
                var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(header)];
                await stream.ReadExactlyAsync(query, token);
                var response = await HandleAsync(query, token) ?? DnsMessage.BuildServerFailure(query);
                var framed = new byte[response.Length + 2];
                BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)response.Length);
                response.CopyTo(framed, 2);
                await stream.WriteAsync(framed, token);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or FormatException)
            {
                Interlocked.Increment(ref _failures);
            }
        }
    }
}
