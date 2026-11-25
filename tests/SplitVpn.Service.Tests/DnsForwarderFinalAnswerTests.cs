using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Пересылка различает окончательный ответ (NOERROR, NODATA, NXDOMAIN, а также REFUSED от всех серверов пути) и
/// «ответа нет» (молчание, SERVFAIL). Во втором случае посредник берёт просроченный ответ из кеша, а без него сам
/// отвечает SERVFAIL. Усечённый ответ UDP, не добранный по TCP, отдаётся как есть: UDP-клиент получит TC, TCP-клиент —
/// SERVFAIL. Сервер — loopback на случайном порту.
/// </summary>
public sealed class DnsForwarderFinalAnswerTests : IAsyncDisposable
{
    private readonly UdpUpstream _upstream = new();
    private readonly UdpUpstream _second = new();

    public async ValueTask DisposeAsync()
    {
        await _upstream.DisposeAsync();
        await _second.DisposeAsync();
    }

    [Fact]
    public async Task ServerFailure_IsNoAnswer()
    {
        _upstream.Rcode = 2;
        var query = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_upstream.EndPoint], null, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        Assert.Null(response);
        Assert.Equal(1, _upstream.Received);
    }

    /// <summary>REFUSED от всех серверов пути — окончательный ответ (решение корпоративного DNS или фильтра).</summary>
    [Fact]
    public async Task RefusedByAllServers_IsFinalRefused()
    {
        _upstream.Rcode = 5;
        _second.Rcode = 5;
        var query = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_upstream.EndPoint, _second.EndPoint], null, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.Equal(5, DnsMessage.GetRcode(response));
        Assert.Equal(1, _second.Received);
    }

    /// <summary>Один отказал REFUSED, другой SERVFAIL: отказали не все — «ответа нет», как при сбое.</summary>
    [Fact]
    public async Task RefusedAndServerFailure_IsNoAnswer()
    {
        _upstream.Rcode = 5;
        _second.Rcode = 2;
        var query = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_upstream.EndPoint, _second.EndPoint], null, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        Assert.Null(response);
    }

    [Fact]
    public async Task RefusedFirstServer_NextServerAnswers()
    {
        _upstream.Rcode = 5;
        var query = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_upstream.EndPoint, _second.EndPoint], null, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.Equal(0, DnsMessage.GetRcode(response));
        Assert.Single(DnsMessage.ReadAddresses(response));
        Assert.Equal(1, _second.Received);
    }

    [Fact]
    public async Task NxDomain_IsFinalAndStopsAtFirstServer()
    {
        _upstream.Rcode = 3;
        var query = DnsMessage.BuildQuery(1, "missing.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_upstream.EndPoint, _second.EndPoint], null, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.Equal(3, DnsMessage.GetRcode(response));
        Assert.Equal(0, _second.Received);
    }

    [Fact]
    public async Task TruncatedUdpWithoutTcp_ReturnsTruncatedAnswer()
    {
        // TCP на этом порту никто не слушает: добрать ответ нельзя. Усечённый ответ отдаётся как есть (с TC):
        // UDP-клиент повторит запрос по TCP, а TCP-клиенту посредник ответит SERVFAIL.
        _upstream.Truncate = true;
        var query = DnsMessage.BuildQuery(1, "big.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_upstream.EndPoint], null, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.True(DnsMessage.IsTruncated(response));
    }

    private DnsProxyServer Proxy(DnsCache cache) => new(IPAddress.Loopback, cache)
    {
        Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = new DnsRoute([_upstream.EndPoint], null) },
    };

    private (DnsCache Cache, FakeTimeProvider Time) WarmStaleCache()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UnixEpoch);
        var cache = new DnsCache(time);
        var warm = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(warm, out var question);
        cache.Put(question, ":" + _upstream.EndPoint, DnsMessage.BuildAddressResponse(warm, [Ipv4.Parse("203.0.113.9")], 60));
        time.Advance(TimeSpan.FromMinutes(5));
        return (cache, time);
    }

    [Fact]
    public async Task Proxy_UpstreamFails_ServesStaleCachedAnswer()
    {
        var (cache, _) = WarmStaleCache();
        await using var proxy = Proxy(cache);
        _upstream.Rcode = 2;

        var response = await proxy.HandleAsync(DnsMessage.BuildQuery(0x2222, "site.example", DnsMessage.TypeA), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.Equal(1, _upstream.Received);
        Assert.Equal(0x2222, DnsMessage.GetId(response));
        Assert.Equal(0, DnsMessage.GetRcode(response));
        Assert.Equal([Ipv4.Parse("203.0.113.9")], DnsMessage.ReadAddresses(response));
    }

    /// <summary>Свежий отказ REFUSED не подменяется просроченным адресом из кеша: иначе он обходил бы блокировку DNS.</summary>
    [Fact]
    public async Task Proxy_UpstreamRefuses_ReturnsRefused_NotStaleAnswer()
    {
        var (cache, _) = WarmStaleCache();
        await using var proxy = Proxy(cache);
        _upstream.Rcode = 5;

        var response = await proxy.HandleAsync(DnsMessage.BuildQuery(0x2222, "site.example", DnsMessage.TypeA), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.Equal(0x2222, DnsMessage.GetId(response));
        Assert.Equal(5, DnsMessage.GetRcode(response));
        Assert.Empty(DnsMessage.ReadAddresses(response));
    }

    [Fact]
    public async Task Proxy_UpstreamFails_WithoutCache_AnswersServerFailure()
    {
        var cache = new DnsCache(new FakeTimeProvider(DateTimeOffset.UnixEpoch));
        await using var proxy = Proxy(cache);
        _upstream.Rcode = 2;

        var response = await proxy.HandleAsync(DnsMessage.BuildQuery(3, "site.example", DnsMessage.TypeA), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.Equal(2, DnsMessage.GetRcode(response));
        Assert.Equal(0, cache.Count);
    }

    /// <summary>Усечённый ответ при недоступном TCP апстрима: UDP-клиент получает TC, TCP-клиент — SERVFAIL.</summary>
    [Fact]
    public async Task Proxy_TruncatedWithoutUpstreamTcp_UdpClientGetsTc_TcpClientGetsServerFailure()
    {
        var token = TestContext.Current.CancellationToken;
        await using var proxy = Proxy(new DnsCache(new FakeTimeProvider(DateTimeOffset.UnixEpoch)));
        _upstream.Truncate = true;
        proxy.Start(0);
        var endPoint = proxy.ListenEndPoint!;

        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        await udp.SendToAsync(DnsMessage.BuildQuery(0x0101, "big.example", DnsMessage.TypeA), endPoint, token);
        var buffer = new byte[4096];
        var received = await udp.ReceiveFromAsync(buffer, new IPEndPoint(IPAddress.Any, 0), token).AsTask().WaitAsync(TimeSpan.FromSeconds(10), token);
        var udpAnswer = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
        Assert.True(DnsMessage.IsTruncated(udpAnswer));
        Assert.Equal(0, DnsMessage.GetRcode(udpAnswer));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(endPoint, token);
        var stream = tcp.GetStream();
        var query = DnsMessage.BuildQuery(0x0202, "big.example", DnsMessage.TypeA);
        var framed = new byte[query.Length + 2];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed, 2);
        await stream.WriteAsync(framed, token);
        var header = new byte[2];
        await stream.ReadExactlyAsync(header, token).AsTask().WaitAsync(TimeSpan.FromSeconds(10), token);
        var tcpAnswer = new byte[System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(header)];
        await stream.ReadExactlyAsync(tcpAnswer, token);
        Assert.False(DnsMessage.IsTruncated(tcpAnswer));
        Assert.Equal(2, DnsMessage.GetRcode(tcpAnswer));
    }

    /// <summary>UDP-сервер на loopback: отвечает заданным кодом, усечённым ответом или адресом.</summary>
    private sealed class UdpUpstream : IAsyncDisposable
    {
        private readonly Socket _socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;
        private int _received;

        public UdpUpstream()
        {
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            EndPoint = (IPEndPoint)_socket.LocalEndPoint!;
            _loop = Task.Run(LoopAsync);
        }

        public IPEndPoint EndPoint { get; }

        public int Rcode { get; set; }

        public bool Truncate { get; set; }

        public int Received => Volatile.Read(ref _received);

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _socket.Dispose();
            await _loop.ContinueWith(_ => { }, TaskScheduler.Default);
            _stop.Dispose();
        }

        private async Task LoopAsync()
        {
            var buffer = new byte[4096];
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var received = await _socket.ReceiveFromAsync(buffer, new IPEndPoint(IPAddress.Any, 0), _stop.Token);
                    Interlocked.Increment(ref _received);
                    var query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
                    byte[] answer;
                    if (Truncate)
                    {
                        answer = DnsMessage.BuildEmptyResponse(query);
                        answer[2] |= 0x02;
                    }
                    else
                    {
                        answer = Rcode != 0 ? DnsMessage.BuildEmptyResponse(query, Rcode) : DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("198.51.100.7")], 300);
                    }

                    await _socket.SendToAsync(answer, received.RemoteEndPoint, _stop.Token);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // Остановка теста.
            }
        }
    }
}
