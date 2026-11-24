using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Пересылка различает окончательный ответ (NOERROR, NODATA, NXDOMAIN) и «ответа нет» (все серверы пути ответили
/// REFUSED или SERVFAIL, усечённый ответ UDP не добран по TCP). Во втором случае посредник берёт просроченный ответ
/// из кеша, а без него сам отвечает SERVFAIL. Сервер — loopback на случайном порту.
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

    [Theory]
    [InlineData(5)]
    [InlineData(2)]
    public async Task ServerRefusalOrFailure_IsNoAnswer(int rcode)
    {
        _upstream.Rcode = rcode;
        var query = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_upstream.EndPoint], null, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        Assert.Null(response);
        Assert.Equal(1, _upstream.Received);
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
    public async Task TruncatedUdpWithoutTcp_IsNoAnswer()
    {
        // TCP на этом порту никто не слушает: добрать ответ нельзя, а усечённый ответ без адресов не окончательный.
        _upstream.Truncate = true;
        var query = DnsMessage.BuildQuery(1, "big.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_upstream.EndPoint], null, TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        Assert.Null(response);
    }

    [Fact]
    public async Task Proxy_UpstreamRefuses_ServesStaleCachedAnswer()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UnixEpoch);
        var cache = new DnsCache(time);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache)
        {
            Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = new DnsRoute([_upstream.EndPoint], null) },
        };
        var warm = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(warm, out var question);
        cache.Put(question, ":" + _upstream.EndPoint, DnsMessage.BuildAddressResponse(warm, [Ipv4.Parse("203.0.113.9")], 60));
        time.Advance(TimeSpan.FromMinutes(5));
        _upstream.Rcode = 5;

        var response = await proxy.HandleAsync(DnsMessage.BuildQuery(0x2222, "site.example", DnsMessage.TypeA), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.Equal(1, _upstream.Received);
        Assert.Equal(0x2222, DnsMessage.GetId(response));
        Assert.Equal(0, DnsMessage.GetRcode(response));
        Assert.Equal([Ipv4.Parse("203.0.113.9")], DnsMessage.ReadAddresses(response));
    }

    [Fact]
    public async Task Proxy_UpstreamRefuses_WithoutCache_AnswersServerFailure()
    {
        var cache = new DnsCache(new FakeTimeProvider(DateTimeOffset.UnixEpoch));
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache)
        {
            Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = new DnsRoute([_upstream.EndPoint], null) },
        };
        _upstream.Rcode = 5;

        var response = await proxy.HandleAsync(DnsMessage.BuildQuery(3, "site.example", DnsMessage.TypeA), TestContext.Current.CancellationToken);

        Assert.NotNull(response);
        Assert.Equal(2, DnsMessage.GetRcode(response));
        Assert.Equal(0, cache.Count);
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
