using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Посредник на настоящем UDP-сокете к локальному upstream: проверяются выбор пути, кеш, проверка ответа
/// и пределы работы. Наружу ничего не уходит — сервер слушает loopback на случайном порту.
/// </summary>
public sealed class DnsProxyTests : IAsyncDisposable
{
    private static readonly Guid Corporate = new("dddddddd-0000-0000-0000-000000000004");
    private const string CorporateName = "srv.corp.example";

    private readonly FakeUpstream _upstream = new();
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UnixEpoch);
    private readonly DnsCache _cache;
    private readonly DnsProxyServer _proxy;

    public DnsProxyTests()
    {
        _cache = new DnsCache(_time);
        _proxy = new DnsProxyServer(IPAddress.Loopback, _cache);
    }

    public async ValueTask DisposeAsync()
    {
        await _proxy.DisposeAsync();
        await _upstream.DisposeAsync();
    }

    private DnsRoute Upstream => new([_upstream.EndPoint], null);

    [Fact]
    public async Task DomainRule_WithUnavailableTarget_FailsInsteadOfAskingTheGeneralDns()
    {
        _proxy.Configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.DirectAllowed,
            Direct = Upstream,
            DomainRoutes = [new DomainRoute("corp.example", RouteTarget.Tunnel(Corporate), Route: null, PinAddresses: true, Unavailable: true)],
        };

        // Прежний ответ того же имени в кеше не должен подменить недоступный корпоративный путь.
        var warm = DnsMessage.BuildQuery(1, CorporateName, DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(warm, out var question);
        _cache.Put(question, _upstream.Context, DnsMessage.BuildAddressResponse(warm, [Ipv4.Parse("203.0.113.9")], 300));

        var response = await Ask(CorporateName);

        Assert.Equal(2, DnsMessage.GetRcode(response));
        Assert.Equal(0, _upstream.Received);
    }

    [Fact]
    public async Task DirectAllowed_RefreshesAnswerWhenTtlRanOut()
    {
        _proxy.Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = Upstream };
        _upstream.Ttl = 60;

        await Ask("site.example");
        _time.Advance(TimeSpan.FromSeconds(30));
        await Ask("site.example");
        Assert.Equal(1, _upstream.Received);

        _time.Advance(TimeSpan.FromSeconds(120));
        var refreshed = await Ask("site.example");

        Assert.Equal(2, _upstream.Received);
        Assert.Equal(0, DnsMessage.GetRcode(refreshed));
    }

    [Fact]
    public async Task Offline_ServesStaleAnswerOnlyUntilTheLimit()
    {
        _proxy.Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = Upstream };
        _upstream.Ttl = 60;
        await Ask("site.example");

        _proxy.Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.Offline, Direct = Upstream };
        _time.Advance(TimeSpan.FromHours(1));
        Assert.Equal(0, DnsMessage.GetRcode(await Ask("site.example")));

        _time.Advance(DnsCache.MaxStaleAge);
        Assert.Equal(2, DnsMessage.GetRcode(await Ask("site.example")));
    }

    [Fact]
    public async Task IdenticalQueriesInFlight_AreForwardedOnce()
    {
        _proxy.Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = Upstream };
        _upstream.Delay = TimeSpan.FromMilliseconds(200);

        var queries = Enumerable.Range(1, 8).Select(id => _proxy.HandleAsync(DnsMessage.BuildQuery((ushort)id, "busy.example", DnsMessage.TypeA), CancellationToken.None)).ToList();
        var responses = await Task.WhenAll(queries);

        Assert.Equal(1, _upstream.Received);
        Assert.All(responses, r => Assert.Equal(0, DnsMessage.GetRcode(r!)));

        // Идентификатор у каждого клиента свой: общий ответ нельзя отдавать как есть.
        Assert.Equal(Enumerable.Range(1, 8), responses.Select(r => (int)DnsMessage.GetId(r!)).Order());
    }

    [Fact]
    public async Task UpstreamAnswerAboutAnotherName_IsRejected()
    {
        _proxy.Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = Upstream };
        _upstream.AnswerAs = "wrong.example";

        var response = await Ask("private.example");

        Assert.Equal(2, DnsMessage.GetRcode(response));
        Assert.Equal(0, _cache.Count);
    }

    [Fact]
    public async Task DomainRule_AnswersOnlyAfterTheRouteIsApplied()
    {
        var sink = new RecordingSink();
        _proxy.RouteSink = sink;
        _proxy.Configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.DirectAllowed,
            Direct = Upstream,
            DomainRoutes = [new DomainRoute("corp.example", RouteTarget.Tunnel(Corporate), Upstream)],
        };

        sink.Applied = false;
        Assert.Equal(2, DnsMessage.GetRcode(await Ask(CorporateName)));

        sink.Applied = true;
        var ok = await Ask(CorporateName);

        Assert.Equal(0, DnsMessage.GetRcode(ok));
        Assert.Equal("corp.example", sink.Last!.Suffix);
        Assert.Equal(RouteTarget.Tunnel(Corporate), sink.Last.Target);
    }

    private async Task<byte[]> Ask(string name)
    {
        var response = await _proxy.HandleAsync(DnsMessage.BuildQuery(0x4242, name, DnsMessage.TypeA), CancellationToken.None);
        return response!;
    }

    [Fact]
    public async Task ExpiredBootstrapPin_ReturnsToDomainRouting()
    {
        var sink = new RecordingSink();
        _proxy.RouteSink = sink;
        _proxy.Configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.DirectAllowed,
            Direct = Upstream,
            DomainRoutes = [new DomainRoute("crl.example", RouteTarget.Direct, Upstream)],
        };
        _cache.Pin("crl.example", [Ipv4.Parse("203.0.113.1")], TimeSpan.FromMinutes(1));
        await Ask("crl.example");
        Assert.Null(sink.Last);
        Assert.Equal(0, _upstream.Received);

        _time.Advance(TimeSpan.FromMinutes(1));
        await Ask("crl.example");

        Assert.Equal(1, _upstream.Received);
        Assert.Equal("crl.example", sink.Last!.Suffix);
    }

    private sealed class RecordingSink : IPinnedRouteSink
    {
        public bool Applied { get; set; } = true;

        public PinnedRouteNotice? Last { get; private set; }

        public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
        {
            Last = notice;
            return ValueTask.FromResult(Applied);
        }
    }

    /// <summary>Локальный DNS-сервер на loopback: считает запросы и отвечает по заданным правилам.</summary>
    private sealed class FakeUpstream : IAsyncDisposable
    {
        private readonly Socket _socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;
        private int _received;

        public FakeUpstream()
        {
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            EndPoint = (IPEndPoint)_socket.LocalEndPoint!;
            _loop = Task.Run(() => LoopAsync(_stop.Token));
        }

        public IPEndPoint EndPoint { get; }

        public string Context => ":" + EndPoint;

        public uint Ttl { get; set; } = 300;

        public TimeSpan Delay { get; set; }

        /// <summary>Отвечать на другое имя: проверка того, что посредник сверяет ответ с вопросом.</summary>
        public string? AnswerAs { get; set; }

        public int Received => Volatile.Read(ref _received);

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _socket.Dispose();
            await _loop.ContinueWith(_ => { }, TaskScheduler.Default);
            _stop.Dispose();
        }

        private async Task LoopAsync(CancellationToken token)
        {
            var buffer = new byte[4096];
            while (!token.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await _socket.ReceiveFromAsync(buffer, new IPEndPoint(IPAddress.Any, 0), token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }

                Interlocked.Increment(ref _received);
                var query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
                if (Delay > TimeSpan.Zero)
                {
                    await Task.Delay(Delay, token);
                }

                var answered = AnswerAs is { } name
                    ? DnsMessage.BuildAddressResponse(DnsMessage.BuildQuery(DnsMessage.GetId(query), name, DnsMessage.TypeA), [Ipv4.Parse("198.51.100.1")], Ttl)
                    : DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("203.0.113.9")], Ttl);
                try
                {
                    await _socket.SendToAsync(answered, received.RemoteEndPoint, token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }
            }
        }
    }
}
