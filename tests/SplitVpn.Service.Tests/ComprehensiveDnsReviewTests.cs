using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed class ComprehensiveDnsReviewTests
{
    [Fact]
    public async Task CnameOnlyResponseFromOldPolicyIsRefused()
    {
        await using var server = new ReviewUpstream();
        var cache = new DnsCache(new FakeTimeProvider());
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache) { RouteSink = new Sink() };
        proxy.Configuration = Config(server);
        server.Respond = query =>
        {
            proxy.Configuration = Config(server) with { DomainRoutes = [new DomainRoute("alias.example", RouteTarget.Blocked, null)] };
            return DnsAuditFixTests.Response(query, 0, [DnsAuditFixTests.Cname("alias.example", "cdn.example.net", 300)]);
        };
        var response = await proxy.HandleAsync(DnsMessage.BuildQuery(1, "alias.example", DnsMessage.TypeA), TestContext.Current.CancellationToken);
        Assert.Equal(2, DnsMessage.GetRcode(response));
        Assert.Null(cache.TryGetCanonicalLink("cdn.example.net"));
    }

    [Fact]
    public async Task Review_CnameOnlyTtlMustNotOutliveCanonicalLink()
    {
        await using var server = new ReviewUpstream();
        var cache = new DnsCache(new FakeTimeProvider());
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache) { RouteSink = new Sink() };
        proxy.Configuration = Config(server);
        server.Respond = q => DnsAuditFixTests.Response(q, 0, [DnsAuditFixTests.Cname("alias.example", "cdn.example.net", 86400)]);
        var response = await proxy.HandleAsync(DnsMessage.BuildQuery(1, "alias.example", DnsMessage.TypeA), TestContext.Current.CancellationToken);
        Assert.True(DnsMessage.GetMinTtl(response) <= DnsProxyServer.MaxRouteTtl.TotalSeconds);
    }

    [Fact]
    public async Task Review_NewNetworkGenerationMustNotJoinOldDnsQuery()
    {
        await using var server = new ReviewUpstream();
        var cache = new DnsCache(new FakeTimeProvider());
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache) { RouteSink = new Sink() };
        proxy.Configuration = Config(server);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        server.Gate = gate.Task;
        var query = DnsMessage.BuildQuery(1, "alias.example", DnsMessage.TypeA);
        var old = proxy.HandleAsync(query, TestContext.Current.CancellationToken);
        await server.ReceivedFirst.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        proxy.Configuration = Config(server);
        cache.Clear();
        var current = proxy.HandleAsync(query, TestContext.Current.CancellationToken);
        gate.SetResult();
        await Task.WhenAll(old, current);
        Assert.Equal(2, server.Received);
    }

    [Fact]
    public async Task Review_UnrelatedConfigurationChangeMustKeepLiveCnamePolicy()
    {
        await using var server = new ReviewUpstream();
        await using var general = new ReviewUpstream();
        var cache = new DnsCache(new FakeTimeProvider());
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache) { RouteSink = new Sink() };
        proxy.Configuration = Config(server) with { Direct = new DnsRoute([general.EndPoint], null) };
        server.Respond = q => DnsAuditFixTests.Response(q, 0, [DnsAuditFixTests.Cname("alias.example", "cdn.example.net", 300)]);
        await proxy.HandleAsync(DnsMessage.BuildQuery(1, "alias.example", DnsMessage.TypeA), TestContext.Current.CancellationToken);
        proxy.Configuration = proxy.Configuration with { LocalSuffixes = ["new.lan"] };
        cache.Clear();
        await proxy.HandleAsync(DnsMessage.BuildQuery(2, "cdn.example.net", DnsMessage.TypeA), TestContext.Current.CancellationToken);
        Assert.Equal(0, general.Received);
    }

    /// <summary>
    /// Путь DNS, который не отвечает (зависший туннель), держит каждый запрос до тайм-аута. Он не должен занять
    /// посредник целиком: лишний запрос к нему получает отказ сразу, а имена других путей разрешаются как обычно.
    /// </summary>
    [Fact]
    public async Task StalledRouteDoesNotStarveOtherNames()
    {
        await using var stalled = new ReviewUpstream { Gate = new TaskCompletionSource().Task };
        await using var general = new ReviewUpstream();
        var cache = new DnsCache(new FakeTimeProvider());
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache) { RouteSink = new Sink() };
        proxy.Configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.DirectAllowed,
            Direct = new DnsRoute([general.EndPoint], null),
            DomainRoutes = [new DomainRoute("slow.example", RouteTarget.Direct, new DnsRoute([stalled.EndPoint], null))],
        };
        var token = TestContext.Current.CancellationToken;
        var waiting = Enumerable.Range(0, DnsProxyServer.MaxQueriesPerRoute)
            .Select(i => proxy.HandleAsync(DnsMessage.BuildQuery((ushort)(i + 1), $"h{i}.slow.example", DnsMessage.TypeA), token))
            .ToList();
        await stalled.ReceivedFirst.Task.WaitAsync(TimeSpan.FromSeconds(2), token);

        var extra = await proxy.HandleAsync(DnsMessage.BuildQuery(900, "extra.slow.example", DnsMessage.TypeA), token);
        var other = await proxy.HandleAsync(DnsMessage.BuildQuery(901, "fast.example.org", DnsMessage.TypeA), token);
        // Вместо замера времени - порядок: запросы к зависшему пути держатся до своего тайм-аута, и пока ни один из них
        // не завершился, ответы выше пришли без ожидания зависшего пути (освободившееся место им не понадобилось).
        var pendingStalled = waiting.Count(t => !t.IsCompleted);

        Assert.Equal(2, DnsMessage.GetRcode(extra));
        Assert.Equal(0, DnsMessage.GetRcode(other));
        Assert.Equal(DnsProxyServer.MaxQueriesPerRoute, pendingStalled);
        Assert.All(await Task.WhenAll(waiting), response => Assert.Equal(2, DnsMessage.GetRcode(response)));
    }

    private static DnsProxyConfiguration Config(ReviewUpstream server) => new()
    {
        Mode = DnsProxyMode.DirectAllowed,
        Direct = new DnsRoute([server.EndPoint], null),
        DomainRoutes = [new DomainRoute("alias.example", RouteTarget.Direct, new DnsRoute([server.EndPoint], null))],
    };

    private sealed class Sink : IPinnedRouteSink
    {
        public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) => ValueTask.FromResult(true);
    }

    private sealed class ReviewUpstream : IAsyncDisposable
    {
        private readonly UdpClient _socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _work;
        public ReviewUpstream() => _work = RunAsync();
        public IPEndPoint EndPoint => (IPEndPoint)_socket.Client.LocalEndPoint!;
        public TaskCompletionSource ReceivedFirst { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Received { get; private set; }
        public Task Gate { get; set; } = Task.CompletedTask;
        public Func<byte[], byte[]> Respond { get; set; } = q => DnsMessage.BuildAddressResponse(q, [Ipv4.Parse("203.0.113.7")], 300);
        private async Task RunAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var packet = await _socket.ReceiveAsync(_stop.Token);
                    Received++;
                    ReceivedFirst.TrySetResult();
                    await Gate.WaitAsync(_stop.Token);
                    await _socket.SendAsync(Respond(packet.Buffer), packet.RemoteEndPoint, _stop.Token);
                }
            }
            catch (OperationCanceledException) { }
        }
        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            await _work;
            _socket.Dispose();
            _stop.Dispose();
        }
    }
}
