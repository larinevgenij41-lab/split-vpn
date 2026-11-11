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
