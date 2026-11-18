using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed class ReviewNov11DnsTests
{
    [Fact]
    public async Task AnyQueryMustNotReturnAddressWithoutRouteAcceptance()
    {
        await using var upstream = new Upstream();
        await using var proxy = MakeProxy(new DnsCache(new FakeTimeProvider()), upstream);
        proxy.RouteSink = new Sink(false);
        upstream.Respond = q => DnsAuditFixTests.Response(q, 0, [DnsAuditFixTests.Record("first.example", DnsMessage.TypeA, 300, [203, 0, 113, 7])]);
        var response = await proxy.HandleAsync(DnsMessage.BuildQuery(1, "first.example", 255), TestContext.Current.CancellationToken);
        Assert.Empty(DnsMessage.ReadAddresses(response!));
    }

    [Fact]
    public async Task MoreSpecificLocalSuffixMustOverrideBroadBlock()
    {
        await using var upstream = new Upstream();
        await using var proxy = MakeProxy(new DnsCache(new FakeTimeProvider()), upstream);
        proxy.Configuration = proxy.Configuration with
        {
            Local = new DnsRoute([upstream.EndPoint], null), LocalSuffixes = ["office.first.example"],
            DomainRoutes = [new DomainRoute("first.example", RouteTarget.Blocked, null)]
        };
        var response = await Ask(proxy, "printer.office.first.example");
        Assert.Equal(0, DnsMessage.GetRcode(response));
    }

    [Fact]
    public async Task FullCanonicalTableMustRefuseUntrackedAlias()
    {
        await using var upstream = new Upstream();
        var cache = new DnsCache(new FakeTimeProvider(), capacity: 1);
        cache.LinkCanonical("occupied.net", "first.example", TimeSpan.FromMinutes(5));
        await using var proxy = MakeProxy(cache, upstream);
        upstream.Respond = q => Alias(q, "first.example", "new.net", 300);
        var response = await Ask(proxy, "first.example");
        Assert.Equal(2, DnsMessage.GetRcode(response));
    }

    [Fact]
    public async Task CanonicalSharedByTwoVpnsMustRefuseConflictingAlias()
    {
        await using var upstream = new Upstream();
        var cache = new DnsCache(new FakeTimeProvider());
        await using var proxy = MakeProxy(cache, upstream);
        upstream.Respond = q => { DnsMessage.TryReadQuestion(q, out var question); return Alias(q, question.Name, "shared.net", 300); };
        Assert.Equal(0, DnsMessage.GetRcode(await Ask(proxy, "first.example")));
        var response = await Ask(proxy, "second.example");
        Assert.Equal(2, DnsMessage.GetRcode(response));
    }

    [Fact]
    public async Task SameTargetAliasMustKeepLongerLeaseFromSecondRule()
    {
        await using var upstream = new Upstream();
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        await using var proxy = MakeProxy(cache, upstream);
        var sharedTarget = RouteTarget.Tunnel(Guid.NewGuid());
        proxy.Configuration = proxy.Configuration with { DomainRoutes = proxy.Configuration.DomainRoutes.Select(r => r with { Target = sharedTarget }).ToList() };
        upstream.Respond = q => { DnsMessage.TryReadQuestion(q, out var question); return Alias(q, question.Name, "shared.net", question.Name == "first.example" ? 10U : 300U); };
        await Ask(proxy, "first.example");
        await Ask(proxy, "second.example");
        time.Advance(TimeSpan.FromSeconds(61));
        Assert.NotNull(cache.TryGetCanonicalLink("shared.net"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RefusedAddressResponseMustNotLeaveCanonicalPolicy(bool observed)
    {
        await using var upstream = new Upstream();
        var cache = new DnsCache(new FakeTimeProvider());
        await using var proxy = MakeProxy(cache, upstream);
        proxy.RouteSink = new Sink(observed, false);
        upstream.Respond = q => DnsAuditFixTests.Response(q, 0,
            [DnsAuditFixTests.Cname("first.example", "cdn.net", 300), DnsAuditFixTests.Record("cdn.net", DnsMessage.TypeA, 300, [203, 0, 113, 7])]);
        Assert.Equal(2, DnsMessage.GetRcode(await Ask(proxy, "first.example")));
        Assert.Null(cache.TryGetCanonicalLink("cdn.net"));
    }

    [Fact]
    public async Task TemporaryPinAnswerMustNotOutliveItsLease()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        cache.Pin("gateway.example", [Ipv4.Parse("203.0.113.7")], TimeSpan.FromSeconds(10));
        time.Advance(TimeSpan.FromSeconds(9));
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache);
        var response = await Ask(proxy, "gateway.example");
        Assert.InRange(DnsMessage.GetMinTtl(response)!.Value, 0U, 1U);
    }

    private static DnsProxyServer MakeProxy(DnsCache cache, Upstream upstream) => new(IPAddress.Loopback, cache)
    {
        RouteSink = new Sink(true),
        Configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.DirectAllowed,
            Direct = new DnsRoute([upstream.EndPoint], null),
            DomainRoutes = [new DomainRoute("first.example", RouteTarget.Tunnel(Guid.NewGuid()), new DnsRoute([upstream.EndPoint], null)),
                new DomainRoute("second.example", RouteTarget.Tunnel(Guid.NewGuid()), new DnsRoute([upstream.EndPoint], null))],
        },
    };
    private static Task<byte[]?> Ask(DnsProxyServer proxy, string name) => proxy.HandleAsync(DnsMessage.BuildQuery(1, name, DnsMessage.TypeA), TestContext.Current.CancellationToken);
    private static byte[] Alias(byte[] query, string name, string canonical, uint ttl) => DnsAuditFixTests.Response(query, 0, [DnsAuditFixTests.Cname(name, canonical, ttl)]);
    private sealed class Sink(bool accept, bool commit = true) : IPinnedRouteSink
    {
        public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) => ValueTask.FromResult(accept);
        public ValueTask<bool> CompleteAsync(PinnedRouteNotice notice, bool accepted) => ValueTask.FromResult(accepted && commit);
    }
    private sealed class Upstream : IAsyncDisposable
    {
        private readonly UdpClient _socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _work;
        public Upstream() => _work = RunAsync();
        public IPEndPoint EndPoint => (IPEndPoint)_socket.Client.LocalEndPoint!;
        public Func<byte[], byte[]> Respond { get; set; } = q => DnsMessage.BuildAddressResponse(q, [Ipv4.Parse("203.0.113.7")], 300);
        private async Task RunAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var packet = await _socket.ReceiveAsync(_stop.Token);
                    await _socket.SendAsync(Respond(packet.Buffer), packet.RemoteEndPoint, _stop.Token);
                }
            }
            catch (OperationCanceledException) { }
        }
        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync(); await _work; _socket.Dispose(); _stop.Dispose();
        }
    }
}
