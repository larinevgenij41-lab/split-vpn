using System.Net;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Dns;
using Microsoft.Extensions.Time.Testing;

namespace SplitVpn.Core.Tests;

public sealed class ReviewNov11CoreTests
{
    [Fact]
    public void CanonicalReservationRejectsConflictBeforeFirstResponseCompletes()
    {
        var cache = new DnsCache(new FakeTimeProvider());
        var first = Guid.NewGuid();
        Assert.True(cache.TryReserveCanonicalLinks(["cdn.net"], "first.example", TimeSpan.FromMinutes(5), first, _ => true));
        Assert.Null(cache.TryGetCanonicalLink("cdn.net"));
        Assert.False(cache.TryReserveCanonicalLinks(["cdn.net", "new.net"], "second.example", TimeSpan.FromMinutes(5), Guid.NewGuid(), _ => false));
        Assert.Null(cache.TryGetCanonicalLink("new.net"));
        cache.CompleteCanonicalLinks(first, true);
        Assert.Equal("first.example", cache.TryGetCanonicalLink("cdn.net"));
    }

    [Fact]
    public void CanonicalChainCapacityIsAtomicAndCancellationFreesIt()
    {
        var cache = new DnsCache(new FakeTimeProvider(), capacity: 1);
        Assert.False(cache.TryReserveCanonicalLinks(["a.net", "b.net"], "first.example", TimeSpan.FromMinutes(5), Guid.NewGuid(), _ => true));
        Assert.Null(cache.TryGetCanonicalLink("a.net"));
        var lease = Guid.NewGuid();
        Assert.True(cache.TryReserveCanonicalLinks(["a.net"], "first.example", TimeSpan.FromMinutes(5), lease, _ => true));
        cache.CompleteCanonicalLinks(lease, false);
        Assert.True(cache.LinkCanonical("b.net", "second.example", TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void CanonicalRejectedRefreshPreservesOnlyPreviouslyAcceptedLifetime()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        cache.LinkCanonical("cdn.net", "first.example", TimeSpan.FromSeconds(10));
        var lease = Guid.NewGuid();
        Assert.True(cache.TryReserveCanonicalLinks(["cdn.net"], "first.example", TimeSpan.FromMinutes(5), lease, _ => true));
        cache.CompleteCanonicalLinks(lease, false);
        Assert.Equal("first.example", cache.TryGetCanonicalLink("cdn.net"));
        time.Advance(TimeSpan.FromSeconds(11));
        Assert.Null(cache.TryGetCanonicalLink("cdn.net"));
    }

    [Fact]
    public void CanonicalSameTargetOwnersKeepIndependentAcceptedLifetimes()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        cache.LinkCanonical("cdn.net", "first.example", TimeSpan.FromSeconds(10));
        var second = Guid.NewGuid();
        Assert.True(cache.TryReserveCanonicalLinks(["cdn.net"], "second.example", TimeSpan.FromMinutes(5), second, _ => true));
        cache.CompleteCanonicalLinks(second, true);
        time.Advance(TimeSpan.FromSeconds(11));
        Assert.Equal("second.example", cache.TryGetCanonicalLink("cdn.net"));
    }

    [Fact]
    public async Task ForbiddenCustomSourceMustTryIndependentMirror()
    {
        var mirror = new Uri("https://mirror.example/list");
        using var handler = new Handler(r => new HttpResponseMessage(r.RequestUri == mirror ? HttpStatusCode.OK : HttpStatusCode.Forbidden) { Content = new StringContent("77.88.0.0/18") });
        using var client = new HttpClient(handler);
        var result = await new GeoDownloader(client).FetchAsync(new CustomUrlSource(new Uri("https://primary.example/list"), [mirror]), null, TestContext.Current.CancellationToken);
        Assert.Equal(GeoFetchStatus.Downloaded, result.Status);
    }

    [Fact]
    public void ProxyRestoreMustPreserveUserAutoDetectChange()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        try
        {
            var settings = new Proxy();
            var applier = new ProxyApplier(settings, path);
            applier.Sync("https://vpn.example/pac");
            settings.State = settings.State with { Flags = settings.State.Flags | 8 };
            applier.Sync(null);
            Assert.NotEqual(0, settings.State.Flags & 8);
        }
        finally { File.Delete(path); }
    }
    private sealed class Proxy : IProxySettings
    {
        public ProxyState State = new(1, null);
        public ProxyState Read() => State;
        public void Write(ProxyState state) => State = state;
    }
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => Task.FromResult(respond(request));
    }
}
