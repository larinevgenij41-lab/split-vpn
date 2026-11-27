using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using System.Buffers.Binary;
using System.Net;
using SplitVpn.Core.Geo;

namespace SplitVpn.Core.Tests;

public sealed class ComprehensiveReviewTests
{
    [Fact]
    public void Review_CacheMustNotExtendAdditionalRecordTtl()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        var query = DnsMessage.BuildQuery(1, "example.org", DnsMessage.TypeA);
        var answer = DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("203.0.113.1")], 300);
        var shortAnswer = DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("203.0.113.2")], 5);
        var response = answer.Concat(shortAnswer.TakeLast(16)).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10), 1);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, "route", response);
        var cached = cache.TryGet(question, "route", 1, false)!;
        Assert.Equal(5U, BinaryPrimitives.ReadUInt32BigEndian(cached.AsSpan(answer.Length + 6)));
    }

    [Fact]
    public async Task Review_GeoUnsolicited304MustTryNextMirror()
    {
        var mirror = new Uri("https://mirror.example/list");
        using var handler = new ReviewHttp(request => new HttpResponseMessage(request.RequestUri == mirror
            ? HttpStatusCode.OK : HttpStatusCode.NotModified) { Content = new StringContent("77.88.0.0/18") });
        using var client = new HttpClient(handler);
        var result = await new GeoDownloader(client).FetchAsync(new CustomUrlSource(new Uri("https://primary.example/list"), [mirror]), null, TestContext.Current.CancellationToken);
        Assert.Equal(GeoFetchStatus.Downloaded, result.Status);
        Assert.Equal(mirror, result.Url);
    }

    [Fact]
    public async Task Review_GeoInvalidPrimaryMustTryHealthyMirror()
    {
        var mirror = new Uri("https://mirror.example/list");
        using var handler = new ReviewHttp(request => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(request.RequestUri == mirror ? "77.88.0.0/18" : "<html>Access denied</html>") });
        using var client = new HttpClient(handler);
        var result = await new GeoDownloader(client).FetchAsync(new CustomUrlSource(new Uri("https://primary.example/list"), [mirror]), null, TestContext.Current.CancellationToken);
        Assert.Equal(mirror, result.Url);
    }

    private sealed class ReviewHttp(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(respond(request));
    }

    [Fact]
    public void Review_ProfileGroupCollisionMustNotRedirectExplicitTunnel()
    {
        var first = new ConnectionProfile { Name = "First", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Primary };
        var second = new ConnectionProfile { Name = "Second", Server = "other.example.org", UserName = "user", Role = ProfileRole.Secondary };
        var settings = new AppSettings
        {
            Profiles = [first, second],
            Groups = [new TunnelGroupSetting { Id = first.Id, Name = "Group", Members = [second.Id] }],
            DefaultTarget = RouteTarget.Tunnel(first.Id),
        };
        Assert.Contains(SettingsValidator.Validate(settings).Errors, e => e.Contains("совпадает", StringComparison.Ordinal));
    }

    [Fact]
    public void Review_CanonicalRefreshMustNotShortenOutstandingLease()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        cache.LinkCanonical("cdn.example.net", "private.example.org", TimeSpan.FromSeconds(300));
        time.Advance(TimeSpan.FromSeconds(1));
        cache.LinkCanonical("cdn.example.net", "private.example.org", TimeSpan.FromSeconds(60));
        time.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal("private.example.org", cache.TryGetCanonicalLink("cdn.example.net"));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"size\":1,\"fileName\":\"test.msi\",\"urls\":null}")]
    public void Review_MalformedManifestShouldReturnError(string package)
    {
        var json = "{\"schema\":1,\"product\":\"SplitVpn\",\"version\":\"0.9.0\",\"package\":" + package + "}";
        ManifestParseResult? result = null;
        var exception = Record.Exception(() => result = UpdateManifestParser.Parse(Encoding.UTF8.GetBytes(json)));
        Assert.Null(exception);
        Assert.NotNull(result!.Error);
    }

    [Fact]
    public void Review_PendingProxyMustConvergeToDesiredUrl()
    {
        var root = Path.Combine(Path.GetTempPath(), "splitvpn-review", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "proxy.json");
            const string first = "https://a.example/pac";
            const string pending = "https://b.example/pac";
            File.WriteAllText(path, JsonSerializer.Serialize(new ProxyBackup(new ProxyState(1, null), first, PendingUrl: pending), JsonDefaults.Options));
            var settings = new ReviewProxy { State = new ProxyState(5, pending) };
            new ProxyApplier(settings, path).Sync(first);
            Assert.Equal(first, settings.State.AutoConfigUrl);
        }
        finally { Directory.Delete(root, true); }
    }

    private sealed class ReviewProxy : IProxySettings
    {
        public ProxyState State { get; set; } = new(1, null);
        public ProxyState Read() => State;
        public void Write(ProxyState state) => State = state;
    }
}
