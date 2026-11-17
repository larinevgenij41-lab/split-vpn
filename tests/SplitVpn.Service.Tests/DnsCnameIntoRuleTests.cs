using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Ревью 0.15.19: имя без правила, чья CNAME-цепочка ведёт в домен, заблокированный правилом пользователя, получает
/// отказ, в том числе при ответе из кеша. Другие правила (закрепление, недоступный путь, служебные имена) на цепочку
/// не распространяются: ответ пришёл путём самого имени, и его адреса не закрепляются за целью правила. И ответ,
/// полученный до очистки кеша при смене сети, после неё в кеш не попадает.
/// </summary>
public sealed class DnsCnameIntoRuleTests : IAsyncDisposable
{
    private static readonly Guid Office = new("dddddddd-0000-0000-0000-000000000007");
    private static readonly uint Address = Ipv4.Parse("203.0.113.7");

    private readonly Upstream _upstream = new();
    private readonly DnsCache _cache = new(new FakeTimeProvider(DateTimeOffset.UnixEpoch));
    private readonly DnsProxyServer _proxy;

    public DnsCnameIntoRuleTests()
    {
        _proxy = new DnsProxyServer(IPAddress.Loopback, _cache);
    }

    public async ValueTask DisposeAsync()
    {
        await _proxy.DisposeAsync();
        await _upstream.DisposeAsync();
    }

    private DnsRoute Route => new([_upstream.EndPoint], null);

    private DnsProxyConfiguration Config(DomainRoute rule) => new()
    {
        Mode = DnsProxyMode.DirectAllowed,
        Direct = Route,
        DomainRoutes = [rule],
    };

    /// <summary>Ответ upstream: вопрос → CNAME → каноническое имя с A-записью (и её же для AAAA-вопроса).</summary>
    private void AnswerThrough(string canonical) => _upstream.Respond = query =>
    {
        DnsMessage.TryReadQuestion(query, out var question);
        return DnsAuditFixTests.Response(query, 0,
        [
            DnsAuditFixTests.Cname(question.Name, canonical, 300),
            DnsAuditFixTests.Record(canonical, DnsMessage.TypeA, 300, [203, 0, 113, 7]),
        ]);
    };

    private async Task<byte[]> Ask(string name, ushort type = DnsMessage.TypeA) =>
        (await _proxy.HandleAsync(DnsMessage.BuildQuery(0x4242, name, type), TestContext.Current.CancellationToken))!;

    /// <summary>Ответ upstream отдан как есть: успех, CNAME и A-запись канонического имени.</summary>
    private static void AssertUnchanged(byte[] response)
    {
        Assert.Equal(0, DnsMessage.GetRcode(response));
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)));
        Assert.Equal([Address], DnsMessage.ReadAddresses(response, "portal.partner.com"));
    }

    [Fact]
    public async Task UnruledNameWithCnameIntoBlockedSuffix_IsRefusedAlsoFromCache()
    {
        _proxy.Configuration = Config(new DomainRoute("tracker.com", RouteTarget.Blocked, null));
        AnswerThrough("x.tracker.com");

        var first = await Ask("metrics.site.com");
        Assert.Equal(DnsProxyServer.RcodeRefused, DnsMessage.GetRcode(first));
        Assert.Empty(DnsMessage.ReadAddresses(first));

        // Ответ без правила лёг в кеш: повторный запрос из кеша блокировку тоже не обходит.
        var second = await Ask("metrics.site.com");
        Assert.Equal(DnsProxyServer.RcodeRefused, DnsMessage.GetRcode(second));
        Assert.Equal(1, _upstream.Received);
    }

    [Fact]
    public async Task BlockRuleAddedLater_AppliesToCachedAnswer()
    {
        _proxy.Configuration = Config(new DomainRoute("corp.example", RouteTarget.Tunnel(Office), Route));
        AnswerThrough("x.tracker.com");
        Assert.Equal(0, DnsMessage.GetRcode(await Ask("metrics.site.com")));

        // Новая конфигурация с блокировкой: признак "есть правило блокировки" не берётся от прежней.
        _proxy.Configuration = Config(new DomainRoute("tracker.com", RouteTarget.Blocked, null));
        Assert.Equal(DnsProxyServer.RcodeRefused, DnsMessage.GetRcode(await Ask("metrics.site.com")));
        Assert.Equal(1, _upstream.Received);
    }

    /// <summary>
    /// Ответ получен путём самого имени (в режиме "напрямую" - DNS сети, которому нельзя доверять): адреса, на которые
    /// он указывает через CNAME в домен правила, не закрепляются за целью правила, а ответ отдаётся как есть.
    /// </summary>
    [Theory]
    [InlineData(DnsMessage.TypeA)]
    [InlineData(DnsMessage.TypeAaaa)]
    public async Task UnruledNameWithCnameIntoPinnedRule_IsAnsweredUnchangedWithoutPin(ushort type)
    {
        var sink = new Sink();
        _proxy.RouteSink = sink;
        _proxy.Configuration = Config(new DomainRoute("corp.example", RouteTarget.Tunnel(Office), Route));
        AnswerThrough("app.corp.example");

        var response = await Ask("portal.partner.com", type);

        AssertUnchanged(response);
        Assert.Null(sink.Last);
    }

    [Fact]
    public async Task UnruledNameWithCnameIntoUnavailableRule_IsAnsweredUnchanged()
    {
        var sink = new Sink();
        _proxy.RouteSink = sink;
        _proxy.Configuration = Config(new DomainRoute("corp.example", RouteTarget.Tunnel(Office), Route: null, Unavailable: true));
        AnswerThrough("app.corp.example");

        AssertUnchanged(await Ask("portal.partner.com"));
        Assert.Null(sink.Last);
    }

    /// <summary>
    /// Служебные правила (веб-проверка интернета Windows с закреплением в своём контексте, узел проверки отзыва без
    /// пути) через CNAME не действуют: чужой ответ не тратит предел адресов проверки и не получает отказ.
    /// </summary>
    [Theory]
    [InlineData(Coordinator.ConnectivityCheckWebHost, false)]
    [InlineData("ocsp.revocation.example", true)]
    public async Task UnruledNameWithCnameIntoServiceRule_IsAnsweredUnchanged(string host, bool unavailable)
    {
        var sink = new Sink();
        _proxy.RouteSink = sink;
        _proxy.Configuration = Config(new DomainRoute(host, RouteTarget.Direct, unavailable ? null : Route, PinAddresses: true,
            Unavailable: unavailable, ExactName: true, PinContext: unavailable ? null : "1|контекст проверки"));
        AnswerThrough(host);

        AssertUnchanged(await Ask("portal.partner.com"));
        Assert.Null(sink.Last);
    }

    [Fact]
    public async Task UnruledNameWithCnameOutsideRules_IsAnsweredUnchanged()
    {
        var sink = new Sink();
        _proxy.RouteSink = sink;
        _proxy.Configuration = Config(new DomainRoute("corp.example", RouteTarget.Tunnel(Office), Route));
        AnswerThrough("cdn.other.net");

        var response = await Ask("portal.partner.com");

        Assert.Equal(0, DnsMessage.GetRcode(response));
        Assert.Equal([Address], DnsMessage.ReadAddresses(response, "portal.partner.com"));
        Assert.Null(sink.Last);
    }

    /// <summary>
    /// Пользователь добавил правило блокировки, пока ответ upstream был в пути: ответ сверяется и с новой конфигурацией
    /// и получает отказ, хотя запрос начинался по прежней (иначе его закешировала бы Windows после сброса).
    /// </summary>
    [Fact]
    public async Task BlockRuleAddedWhileAnswerInFlight_IsRefused()
    {
        _proxy.Configuration = Config(new DomainRoute("corp.example", RouteTarget.Tunnel(Office), Route));
        var blocked = Config(new DomainRoute("tracker.com", RouteTarget.Blocked, null));
        _upstream.Respond = query =>
        {
            _proxy.Configuration = blocked;
            DnsMessage.TryReadQuestion(query, out var question);
            return DnsAuditFixTests.Response(query, 0,
            [
                DnsAuditFixTests.Cname(question.Name, "x.tracker.com", 300),
                DnsAuditFixTests.Record("x.tracker.com", DnsMessage.TypeA, 300, [203, 0, 113, 7]),
            ]);
        };

        var response = await Ask("metrics.site.com");

        Assert.Equal(DnsProxyServer.RcodeRefused, DnsMessage.GetRcode(response));
        Assert.Empty(DnsMessage.ReadAddresses(response));
        Assert.Equal(1, _upstream.Received);
    }

    /// <summary>
    /// Служба меняет конфигурацию и очищает кеш; ответ, пришедший после очистки, но на запрос, отправленный до неё,
    /// в кеш не кладётся, даже если экземпляр конфигурации тот же (проверка конфигурации прошла до очистки).
    /// </summary>
    [Fact]
    public async Task AnswerForwardedBeforeCacheClear_IsNotCached()
    {
        _proxy.Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = Route };
        _upstream.Respond = query =>
        {
            _cache.Clear();
            return DnsMessage.BuildAddressResponse(query, [Address], 300);
        };

        Assert.Equal(0, DnsMessage.GetRcode(await Ask("site.example")));
        Assert.Equal(0, _cache.Count);

        // Без очистки во время запроса ответ кешируется как обычно.
        _upstream.Respond = query => DnsMessage.BuildAddressResponse(query, [Address], 300);
        await Ask("site.example");
        Assert.Equal(1, _cache.Count);
    }

    private sealed class Sink : IPinnedRouteSink
    {
        public bool Applied { get; init; } = true;

        public PinnedRouteNotice? Last { get; private set; }

        public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
        {
            Last = notice;
            return ValueTask.FromResult(Applied);
        }
    }

    /// <summary>UDP-upstream на loopback: считает запросы, ответ задаёт тест.</summary>
    private sealed class Upstream : IAsyncDisposable
    {
        private readonly UdpClient _socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _work;
        private int _received;

        public Upstream() => _work = RunAsync();

        public IPEndPoint EndPoint => (IPEndPoint)_socket.Client.LocalEndPoint!;

        public int Received => Volatile.Read(ref _received);

        public Func<byte[], byte[]> Respond { get; set; } = q => DnsMessage.BuildAddressResponse(q, [Ipv4.Parse("203.0.113.7")], 300);

        private async Task RunAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var packet = await _socket.ReceiveAsync(_stop.Token);
                    Interlocked.Increment(ref _received);
                    await _socket.SendAsync(Respond(packet.Buffer), packet.RemoteEndPoint, _stop.Token);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
            }
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
