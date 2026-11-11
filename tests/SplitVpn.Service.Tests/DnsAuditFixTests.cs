using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Исправления аудита 2026-11-01 в DNS-посреднике: CNAME-связи, AAAA и Block под правилом, полный ключ
/// кеша, смена политики во время закрепления, идентификатор ответа по TCP и устойчивый приём TCP.
/// </summary>
public sealed class DnsAuditFixTests : IAsyncDisposable
{
    private static readonly Guid Corporate = new("dddddddd-0000-0000-0000-000000000004");

    private readonly ScriptedUpstream _rule = new();
    private readonly ScriptedUpstream _general = new();
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UnixEpoch);
    private readonly DnsCache _cache;
    private readonly DnsProxyServer _proxy;

    public DnsAuditFixTests()
    {
        _cache = new DnsCache(_time);
        _proxy = new DnsProxyServer(IPAddress.Loopback, _cache);
    }

    public async ValueTask DisposeAsync()
    {
        await _proxy.DisposeAsync();
        await _rule.DisposeAsync();
        await _general.DisposeAsync();
    }

    private DnsProxyConfiguration RuleConfiguration(RouteTarget target) => new()
    {
        Mode = DnsProxyMode.DirectAllowed,
        Direct = new DnsRoute([_general.EndPoint], null),
        DomainRoutes = [new DomainRoute("alias.example", target, new DnsRoute([_rule.EndPoint], null))],
    };

    private async Task<byte[]> Ask(string name, ushort type = DnsMessage.TypeA) =>
        (await _proxy.HandleAsync(DnsMessage.BuildQuery(0x4242, name, type), CancellationToken.None))!;

    [Fact]
    public async Task CnameOnlyAnswer_CanonicalNameInheritsTheRule()
    {
        var sink = new RecordingSink();
        _proxy.RouteSink = sink;
        _proxy.Configuration = RuleConfiguration(RouteTarget.Tunnel(Corporate));
        _rule.Respond = query => DnsMessage.TryReadQuestion(query, out var q) && q.Name == "www.alias.example"
            ? Response(query, 0, [Cname("www.alias.example", "cdn.other.net", 300)])
            : DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("203.0.113.7")], 300);

        var alias = await Ask("www.alias.example");
        Assert.Equal(0, DnsMessage.GetRcode(alias));
        Assert.Null(sink.Last);

        var canonical = await Ask("cdn.other.net");

        Assert.Equal(0, DnsMessage.GetRcode(canonical));
        Assert.Equal(0, _general.Received);
        Assert.Equal("alias.example", sink.Last!.Suffix);
        Assert.Equal(RouteTarget.Tunnel(Corporate), sink.Last.Target);
        Assert.Equal([Ipv4.Parse("203.0.113.7")], sink.Last.Addresses);

        // Связь живёт не дольше TTL: после него каноническое имя снова идёт общим путём.
        _time.Advance(TimeSpan.FromHours(2));
        await Ask("cdn.other.net");
        Assert.Equal(1, _general.Received);
    }

    /// <summary>Имена с правилами «VPN» и «Напрямую» ведут к одному каноническому имени: оно наследует VPN в любом порядке.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConflictingCnameAliases_RejectSecondAndPreserveIssuedTarget(bool vpnFirst)
    {
        var sink = new RecordingSink();
        _proxy.RouteSink = sink;
        _proxy.Configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.DirectAllowed,
            Direct = new DnsRoute([_general.EndPoint], null),
            DomainRoutes =
            [
                new DomainRoute("vpn.example", RouteTarget.Tunnel(Corporate), new DnsRoute([_rule.EndPoint], null)),
                new DomainRoute("direct.example", RouteTarget.Direct, new DnsRoute([_general.EndPoint], null)),
            ],
        };
        Func<byte[], byte[]> respond = query => DnsMessage.TryReadQuestion(query, out var q) && q.Name != "cdn.shared.net"
            ? Response(query, 0, [Cname(q.Name, "cdn.shared.net", 300)])
            : DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("203.0.113.9")], 300);
        _rule.Respond = respond;
        _general.Respond = respond;

        Assert.Equal(0, DnsMessage.GetRcode(await Ask(vpnFirst ? "www.vpn.example" : "www.direct.example")));
        Assert.Equal(2, DnsMessage.GetRcode(await Ask(vpnFirst ? "www.direct.example" : "www.vpn.example")));

        await Ask("cdn.shared.net");

        Assert.Equal(vpnFirst ? "vpn.example" : "direct.example", sink.Last!.Suffix);
        Assert.Equal(vpnFirst ? RouteTarget.Tunnel(Corporate) : RouteTarget.Direct, sink.Last.Target);
    }

    [Fact]
    public async Task AaaaUnderPinnedRule_GetsEmptyAnswerWithoutUpstream()
    {
        _proxy.Configuration = RuleConfiguration(RouteTarget.Tunnel(Corporate));

        var ruled = await Ask("www.alias.example", DnsMessage.TypeAaaa);
        Assert.Equal(0, DnsMessage.GetRcode(ruled));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(ruled.AsSpan(6)));
        Assert.Equal(0, _rule.Received);

        // Имя без правила получает настоящий ответ.
        await Ask("site.example", DnsMessage.TypeAaaa);
        Assert.Equal(1, _general.Received);
    }

    [Fact]
    public async Task BlockedName_IsRefusedNotNxDomain()
    {
        _proxy.Configuration = RuleConfiguration(RouteTarget.Blocked);

        var response = await Ask("www.alias.example");

        Assert.Equal(DnsProxyServer.RcodeRefused, DnsMessage.GetRcode(response));
        Assert.Equal(0, _rule.Received);
    }

    [Fact]
    public async Task QueriesWithDifferentEdnsOptions_DoNotShareCache()
    {
        _proxy.Configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed, Direct = new DnsRoute([_general.EndPoint], null) };
        var plain = DnsMessage.BuildQuery(1, "cdn.example", DnsMessage.TypeA);
        var subnetA = WithOption(plain, [0x00, 0x01, 0x18, 0x00, 192, 0, 2]);
        var subnetB = WithOption(plain, [0x00, 0x01, 0x18, 0x00, 198, 51, 100]);

        await _proxy.HandleAsync(subnetA, CancellationToken.None);
        await _proxy.HandleAsync(subnetA, CancellationToken.None);
        Assert.Equal(1, _general.Received);

        await _proxy.HandleAsync(subnetB, CancellationToken.None);
        Assert.Equal(2, _general.Received);

        // Запрос без рекурсии (RD = 0) не получает ответ рекурсивного.
        await _proxy.HandleAsync(plain, CancellationToken.None);
        var noRecursion = plain.ToArray();
        noRecursion[2] &= 0xFE;
        await _proxy.HandleAsync(noRecursion, CancellationToken.None);
        Assert.Equal(4, _general.Received);

        DnsMessage.TryReadQuestion(plain, out var question);
        var keys = new[] { plain, noRecursion, subnetA, subnetB }
            .Select(q => DnsProxyServer.InFlightKey(DnsMessage.ReadQueryFlags(q), question, "ctx")).ToList();
        Assert.Equal(4, keys.Distinct().Count());
    }

    [Fact]
    public async Task RuleChangedWhileRouteWasApplied_AnswerIsWithheld()
    {
        var replaced = RuleConfiguration(RouteTarget.Direct);
        _proxy.RouteSink = new RecordingSink { During = () => _proxy.Configuration = replaced };
        _proxy.Configuration = RuleConfiguration(RouteTarget.Tunnel(Corporate));
        _rule.Respond = query => DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("203.0.113.7")], 300);

        var response = await Ask("www.alias.example");

        Assert.Equal(2, DnsMessage.GetRcode(response));
        Assert.Empty(DnsMessage.ReadAddresses(response));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TcpAnswerWithForeignId_IsRejected(bool foreignId)
    {
        _rule.Truncate = true;
        _rule.TcpIdOffset = foreignId ? (ushort)1 : (ushort)0;
        var query = DnsMessage.BuildQuery(0x1234, "big.example", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [_rule.EndPoint], null, TimeSpan.FromSeconds(2), CancellationToken.None);

        Assert.NotNull(response);
        Assert.Equal(0x1234, DnsMessage.GetId(response));

        // Чужой ответ по TCP отброшен: остаётся усечённый ответ UDP без адресов.
        Assert.Equal(foreignId, DnsMessage.IsTruncated(response));
        Assert.Equal(foreignId ? 0 : 1, DnsMessage.ReadAddresses(response).Count);
    }

    [Fact]
    public async Task TcpAcceptError_DoesNotStopTcpListener()
    {
        var calls = 0;
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, _cache)
        {
            AcceptTcp = (listener, token) => Interlocked.Increment(ref calls) == 1
                ? ValueTask.FromException<TcpClient>(new SocketException((int)SocketError.ConnectionReset))
                : listener.AcceptTcpClientAsync(token),
        };
        _cache.Pin("pinned.example", [Ipv4.Parse("203.0.113.5")]);
        proxy.Start(0);

        using var client = new TcpClient();
        await client.ConnectAsync(proxy.ListenEndPoint!, TestContext.Current.CancellationToken);
        var stream = client.GetStream();
        var query = DnsMessage.BuildQuery(7, "pinned.example", DnsMessage.TypeA);
        var framed = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed, 2);
        await stream.WriteAsync(framed, TestContext.Current.CancellationToken);
        var header = new byte[2];
        await stream.ReadExactlyAsync(header, TestContext.Current.CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var response = new byte[BinaryPrimitives.ReadUInt16BigEndian(header)];
        await stream.ReadExactlyAsync(response, TestContext.Current.CancellationToken);

        Assert.True(calls >= 2);
        Assert.Equal([Ipv4.Parse("203.0.113.5")], DnsMessage.ReadAddresses(response));
    }

    /// <summary>Запрос с записью OPT, несущей заданные опции (например, Client Subnet).</summary>
    private static byte[] WithOption(byte[] query, byte[] option)
    {
        var data = new byte[4 + option.Length];
        BinaryPrimitives.WriteUInt16BigEndian(data, 8); // EDNS Client Subnet
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2), (ushort)option.Length);
        option.CopyTo(data, 4);
        var result = new byte[query.Length + 11 + data.Length];
        query.CopyTo(result, 0);
        result[11] = 1; // ARCOUNT
        var offset = query.Length;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 1), DnsMessage.TypeOpt);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 3), 1232);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 9), (ushort)data.Length);
        data.CopyTo(result, offset + 11);
        return result;
    }

    internal static byte[] EncodeName(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }

        bytes.Add(0);
        return [.. bytes];
    }

    internal static byte[] Cname(string owner, string target, uint ttl) => Record(owner, DnsMessage.TypeCname, ttl, EncodeName(target));

    internal static byte[] Record(string owner, ushort type, uint ttl, byte[] data)
    {
        var name = EncodeName(owner);
        var record = new byte[name.Length + 10 + data.Length];
        name.CopyTo(record, 0);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(name.Length), type);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(name.Length + 2), DnsMessage.ClassIn);
        BinaryPrimitives.WriteUInt32BigEndian(record.AsSpan(name.Length + 4), ttl);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(name.Length + 8), (ushort)data.Length);
        data.CopyTo(record, name.Length + 10);
        return record;
    }

    /// <summary>Ответ на запрос с заданными записями секции ответа.</summary>
    internal static byte[] Response(byte[] query, int rcode, IReadOnlyList<byte[]> answers)
    {
        var head = DnsMessage.BuildEmptyResponse(query, rcode);
        BinaryPrimitives.WriteUInt16BigEndian(head.AsSpan(6), (ushort)answers.Count);
        return [.. head, .. answers.SelectMany(a => a)];
    }

    private sealed class RecordingSink : IPinnedRouteSink
    {
        public PinnedRouteNotice? Last { get; private set; }

        /// <summary>Что происходит, пока ответ ждёт применения маршрута.</summary>
        public Action? During { get; init; }

        public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
        {
            Last = notice;
            During?.Invoke();
            return ValueTask.FromResult(true);
        }
    }

    /// <summary>Upstream на loopback: UDP и TCP на одном порту, ответ задаётся тестом.</summary>
    private sealed class ScriptedUpstream : IAsyncDisposable
    {
        private readonly Socket _udp;
        private readonly TcpListener _tcp;
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _udpLoop;
        private readonly Task _tcpLoop;
        private int _received;

        public ScriptedUpstream()
        {
            // Свободный TCP-порт не гарантирует свободный UDP с тем же номером (занят или в исключённом
            // диапазоне Windows): пробуем несколько портов.
            for (var attempt = 0; ; attempt++)
            {
                var tcp = new TcpListener(IPAddress.Loopback, 0);
                tcp.Start();
                var endPoint = (IPEndPoint)tcp.LocalEndpoint;
                var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                try
                {
                    udp.Bind(endPoint);
                    _tcp = tcp;
                    _udp = udp;
                    EndPoint = endPoint;
                    break;
                }
                catch (SocketException) when (attempt < 20)
                {
                    udp.Dispose();
                    tcp.Stop();
                    tcp.Dispose();
                }
            }

            _udpLoop = Task.Run(() => UdpLoopAsync(_stop.Token));
            _tcpLoop = Task.Run(() => TcpLoopAsync(_stop.Token));
        }

        public IPEndPoint EndPoint { get; }

        public Func<byte[], byte[]> Respond { get; set; } = query => DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("203.0.113.9")], 300);

        /// <summary>По UDP — только усечённый ответ (TC): клиент обязан повторить по TCP.</summary>
        public bool Truncate { get; set; }

        /// <summary>Сдвиг идентификатора ответа по TCP: ненулевой — ответ «чужой».</summary>
        public ushort TcpIdOffset { get; set; }

        public int Received => Volatile.Read(ref _received);

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _udp.Dispose();
            _tcp.Stop();
            await Task.WhenAll(_udpLoop, _tcpLoop).ContinueWith(_ => { }, TaskScheduler.Default);
            _stop.Dispose();
        }

        private async Task UdpLoopAsync(CancellationToken token)
        {
            var buffer = new byte[4096];
            while (!token.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await _udp.ReceiveFromAsync(buffer, new IPEndPoint(IPAddress.Any, 0), token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }

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
                    answer = Respond(query);
                }

                try
                {
                    await _udp.SendToAsync(answer, received.RemoteEndPoint, token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }
            }
        }

        private async Task TcpLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    using var client = await _tcp.AcceptTcpClientAsync(token);
                    var stream = client.GetStream();
                    var header = new byte[2];
                    await stream.ReadExactlyAsync(header, token);
                    var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(header)];
                    await stream.ReadExactlyAsync(query, token);
                    var answer = Respond(query);
                    DnsMessage.SetId(answer, (ushort)(DnsMessage.GetId(query) + TcpIdOffset));
                    var framed = new byte[answer.Length + 2];
                    BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)answer.Length);
                    answer.CopyTo(framed, 2);
                    await stream.WriteAsync(framed, token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException or IOException)
                {
                    if (token.IsCancellationRequested)
                    {
                        return;
                    }
                }
            }
        }
    }
}
