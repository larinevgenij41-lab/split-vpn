using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Ответ под правилом для домена с закреплением: не больше <see cref="DnsProxyServer.MaxPinnedAddressesPerAnswer"/>
/// адресов закрепляется, клиенту уходят только принятые службой адреса, дополнительная секция (адреса целей SRV, MX,
/// NS) не отдаётся, кроме OPT.
/// </summary>
public sealed class DnsPinTrimTests : IAsyncDisposable
{
    private readonly TrimUpstream _upstream = new();
    private readonly DnsProxyServer _proxy;

    public DnsPinTrimTests()
    {
        _proxy = new DnsProxyServer(IPAddress.Loopback, new DnsCache(new FakeTimeProvider(DateTimeOffset.UnixEpoch)));
        _proxy.Configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.DirectAllowed,
            Direct = new DnsRoute([_upstream.EndPoint], null),
            DomainRoutes = [new DomainRoute("alias.example", RouteTarget.Direct, new DnsRoute([_upstream.EndPoint], null))],
        };
    }

    public async ValueTask DisposeAsync()
    {
        await _proxy.DisposeAsync();
        await _upstream.DisposeAsync();
    }

    private static List<uint> Addresses(int count) =>
        Enumerable.Range(0, count).Select(i => Ipv4.Parse("203.0.113.0") + (uint)i + 1).ToList();

    private static ushort Count(byte[] message, int section) => BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(6 + (2 * section)));

    [Fact]
    public async Task LongAnswer_OnlyFirstAddressesArePinnedAndReturned()
    {
        var all = Addresses(40);
        _upstream.Respond = query => DnsMessage.BuildAddressResponse(query, all, 300);
        var sink = new TrimSink();
        _proxy.RouteSink = sink;

        var reply = (await _proxy.HandleAsync(DnsMessage.BuildQuery(7, "www.alias.example", DnsMessage.TypeA), CancellationToken.None))!;

        Assert.Equal(0, DnsMessage.GetRcode(reply));
        Assert.Equal(all.Take(DnsProxyServer.MaxPinnedAddressesPerAnswer), sink.Last!.Addresses);
        Assert.Equal(all.Take(DnsProxyServer.MaxPinnedAddressesPerAnswer), DnsMessage.ReadAddresses(reply, "www.alias.example"));
        Assert.Equal(DnsProxyServer.MaxPinnedAddressesPerAnswer, Count(reply, 0));
    }

    [Fact]
    public async Task PartialAcceptance_ReturnsOnlyAcceptedAddresses()
    {
        var all = Addresses(3);
        _upstream.Respond = query => DnsMessage.BuildAddressResponse(query, all, 300);
        var sink = new TrimSink { Accept = notice => [notice.Addresses[1]] };
        _proxy.RouteSink = sink;

        var reply = (await _proxy.HandleAsync(DnsMessage.BuildQuery(8, "www.alias.example", DnsMessage.TypeA), CancellationToken.None))!;

        Assert.Equal(0, DnsMessage.GetRcode(reply));
        Assert.Equal(new[] { all[1] }, DnsMessage.ReadAddresses(reply, "www.alias.example"));
        Assert.Equal(1, Count(reply, 0));
        Assert.Equal(new[] { all[1] }, sink.Completed.Single(c => c.Accepted).Addresses);
    }

    [Fact]
    public async Task PartialAcceptance_NothingAccepted_IsServerFailure()
    {
        _upstream.Respond = query => DnsMessage.BuildAddressResponse(query, Addresses(2), 300);
        _proxy.RouteSink = new TrimSink { Accept = _ => [] };

        var reply = (await _proxy.HandleAsync(DnsMessage.BuildQuery(9, "www.alias.example", DnsMessage.TypeA), CancellationToken.None))!;

        Assert.Equal(2, DnsMessage.GetRcode(reply));
        Assert.Empty(DnsMessage.ReadAddresses(reply));
    }

    [Fact]
    public async Task SrvAnswer_AdditionalAddressesAreNotReturned_OptIsKept()
    {
        const string service = "_sip._tcp.alias.example";
        _upstream.Respond = query =>
        {
            var empty = DnsMessage.BuildEmptyResponse(query);
            var edns = DnsMessage.ReadEdns(query).Present;
            var head = edns ? empty[..^11] : empty;
            var opt = edns ? empty[^11..] : [];
            byte[] srvData = [0, 10, 0, 5, 0x13, 0xC4, .. DnsAuditFixTests.EncodeName("sip.alias.example")];
            byte[] message =
            [
                .. head,
                .. DnsAuditFixTests.Record(service, 33, 300, srvData),
                .. DnsAuditFixTests.Record("sip.alias.example", DnsMessage.TypeA, 300, [203, 0, 113, 50]),
                .. DnsAuditFixTests.Record("sip.alias.example", DnsMessage.TypeAaaa, 300, new byte[16]),
                .. opt,
            ];
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(6), 1);
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(10), (ushort)(edns ? 3 : 2));
            return message;
        };
        var sink = new TrimSink();
        _proxy.RouteSink = sink;
        var query = DnsMessage.AppendOpt(DnsMessage.BuildQuery(10, service, 33), 1232, dnssecOk: false);

        var reply = (await _proxy.HandleAsync(query, CancellationToken.None))!;

        Assert.Equal(0, DnsMessage.GetRcode(reply));
        Assert.Equal(1, Count(reply, 0));
        Assert.True(DnsMessage.ReadEdns(reply).Present);
        Assert.Equal(1, Count(reply, 2));
        Assert.True(reply.AsSpan().IndexOf(new byte[] { 203, 0, 113, 50 }) < 0);
        Assert.Null(sink.Last);
    }

    private sealed class TrimSink : IPinnedRouteSink
    {
        public PinnedRouteNotice? Last { get; private set; }

        public Func<PinnedRouteNotice, IReadOnlyList<uint>>? Accept { get; init; }

        public List<(IReadOnlyList<uint> Addresses, bool Accepted)> Completed { get; } = [];

        public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
        {
            Last = notice;
            return ValueTask.FromResult(true);
        }

        public ValueTask<IReadOnlyList<uint>?> ObservePartialAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
        {
            Last = notice;
            return ValueTask.FromResult<IReadOnlyList<uint>?>(Accept is { } accept ? accept(notice) : notice.Addresses);
        }

        public ValueTask<bool> CompleteAsync(PinnedRouteNotice notice, bool accepted)
        {
            Completed.Add((notice.Addresses, accepted));
            return ValueTask.FromResult(accepted);
        }
    }

    /// <summary>Upstream DNS на loopback, отвечающий по <see cref="Respond"/>; им пользуются и тесты моста к координатору.</summary>
    internal sealed class TrimUpstream : IAsyncDisposable
    {
        private readonly UdpClient _socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _work;

        public TrimUpstream() => _work = RunAsync();

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
