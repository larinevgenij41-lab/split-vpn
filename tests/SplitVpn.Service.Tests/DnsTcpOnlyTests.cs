using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Dns;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>«VPN поверх SSH»: путь не переносит UDP, поэтому DNS через него идёт сразу по TCP.</summary>
public sealed class DnsTcpOnlyTests
{
    [Fact]
    public async Task TcpOnly_AnswersOverTcp_WithoutTouchingUdp()
    {
        await using var upstream = new TcpAndUdpUpstream();
        var query = DnsMessage.BuildQuery(0x4242, "example.org", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [upstream.EndPoint], null, TimeSpan.FromSeconds(2), tcpOnly: true, CancellationToken.None);

        Assert.NotNull(response);
        Assert.Equal(0x4242, DnsMessage.GetId(response));
        Assert.Single(DnsMessage.ReadAddresses(response));
        Assert.Equal(1, upstream.TcpQueries);
        Assert.Equal(0, upstream.UdpQueries);
    }

    /// <summary>Прежнее поведение: UDP молчит - на TCP пересылка сама не переходит, ответа нет. Поэтому нужен отдельный режим.</summary>
    [Fact]
    public async Task Default_DoesNotFallBackToTcp_WhenUdpIsSilent()
    {
        await using var upstream = new TcpAndUdpUpstream();
        var query = DnsMessage.BuildQuery(1, "example.org", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [upstream.EndPoint], null, TimeSpan.FromMilliseconds(300), CancellationToken.None);

        Assert.Null(response);
        Assert.Equal(1, upstream.UdpQueries);
        Assert.Equal(0, upstream.TcpQueries);
    }

    [Fact]
    public async Task TcpOnly_TriesNextServer_WhenFirstRefusesConnection()
    {
        await using var upstream = new TcpAndUdpUpstream();
        using var closed = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        closed.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var dead = (IPEndPoint)closed.LocalEndPoint!;
        var query = DnsMessage.BuildQuery(7, "example.org", DnsMessage.TypeA);

        var response = await DnsForwarder.ForwardAsync(query, [dead, upstream.EndPoint], null, TimeSpan.FromSeconds(2), tcpOnly: true, CancellationToken.None);

        Assert.NotNull(response);
        Assert.Equal(1, upstream.TcpQueries);
    }

    [Fact]
    public void Route_TcpOnlyHasLongerTimeout_AndDiffersFromPlainRoute()
    {
        var servers = new[] { new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53) };
        var plain = new DnsRoute(servers, 7);
        var tcp = new DnsRoute(servers, 7, TcpOnly: true);

        Assert.False(plain.TcpOnly);
        Assert.NotEqual(plain, tcp);
        Assert.Equal(DnsForwarder.DefaultTimeout, DnsForwarder.TimeoutFor(plain));
        Assert.True(DnsForwarder.TimeoutFor(tcp) > DnsForwarder.DefaultTimeout);
    }

    /// <summary>Сервер на одном порту: по TCP отвечает, по UDP молчит и только считает запросы.</summary>
    private sealed class TcpAndUdpUpstream : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly Socket _udp = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _tcpLoop;
        private readonly Task _udpLoop;
        private int _tcpQueries;
        private int _udpQueries;

        public TcpAndUdpUpstream()
        {
            _listener.Start();
            EndPoint = (IPEndPoint)_listener.LocalEndpoint;
            _udp.Bind(new IPEndPoint(IPAddress.Loopback, EndPoint.Port));
            _tcpLoop = Task.Run(TcpLoopAsync);
            _udpLoop = Task.Run(UdpLoopAsync);
        }

        public IPEndPoint EndPoint { get; }

        public int TcpQueries => Volatile.Read(ref _tcpQueries);

        public int UdpQueries => Volatile.Read(ref _udpQueries);

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _listener.Stop();
            _udp.Dispose();
            await Task.WhenAll(_tcpLoop, _udpLoop).ContinueWith(_ => { }, TaskScheduler.Default);
            _stop.Dispose();
        }

        private async Task TcpLoopAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    var stream = client.GetStream();
                    var header = new byte[2];
                    await stream.ReadExactlyAsync(header, _stop.Token);
                    var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(header)];
                    await stream.ReadExactlyAsync(query, _stop.Token);
                    Interlocked.Increment(ref _tcpQueries);
                    var answer = DnsMessage.BuildAddressResponse(query, [0xC0000201], 60);
                    var framed = new byte[answer.Length + 2];
                    BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)answer.Length);
                    answer.CopyTo(framed, 2);
                    await stream.WriteAsync(framed, _stop.Token);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException or ObjectDisposedException)
            {
                // Остановка теста.
            }
        }

        private async Task UdpLoopAsync()
        {
            var buffer = new byte[4096];
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    await _udp.ReceiveFromAsync(buffer, new IPEndPoint(IPAddress.Any, 0), _stop.Token);
                    Interlocked.Increment(ref _udpQueries);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                // Остановка теста.
            }
        }
    }
}
