using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed class DnsShutdownTests
{
    [Fact]
    public async Task RepeatedStartStop_ReleasesBothListeningPorts()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        for (var i = 0; i < 25; i++)
        {
            await using var proxy = new DnsProxyServer(IPAddress.Loopback, new DnsCache(TimeProvider.System));
            proxy.Start(0);
            var endpoint = proxy.ListenEndPoint!;
            while (!proxy.TcpListening)
            {
                await Task.Delay(10, timeout.Token);
            }

            Assert.Throws<InvalidOperationException>(() => proxy.Start(0));
            await proxy.DisposeAsync();
            // Повторный Dispose безопасен; оба порта доступны до сборки мусора.
            await proxy.DisposeAsync();
            Assert.Throws<ObjectDisposedException>(() => proxy.Start(0));
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
            using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
            udp.Bind(endpoint);
            tcp.Bind(endpoint);
            tcp.Listen(1);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Dispose_WaitsForAcceptedRequests(bool tcp)
    {
        var cache = new DnsCache(TimeProvider.System);
        var query = DnsMessage.BuildQuery(1, "shutdown.example", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, "", DnsMessage.BuildAddressResponse(query, [0xCB007109u], 60));
        var sink = new WaitingSink();
        var proxy = new DnsProxyServer(IPAddress.Loopback, cache)
        {
            RouteSink = sink,
            Configuration = new DnsProxyConfiguration
            {
                DomainRoutes = [new("shutdown.example", RouteTarget.Direct, null)],
            },
        };
        Task? dispose = null;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var client = new Socket(AddressFamily.InterNetwork, tcp ? SocketType.Stream : SocketType.Dgram,
            tcp ? ProtocolType.Tcp : ProtocolType.Udp);
        try
        {
            proxy.Start(0);
            if (tcp)
            {
                while (!proxy.TcpListening)
                {
                    await Task.Delay(10, timeout.Token);
                }

                await client.ConnectAsync(proxy.ListenEndPoint!, timeout.Token);
                await using var stream = new NetworkStream(client, ownsSocket: false);
                var framed = new byte[query.Length + 2];
                BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
                query.CopyTo(framed, 2);
                await stream.WriteAsync(framed, timeout.Token);
            }
            else
            {
                await client.SendToAsync(query, proxy.ListenEndPoint!, timeout.Token);
            }

            await sink.Entered.Task.WaitAsync(timeout.Token);
            dispose = proxy.DisposeAsync().AsTask();
            var wait = Task.Delay(100, timeout.Token);
            Assert.Same(wait, await Task.WhenAny(dispose, wait));
        }
        finally
        {
            sink.Finish.TrySetResult();
            await (dispose ?? proxy.DisposeAsync().AsTask()).WaitAsync(timeout.Token);
        }

        Assert.True(sink.Completed);
    }

    private sealed class WaitingSink : IPinnedRouteSink
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Finish { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Completed { get; private set; }

        public async ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await Finish.Task;
            Completed = true;
            cancellationToken.ThrowIfCancellationRequested();
            return true;
        }
    }
}
