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

    [Fact]
    public async Task TcpTaken_WorksOverUdpFailsLargeAnswersAndTakesTcpLater()
    {
        // Захватчик TCP - сокет самой пробы: порт не отпускается между выбором и захватом.
        var (probeUdp, squatter) = HoldFreePort(IPAddress.Loopback);
        var port = ((IPEndPoint)squatter.LocalEndPoint!).Port;
        probeUdp.Dispose();

        var cache = new DnsCache(TimeProvider.System);
        cache.Pin("small.example", [0xCB007109u]);
        cache.Pin("big.example", Enumerable.Range(1, 100).Select(i => (uint)i).ToList());
        var warnings = new List<string>();
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache) { RetryInterval = TimeSpan.FromMilliseconds(50) };
        proxy.Warning = message =>
        {
            lock (warnings)
            {
                warnings.Add(message);
            }
        };
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            proxy.Start(port);

            Assert.False(proxy.TcpListening);
            Assert.Single(warnings);
            var endpoint = proxy.ListenEndPoint!;
            Assert.Equal([0xCB007109u], DnsMessage.ReadAddresses(await QueryUdpAsync(endpoint, "small.example", timeout.Token)));

            // Усечённый ответ отправил бы повтор по TCP чужому процессу: вместо него отказ.
            var big = await QueryUdpAsync(endpoint, "big.example", timeout.Token);
            Assert.Equal(2, DnsMessage.GetRcode(big));
            Assert.False(DnsMessage.IsTruncated(big));
        }
        finally
        {
            squatter.Dispose();
        }

        while (!proxy.TcpListening)
        {
            await Task.Delay(10, timeout.Token);
        }

        var truncated = await QueryUdpAsync(proxy.ListenEndPoint!, "big.example", timeout.Token);
        Assert.True(DnsMessage.IsTruncated(truncated));
        Assert.Equal(0, DnsMessage.GetRcode(truncated));
        using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await tcp.ConnectAsync(proxy.ListenEndPoint!, timeout.Token);
    }

    [Fact]
    public async Task Start_FailsWhenUdpPortIsTaken()
    {
        // Захватчик UDP - сокет самой пробы: порт не отпускается между выбором и захватом.
        var held = HoldFreePort(IPAddress.Loopback);
        using var squatter = held.Udp;
        var port = ((IPEndPoint)squatter.LocalEndPoint!).Port;
        held.Tcp.Dispose();

        await using var proxy = new DnsProxyServer(IPAddress.Loopback, new DnsCache(TimeProvider.System));

        Assert.Throws<SocketException>(() => proxy.Start(port));
        Assert.False(proxy.TcpListening);
        // TCP, занятый на время попытки, отпущен.
        using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
        tcp.Bind(new IPEndPoint(IPAddress.Loopback, port));
    }

    /// <summary>
    /// Эксклюзивно занимает случайный порт, годный и для UDP, и для TCP (вне исключённых диапазонов обоих протоколов),
    /// и возвращает оба сокета. Тест оставляет один из них захватчиком: отпустить порт и занять его заново - гонка
    /// с другими процессами за свободный номер.
    /// </summary>
    private static (Socket Udp, Socket Tcp) HoldFreePort(IPAddress address)
    {
        for (var attempt = 1; ; attempt++)
        {
            var tcp = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
            var udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
            try
            {
                tcp.Bind(new IPEndPoint(address, Random.Shared.Next(49152, 65536)));
                tcp.Listen(1);
                udp.Bind(tcp.LocalEndPoint!);
                return (udp, tcp);
            }
            catch (SocketException)
            {
                udp.Dispose();
                tcp.Dispose();
                if (attempt >= 50)
                {
                    throw;
                }
            }
        }
    }

    private static async Task<byte[]> QueryUdpAsync(IPEndPoint endpoint, string name, CancellationToken token)
    {
        using var client = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await client.SendToAsync(DnsMessage.BuildQuery(7, name, DnsMessage.TypeA), endpoint, token);
        var buffer = new byte[4096];
        var received = await client.ReceiveAsync(buffer, token);
        return buffer.AsSpan(0, received).ToArray();
    }

    [Fact]
    public async Task OptionalAddress_AnswersOnBothAddresses()
    {
        Assert.SkipUnless(Socket.OSSupportsIPv6, "Стек IPv6 недоступен: проверять ::1 нечем.");

        var cache = new DnsCache(TimeProvider.System);
        cache.Pin("pinned.example", [0xCB007109u]);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache, IPAddress.IPv6Loopback);
        proxy.Start(0);
        Assert.True(proxy.OptionalListening);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        foreach (var endpoint in new[] { proxy.ListenEndPoint!, proxy.OptionalEndPoint! })
        {
            using var client = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            await client.SendToAsync(DnsMessage.BuildQuery(7, "pinned.example", DnsMessage.TypeA), endpoint, timeout.Token);
            var buffer = new byte[512];
            var received = await client.ReceiveAsync(buffer, timeout.Token);
            Assert.Equal([0xCB007109u], DnsMessage.ReadAddresses(buffer.AsSpan(0, received)));
        }
    }

    [Fact]
    public async Task OptionalAddressTaken_KeepsPrimaryAndTakesItLater()
    {
        Assert.SkipUnless(Socket.OSSupportsIPv6, "Стек IPv6 недоступен: проверять ::1 нечем.");

        // Захватчик ::1 — такой же посредник: он подбирает порт, свободный и для UDP, и для TCP.
        var squatter = new DnsProxyServer(IPAddress.IPv6Loopback, new DnsCache(TimeProvider.System));
        squatter.Start(0);
        var port = squatter.ListenEndPoint!.Port;
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, new DnsCache(TimeProvider.System), IPAddress.IPv6Loopback)
        {
            RetryInterval = TimeSpan.FromMilliseconds(50),
        };

        try
        {
            proxy.Start(port);

            Assert.True(proxy.TcpListening);
            Assert.False(proxy.OptionalListening);
            Assert.Equal(port, proxy.ListenEndPoint!.Port);
        }
        finally
        {
            await squatter.DisposeAsync();
        }

        // Адрес освободился: посредник занимает его в фоне.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!proxy.OptionalListening)
        {
            await Task.Delay(10, timeout.Token);
        }

        Assert.Equal(port, proxy.OptionalEndPoint!.Port);
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
