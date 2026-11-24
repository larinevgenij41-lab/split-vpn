using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Соединения TCP посредника: абсолютный срок жизни и простой между запросами не дают одной программе навсегда
/// занять места <see cref="DnsProxyServer.MaxTcpClients"/>; остановка слушателя не роняет цикл приёма.
/// Посредник слушает loopback на случайном порту.
/// </summary>
public sealed class DnsProxyTcpLifetimeTests
{
    private static readonly uint Pinned = Ipv4.Parse("203.0.113.5");

    [Fact]
    public async Task Connection_SendingQueriesEverySecond_IsClosedByAbsoluteLifetime()
    {
        var cache = new DnsCache(TimeProvider.System);
        cache.Pin("pinned.example", [Pinned]);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache)
        {
            TcpIdleTimeout = TimeSpan.FromSeconds(2),
            TcpConnectionLifetime = TimeSpan.FromSeconds(3),
        };
        proxy.Start(0);
        using var client = new TcpClient();
        await client.ConnectAsync(proxy.ListenEndPoint!, TestContext.Current.CancellationToken);
        var stream = client.GetStream();

        var clock = Stopwatch.StartNew();
        var answered = 0;
        var closed = false;
        for (var i = 0; i < 15 && !closed; i++)
        {
            var response = await TryExchangeAsync(stream, (ushort)(i + 1));
            if (response is null)
            {
                closed = true;
                break;
            }

            Assert.Equal([Pinned], DnsMessage.ReadAddresses(response));
            answered++;
            await Task.Delay(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        }

        // Без предела соединение жило бы все 15 запросов: срок простоя перезапускался с каждым.
        Assert.True(closed);
        Assert.InRange(answered, 2, 5);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"соединение закрыто через {clock.Elapsed}");
    }

    [Fact]
    public async Task IdleConnection_AfterAnswer_IsClosedQuietly()
    {
        var cache = new DnsCache(TimeProvider.System);
        cache.Pin("pinned.example", [Pinned]);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache)
        {
            TcpIdleTimeout = TimeSpan.FromMilliseconds(500),
            TcpConnectionLifetime = TimeSpan.FromSeconds(30),
        };
        proxy.Start(0);
        using var client = new TcpClient();
        await client.ConnectAsync(proxy.ListenEndPoint!, TestContext.Current.CancellationToken);
        var stream = client.GetStream();

        Assert.NotNull(await TryExchangeAsync(stream, 1));
        var clock = Stopwatch.StartNew();
        var header = new byte[2];
        var read = await stream.ReadAtLeastAsync(header, 1, throwOnEndOfStream: false, TestContext.Current.CancellationToken)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal(0, read);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5));

        // Закрытие по простою штатное: отказом не считается.
        Assert.Equal(0, proxy.Stats.Failures);
    }

    [Fact]
    public async Task AcceptOnStoppedListener_EndsLoopWithoutFaultOrFailure()
    {
        var calls = 0;
        var secondCall = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, new DnsCache(TimeProvider.System))
        {
            // Слушатель освобождённого адреса остановлен, пока приём ждал: сначала прерванный приём, затем приём
            // на остановленном слушателе.
            AcceptTcp = (_, _) =>
            {
                switch (Interlocked.Increment(ref calls))
                {
                    case 1:
                        return ValueTask.FromException<TcpClient>(new SocketException((int)SocketError.OperationAborted));
                    default:
                        secondCall.TrySetResult();
                        return ValueTask.FromException<TcpClient>(new InvalidOperationException("Not listening."));
                }
            },
        };
        proxy.Start(0);

        await secondCall.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Task? finished = null;
        var clock = Stopwatch.StartNew();
        while (finished is null && clock.Elapsed < TimeSpan.FromSeconds(10))
        {
            finished = proxy.ReceiveLoops.FirstOrDefault(t => t.IsCompleted);
            if (finished is null)
            {
                await Task.Delay(20, TestContext.Current.CancellationToken);
            }
        }

        Assert.NotNull(finished);
        Assert.Equal(TaskStatus.RanToCompletion, finished.Status);
        Assert.Equal(2, Volatile.Read(ref calls));
        Assert.Equal(0, proxy.Stats.Failures);
    }

    /// <summary>Запрос закреплённого имени и ответ; null — посредник закрыл соединение.</summary>
    private static async Task<byte[]?> TryExchangeAsync(NetworkStream stream, ushort id)
    {
        var query = DnsMessage.BuildQuery(id, "pinned.example", DnsMessage.TypeA);
        var framed = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed, 2);
        try
        {
            await stream.WriteAsync(framed, TestContext.Current.CancellationToken);
            var header = new byte[2];
            if (await stream.ReadAtLeastAsync(header, 2, throwOnEndOfStream: false, TestContext.Current.CancellationToken)
                    .AsTask().WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken) < 2)
            {
                return null;
            }

            var response = new byte[BinaryPrimitives.ReadUInt16BigEndian(header)];
            await stream.ReadExactlyAsync(response, TestContext.Current.CancellationToken);
            return response;
        }
        catch (IOException)
        {
            return null;
        }
    }
}
