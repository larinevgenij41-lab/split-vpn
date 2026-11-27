using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Аудит 24.11.2026: слушатель всех адресов не эксклюзивный, и процесс без прав администратора занимал
/// &lt;адрес адаптера&gt;:53 - более точная привязка выигрывает - и получал DNS-запросы всей системы первым.
/// Теперь адрес, объявляемый DNS-сервером адаптера, посредник занимает эксклюзивно, а слушатель всех адресов
/// по-прежнему не мешает чужим резолверам на их адресах (ICS, Hyper-V, WSL).
/// </summary>
public sealed class DnsProxyExclusiveBindTests
{
    private static IPAddress[] LocalAddresses() =>
        Dns.GetHostAddresses(Dns.GetHostName(), AddressFamily.InterNetwork).Where(a => !IPAddress.IsLoopback(a)).ToArray();

    private static DnsProxyServer NewProxy(Action<string>? warning = null, DnsCache? cache = null) =>
        new(IPAddress.Loopback, cache ?? new DnsCache(new FakeTimeProvider()))
        {
            ServeAdapterAddresses = true,
            Warning = warning,
            ReadLocalAddresses = LocalAddresses,
        };

    private static Socket Udp(IPAddress address, int port, bool exclusive = false, bool reuse = false)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            if (exclusive)
            {
                socket.ExclusiveAddressUse = true;
            }

            if (reuse)
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            }

            socket.Bind(new IPEndPoint(address, port));
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static Socket Tcp(IPAddress address, int port, bool exclusive = false, bool reuse = false)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            if (exclusive)
            {
                socket.ExclusiveAddressUse = true;
            }

            if (reuse)
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            }

            socket.Bind(new IPEndPoint(address, port));
            socket.Listen();
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Чужая привязка к адресу и порту отвергается при любых флагах: без флагов, эксклюзивная, SO_REUSEADDR.</summary>
    private static void AssertBindFails(IPAddress address, int port)
    {
        Assert.Throws<SocketException>(() => Udp(address, port).Dispose());
        Assert.Throws<SocketException>(() => Udp(address, port, exclusive: true).Dispose());
        Assert.Throws<SocketException>(() => Udp(address, port, reuse: true).Dispose());
        Assert.Throws<SocketException>(() => Tcp(address, port).Dispose());
        Assert.Throws<SocketException>(() => Tcp(address, port, reuse: true).Dispose());
    }

    private static void AssertBindSucceeds(IPAddress address, int port)
    {
        using (Udp(address, port, exclusive: true))
        using (Tcp(address, port, exclusive: true))
        {
        }
    }

    /// <summary>
    /// Опыт из задачи: при удерживаемом не эксклюзивном 0.0.0.0:P свой эксклюзивный &lt;адрес&gt;:P привязывается,
    /// после этого чужая привязка к &lt;адрес&gt;:P отвергается, а к другому локальному адресу:P проходит.
    /// </summary>
    [Fact]
    public async Task ClaimedAddress_RefusesForeignBind_OtherAddressesStayFree()
    {
        var locals = LocalAddresses();
        if (locals.Length == 0)
        {
            Assert.Skip("У компьютера нет адреса IPv4, кроме loopback");
            return;
        }

        await using var proxy = NewProxy();
        proxy.Start(0);
        Assert.True(proxy.AdapterListening);
        var port = proxy.AdapterEndPoint!.Port;

        var local = locals[0];
        Assert.Equal([local], proxy.ClaimAdapterAddresses([local]));
        Assert.Equal([local], proxy.ClaimedAdapterAddresses);
        // Повторный вызов не занимает адрес второй раз и подтверждает его.
        Assert.Equal([local], proxy.ClaimAdapterAddresses([local]));

        AssertBindFails(local, port);

        // Другой локальный адрес остаётся свободен для своего резолвера (ICS, Hyper-V, WSL).
        AssertBindSucceeds(IPAddress.Parse("127.0.0.2"), port);
        foreach (var other in locals.Skip(1))
        {
            AssertBindSucceeds(other, port);
        }
    }

    [Fact]
    public async Task ClaimedAddress_AnswersQueryFromThisComputer()
    {
        if (LocalAddresses().FirstOrDefault() is not { } local)
        {
            Assert.Skip("У компьютера нет адреса IPv4, кроме loopback");
            return;
        }

        var cache = new DnsCache(new FakeTimeProvider());
        cache.Pin("pinned.example", [Core.Net.Ipv4.Parse("203.0.113.7")]);
        await using var proxy = NewProxy(cache: cache);
        proxy.Start(0);
        Assert.Equal([local], proxy.ClaimAdapterAddresses([local]));
        var port = proxy.ListenEndPoint!.Port;

        using var client = new UdpClient(new IPEndPoint(local, 0));
        await client.SendAsync(DnsMessage.BuildQuery(9, "pinned.example", DnsMessage.TypeA), new IPEndPoint(local, port), TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var answer = await client.ReceiveAsync(timeout.Token);
        Assert.Equal(local, answer.RemoteEndPoint.Address);
        Assert.Equal(0, DnsMessage.GetRcode(answer.Buffer));

        using var tcp = new TcpClient(new IPEndPoint(local, 0));
        await tcp.ConnectAsync(local, port, timeout.Token);
        Assert.True(tcp.Connected);
    }

    [Fact]
    public async Task ForeignListenerOnAddress_ClaimFailsWithWarning_WithoutLeakingSockets_ThenRetrySucceeds()
    {
        if (LocalAddresses().FirstOrDefault() is not { } local)
        {
            Assert.Skip("У компьютера нет адреса IPv4, кроме loopback");
            return;
        }

        var warnings = new List<string>();
        await using var proxy = NewProxy(m => { lock (warnings) { warnings.Add(m); } });
        proxy.Start(0);
        var port = proxy.ListenEndPoint!.Port;

        // Чужая программа уже держит UDP на адресе адаптера: захват не удаётся, адрес не объявляется. TCP посредник
        // занимает первым и при отказе UDP обязан его отпустить.
        var foreign = Udp(local, port, exclusive: true);
        Assert.Empty(proxy.ClaimAdapterAddresses([local]));
        Assert.Empty(proxy.ClaimAdapterAddresses([local]));
        Assert.Empty(proxy.ClaimedAdapterAddresses);
        lock (warnings)
        {
            // Предупреждение с адресом - один раз, а не на каждой сверке.
            Assert.Single(warnings, w => w.Contains(local.ToString(), StringComparison.Ordinal) && w.Contains("не занял", StringComparison.Ordinal));
        }

        // Частичного захвата нет: TCP на адресе посредник не держит.
        Tcp(local, port, exclusive: true).Dispose();

        foreign.Dispose();
        Assert.Equal([local], proxy.ClaimAdapterAddresses([local]));
        lock (warnings)
        {
            Assert.Contains(warnings, w => w.Contains("занял " + local, StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Release_And_Dispose_FreeClaimedAddresses()
    {
        if (LocalAddresses().FirstOrDefault() is not { } local)
        {
            Assert.Skip("У компьютера нет адреса IPv4, кроме loopback");
            return;
        }

        await using var proxy = NewProxy();
        proxy.Start(0);
        var port = proxy.ListenEndPoint!.Port;

        proxy.ClaimAdapterAddresses([local]);
        proxy.ReleaseAdapterAddresses([local]);
        AssertBindFails(local, port);
        proxy.ReleaseAdapterAddresses([]);
        Assert.Empty(proxy.ClaimedAdapterAddresses);
        AssertBindSucceeds(local, port);

        proxy.ClaimAdapterAddresses([local]);
        await proxy.DisposeAsync();
        AssertBindSucceeds(local, port);
        // После остановки посредник ничего не занимает.
        Assert.Empty(proxy.ClaimAdapterAddresses([local]));
        AssertBindSucceeds(local, port);
    }

    [Fact]
    public async Task Claim_BeforeStart_ReturnsNothing()
    {
        await using var proxy = NewProxy();
        Assert.Empty(proxy.ClaimAdapterAddresses([IPAddress.Parse("192.0.2.1")]));
    }
}
