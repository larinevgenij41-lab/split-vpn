using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// 0.17.9: посредник отвечает и на адресе основного адаптера. Запрос, привязанный к адаптеру (проверка интернета
/// Windows), до 127.0.0.1 не доходит, и Wi-Fi после загрузки сбрасывала служба автонастройки WLAN.
/// </summary>
public sealed class AdapterAddressDnsTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("192.168.1.100,127.0.0.1", true)]
    [InlineData("192.168.1.100 127.0.0.1", true)]
    [InlineData("127.0.0.1,192.168.1.100", false)]
    [InlineData("192.168.1.100,127.0.0.1,8.8.8.8", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("fe80::1,127.0.0.1", false)]
    [InlineData("", false)]
    public void IsProxySet_RecognizesLoopbackAndOwnAddressPair(string servers, bool expected)
    {
        Assert.Equal(expected, InterfaceDnsOps.IsProxySet(servers));
    }

    [Fact]
    public void ProxyNameServers_PutsOwnAddressFirst()
    {
        Assert.Equal("127.0.0.1", InterfaceDnsOps.ProxyNameServers(null));
        Assert.Equal("192.168.1.100,127.0.0.1", InterfaceDnsOps.ProxyNameServers("192.168.1.100"));
    }

    [Fact]
    public void Original_OwnAddressPairIsOursOnlyWithBackup()
    {
        Assert.Equal("192.168.1.1", InterfaceDnsOps.Original("192.168.1.100,127.0.0.1", "192.168.1.1"));
        Assert.Equal("192.168.1.100,127.0.0.1", InterfaceDnsOps.Original("192.168.1.100,127.0.0.1", null));
    }

    [Theory]
    [InlineData("192.168.1.100,127.0.0.1", "", true)]
    [InlineData("192.168.1.100,127.0.0.1", "::1", true)]
    [InlineData("192.168.1.77,127.0.0.1", "", false)]
    [InlineData("192.168.1.100", "", false)]
    public void IsOnlyProxyLoopback_AcceptsOwnAddressOfTheAdapter(string v4, string v6, bool expected)
    {
        Assert.Equal(expected, InterfaceDnsOps.IsOnlyProxyLoopback(v4, v6, ["192.168.1.100"]));
    }

    private static IPAddress? LocalAddress() =>
        Dns.GetHostAddresses(Dns.GetHostName(), AddressFamily.InterNetwork).FirstOrDefault(a => !IPAddress.IsLoopback(a));

    [Fact]
    public async Task Proxy_AnswersOnAdapterAddress_OnlyToThisComputer()
    {
        if (LocalAddress() is not { } local)
        {
            return; // У компьютера нет адреса IPv4, кроме loopback: проверять нечем.
        }

        var cache = new DnsCache(new FakeTimeProvider());
        cache.Pin("pinned.example", [Ipv4.Parse("203.0.113.7")]);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache)
        {
            ServeAdapterAddresses = true,
            ReadLocalAddresses = () => [local],
        };
        proxy.Start(0);
        Assert.True(proxy.AdapterListening);
        var port = proxy.AdapterEndPoint!.Port;
        Assert.Equal(proxy.ListenEndPoint!.Port, port);

        // Запрос с адреса адаптера к адресу адаптера: так его отправляет Windows при проверке интернета на интерфейсе.
        using var client = new UdpClient(new IPEndPoint(local, 0));
        var query = DnsMessage.BuildQuery(7, "pinned.example", DnsMessage.TypeA);
        await client.SendAsync(query, new IPEndPoint(local, port), TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var answer = await client.ReceiveAsync(timeout.Token);
        Assert.Equal(local, answer.RemoteEndPoint.Address);
        Assert.Equal(0, DnsMessage.GetRcode(answer.Buffer));

        Assert.True(proxy.IsLocalSource(IPAddress.Loopback));
        Assert.False(proxy.IsLocalSource(IPAddress.Parse("192.0.2.200")));
    }

    [Fact]
    public async Task Proxy_IgnoresQueryFromForeignAddress()
    {
        if (LocalAddress() is not { } local)
        {
            return;
        }

        var cache = new DnsCache(new FakeTimeProvider());
        cache.Pin("pinned.example", [Ipv4.Parse("203.0.113.7")]);
        // Список адресов компьютера пуст: отправитель с адреса адаптера считается чужим, как запрос из сети.
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache) { ServeAdapterAddresses = true, ReadLocalAddresses = () => [] };
        proxy.Start(0);

        using var client = new UdpClient(new IPEndPoint(local, 0));
        await client.SendAsync(DnsMessage.BuildQuery(7, "pinned.example", DnsMessage.TypeA), new IPEndPoint(local, proxy.AdapterEndPoint!.Port), TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromMilliseconds(500));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await client.ReceiveAsync(timeout.Token));
    }

    [Fact]
    public async Task Proxy_AdapterListener_CoexistsWithForeignListenerOnItsOwnAddress()
    {
        if (LocalAddress() is not { } local)
        {
            return;
        }

        await using var proxy = new DnsProxyServer(IPAddress.Loopback, new DnsCache(new FakeTimeProvider())) { ServeAdapterAddresses = true };
        proxy.Start(0);

        // Чужой резолвер (DNS WSL, Hyper-V) занимает порт на своём адресе эксклюзивно уже после нас: ему не мешаем.
        using var foreign = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
        foreign.Bind(new IPEndPoint(local, proxy.AdapterEndPoint!.Port));
    }
}
