using System.Net;
using SplitVpn.Core.Net;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>0.17.9: основному адаптеру ставится DNS «свой адрес, 127.0.0.1» (см. AdapterAddressDnsTests).</summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task PrimaryAdapter_GetsOwnAddressFirst_WhenProxyServesAdapterAddresses()
    {
        _world.Proxy.ServesAdapterAddresses = true;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Equal("192.168.1.100,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        // Туннелю свой адрес не ставится: только основному адаптеру.
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.TunnelGuid]);
        // Собственный адрес адаптера — посредник, а не сервер DNS: в пути посредника он не попадает.
        var own = IPAddress.Parse(Ipv4.Format(FakeWorld.WiFiAddress));
        Assert.DoesNotContain(_world.Proxy.Configuration.Direct?.Servers ?? [], s => s.Address.Equals(own));
    }

    [Fact]
    public async Task PrimaryAdapter_ListFollowsAddressChange_AndListenerLoss()
    {
        _world.Proxy.ServesAdapterAddresses = true;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal("192.168.1.100,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);

        _world.Inventory.WiFiAddress = Ipv4.Parse("192.168.1.101");
        await TickAsync(coordinator);
        Assert.Equal("192.168.1.101,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);

        // Слушатель адресов адаптеров пропал: возвращается одиночный 127.0.0.1.
        _world.Proxy.ServesAdapterAddresses = false;
        _world.Inventory.WiFiAddress = Ipv4.Parse("192.168.1.102");
        await TickAsync(coordinator);
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
    }

    /// <summary>
    /// Аудит 24.11.2026: адрес адаптера объявляется DNS-сервером, только если посредник занял порт на нём
    /// эксклюзивно. Порт держит другая программа - адаптеру только 127.0.0.1; освободился - сверка подхватывает.
    /// </summary>
    [Fact]
    public async Task PrimaryAdapter_OwnAddressNotAnnounced_WhenExclusiveClaimFails()
    {
        _world.Proxy.ServesAdapterAddresses = true;
        _world.Proxy.ForeignHeld.Add(FakeWorld.WiFiAddress);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Empty(_world.Proxy.Claimed);

        // Чужая программа освободила порт: повторный захват на периодической сверке, адрес снова первым.
        _world.Proxy.ForeignHeld.Clear();
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);
        Assert.Equal("192.168.1.100,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Contains(FakeWorld.WiFiAddress, _world.Proxy.Claimed);
    }

    /// <summary>Ушедший адрес освобождается только после того, как он убран из DNS адаптера.</summary>
    [Fact]
    public async Task PrimaryAdapter_OldAddressReleasedAfterDnsRewritten()
    {
        _world.Proxy.ServesAdapterAddresses = true;
        var released = new List<uint>();
        _world.Proxy.OnRelease = address =>
        {
            Assert.DoesNotContain(Ipv4.Format(address), _world.Dns.NameServers.Values.SelectMany(v => v.Split(',')));
            released.Add(address);
        };
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal([FakeWorld.WiFiAddress], _world.Proxy.Claimed);

        var next = Ipv4.Parse("192.168.1.101");
        _world.Inventory.WiFiAddress = next;
        await TickAsync(coordinator);

        Assert.Equal("192.168.1.101,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal([FakeWorld.WiFiAddress], released);
        Assert.Equal([next], _world.Proxy.Claimed);
    }

    [Fact]
    public async Task OwnAddressPairWithoutBackup_IsLeftAlone()
    {
        _world.Proxy.ServesAdapterAddresses = true;
        _world.Dns.NameServers[FakeWorld.WiFiGuid] = "192.168.1.50,127.0.0.1";
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Equal("192.168.1.50,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
    }
}
