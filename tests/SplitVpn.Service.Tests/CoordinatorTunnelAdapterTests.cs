using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Интерфейс RAS-туннеля и маршруты к серверу (аудит 2026-11-01, ID5, ID6, ID7, ID17, ID78): интерфейс,
/// не найденный сразу после дозвона, ищется снова; исчезнувший — не держится из прежнего снимка;
/// одинаковые адреса двух серверов не сажают оба туннеля на один интерфейс; сервер в локальной сети
/// маршрутизируется напрямую; неподтверждённый разрыв не забывает соединение.
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task RasAdapterMissingAfterDial_IsFoundOnLaterReconcile()
    {
        _world.Inventory.HideTunnel(0);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.NotNull(tunnel.Connection);
        Assert.Null(tunnel.Adapter);
        Assert.False(_world.Routes.HasHalfRoutesOn(FakeWorld.TunnelLuid));

        _world.Inventory.HideTunnel(0, hidden: false);
        await TickAsync(coordinator);

        Assert.Equal(FakeWorld.TunnelLuid, tunnel.Adapter?.Luid);
        Assert.True(_world.Routes.HasHalfRoutesOn(FakeWorld.TunnelLuid));
        Assert.Equal(1, _world.Ras.Dials);
    }

    [Fact]
    public async Task RasAdapterVanished_IsDropped_AndConnectionRedialedAfterTimeout()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.NotNull(tunnel.Adapter);

        _world.Inventory.HideTunnel(0);
        await TickAsync(coordinator);

        Assert.Null(tunnel.Adapter);
        Assert.Null(tunnel.Luid);
        Assert.False(_world.Routes.HasHalfRoutesOn(FakeWorld.TunnelLuid));
        Assert.Equal(0, _world.Ras.HangUps);

        // Пока срок не вышел, соединение не рвётся: интерфейс мог пропасть на мгновение.
        _world.Time.Advance(TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.Equal(0, _world.Ras.HangUps);

        _world.Time.Advance(Coordinator.AdapterMissingTimeout);
        await TickAsync(coordinator);

        Assert.True(_world.Ras.HangUps > 0);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("интерфейс VPN не найден", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SameRasAddress_NamedInterfaces_EachTunnelGetsItsOwn()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        _world.Inventory.SharedTunnelAddress = Ipv4.Parse("10.255.0.2");
        _world.Inventory.TunnelName = slot => _world.Ras.EntryOfSlot(slot) ?? "";
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        var first = coordinator.Facts.Tunnels[_profile.Id];
        var other = coordinator.Facts.Tunnels[second.Id];
        Assert.NotNull(first.Adapter);
        Assert.NotNull(other.Adapter);
        Assert.NotEqual(first.Adapter.Luid, other.Adapter.Luid);
        Assert.Equal(first.EntryName, first.Adapter.Name);
        Assert.Equal(other.EntryName, other.Adapter.Name);
    }

    [Fact]
    public async Task SameRasAddress_IndistinguishableInterfaces_NeverShareLuid()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        _world.Inventory.SharedTunnelAddress = Ipv4.Parse("10.255.0.2");
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);
        await TickAsync(coordinator);

        var first = coordinator.Facts.Tunnels[_profile.Id].Adapter;
        var other = coordinator.Facts.Tunnels[second.Id].Adapter;
        Assert.False(first is not null && other is not null && first.Luid == other.Luid, "оба туннеля на одном интерфейсе");
    }

    [Theory]
    [InlineData("192.168.1.50")]
    [InlineData("192.168.1.1")]
    public async Task ServerInPrimaryOnLinkNetwork_GetsOnLinkRoute(string address)
    {
        var second = SecondProfile() with { Server = address };
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        var server = new Ipv4Cidr(Ipv4.Parse(address), 32);
        var route = Assert.Single(_world.Routes.Current, r => r.Destination == server);
        Assert.Equal(0u, route.NextHop);
        Assert.Equal(FakeWorld.WiFiLuid, route.InterfaceLuid);
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.Server, 32) && r.NextHop == FakeWorld.Gateway);
    }

    [Fact]
    public async Task HangUpNotConfirmed_KeepsConnectionInModel()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 1460);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);

        Assert.NotNull(tunnel.Connection);
        Assert.True(_world.Ras.Connected);
        Assert.NotNull(coordinator.Facts.PartialError);
    }
}
