using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Net;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Маршруты с исключениями при «остальном через VPN»: прямые подсети RU-базы ставятся широкими маршрутами,
/// дыры в них возвращаются в туннель. Путь каждого адреса прежний, записей меньше, а обрыв туннеля не
/// перестраивает прямые маршруты.
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task RouteCover_KeepsEveryPath_WithFewerRoutes()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var routes = _world.Routes.Current;
        // В тестовой базе 5.0.0.0–5.0.249.0 — российские /24, 5.0.250.0–5.0.255.255 — нет.
        Assert.Equal(FakeWorld.WiFiLuid, Lookup(routes, Ipv4.Parse("5.0.10.1")));
        Assert.Equal(FakeWorld.WiFiLuid, Lookup(routes, Ipv4.Parse("5.0.249.200")));
        Assert.Equal(FakeWorld.TunnelLuid, Lookup(routes, Ipv4.Parse("5.0.251.1")));
        Assert.Equal(FakeWorld.TunnelLuid, Lookup(routes, Ipv4.Parse("8.8.8.8")));
        Assert.Equal(FakeWorld.WiFiLuid, Lookup(routes, Ipv4.Parse("77.88.10.1")));

        var direct = routes.Count(r => r.InterfaceLuid == FakeWorld.WiFiLuid && r.Destination.PrefixLength < 32);
        Assert.True(direct < coordinator.Facts.Policy!.DirectRouteCidrs.Count, $"прямых маршрутов {direct}, точно {coordinator.Facts.Policy.DirectRouteCidrs.Count}");

        foreach (var address in Enumerable.Range(0, 5 * 256).Select(i => Ipv4.Parse($"5.{i / 256}.{i % 256}.7")))
        {
            var expected = coordinator.Facts.Policy.Classify(address).Decision == Decision.Direct ? FakeWorld.WiFiLuid : FakeWorld.TunnelLuid;
            Assert.True(expected == Lookup(routes, address), Ipv4.Format(address));
        }
    }

    [Fact]
    public async Task RouteCover_TunnelDrop_KeepsDirectRoutes()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var before = _world.Routes.Current.Where(r => r.InterfaceLuid == FakeWorld.WiFiLuid).ToHashSet();

        _world.Ras.Drop();
        _world.Ras.Results.Enqueue(new Windows.Ras.RasDialResult(false, null, 809, "Нет ответа"));
        await TickAsync(coordinator);

        Assert.DoesNotContain(_world.Routes.Current, r => r.InterfaceLuid == FakeWorld.TunnelLuid);
        Assert.True(before.SetEquals(_world.Routes.Current.Where(r => r.InterfaceLuid == FakeWorld.WiFiLuid)));
    }

    [Fact]
    public async Task RouteCover_ServerInsideDirectNetwork_GetsNoTunnelRoute()
    {
        // Сервер VPN внутри российской сети: второй /32 в туннель увёл бы транспорт туннеля внутрь туннеля.
        var server = Ipv4.Parse("5.0.10.10");
        _world.Routes.ServerAddress = server;
        SaveSettings(Settings() with { Profiles = [_profile with { Server = Ipv4.Format(server) }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var routes = _world.Routes.Current;
        Assert.Equal([server], coordinator.Facts.Tunnels[_profile.Id].ServerAddresses);
        Assert.DoesNotContain(routes, r => r.Destination == new Ipv4Cidr(server, 32) && r.InterfaceLuid != FakeWorld.WiFiLuid);
        Assert.Equal(FakeWorld.WiFiLuid, Lookup(routes, server));
        Assert.Equal(FakeWorld.WiFiLuid, Lookup(routes, Ipv4.Parse("5.0.10.11")));
        Assert.Equal(FakeWorld.TunnelLuid, Lookup(routes, Ipv4.Parse("5.0.251.1")));
    }

    [Fact]
    public async Task RouteCover_DefaultTunnelAddresses_NotInsideSecondTunnelRoute()
    {
        // Адреса туннеля «остального интернета» внутри сети второго туннеля: при обрыве основного они не должны
        // оказаться под маршрутом второго туннеля.
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules =
            [
                new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) },
                new UserRuleSetting { Cidr = "13.107.255.0/24", Target = RouteTarget.Tunnel(_profile.Id) },
            ],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var secondLuid = coordinator.Facts.Tunnels[second.Id].Luid;
        Assert.NotNull(secondLuid);
        var routes = _world.Routes.Current;
        Assert.Equal(secondLuid, Lookup(routes, Ipv4.Parse("13.107.10.1")));
        Assert.Equal(FakeWorld.TunnelLuid, Lookup(routes, Ipv4.Parse("13.107.255.1")));
        Assert.DoesNotContain(routes, r => r.InterfaceLuid == secondLuid && r.Destination.Contains(Ipv4.Parse("13.107.255.1")));
    }

    [Fact]
    public async Task RouteCover_TunnelRoute_DoesNotEndOnForeignAddress()
    {
        // Windows ставит /32 последнего адреса каждой сети туннеля: он не должен перехватить прямой адрес.
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules =
            [
                new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) },
                new UserRuleSetting { Cidr = "13.107.255.255/32", Target = RouteTarget.Direct },
            ],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var routes = _world.Routes.Current;
        Assert.Equal(FakeWorld.WiFiLuid, Lookup(routes, Ipv4.Parse("13.107.255.255")));
        foreach (var route in routes.Where(r => r.NextHop == 0 && r.InterfaceLuid != FakeWorld.WiFiLuid && r.Destination.PrefixLength <= RouteCover.MaxBroadcastPrefix))
        {
            var last = route.Destination.ToRange().End;
            Assert.True(Lookup(routes, last) == route.InterfaceLuid, $"{route.Destination}: последний адрес {Ipv4.Format(last)} идёт в другой интерфейс");
        }
    }

    [Fact]
    public void BroadcastSafePieces_SplitAroundAddressPinnedElsewhere()
    {
        // Маршрут туннеля 13.107.0.0/16, последний адрес которого закреплён правилом домена за прямой целью,
        // и исключение 13.107.128.0/24 к прямой цели внутри него.
        var route = new CoverRoute(Ipv4Cidr.Parse("13.107.0.0/16"), 1);
        var exception = new CoverRoute(Ipv4Cidr.Parse("13.107.128.0/24"), 2);
        var tunnel = RangeSet.From([Ipv4Cidr.Parse("13.107.0.0/16")]).Subtract(RangeSet.From([Ipv4Cidr.Parse("13.107.128.0/24")]));
        var cover = new Coordinator.RouteCoverCache([(tunnel, 1), (RangeSet.From([Ipv4Cidr.Parse("13.107.128.0/24")]), 2)],
            [new CoverTarget(true, OnLink: true), new CoverTarget(true, OnLink: true), new CoverTarget(true)], RangeSet.Empty, [route, exception]);
        var pinned = Ipv4.Parse("13.107.255.255");

        var pieces = Coordinator.BroadcastSafePieces(route, cover, a => a == pinned ? 2 : -2);

        Assert.All(pieces.Where(p => p.PrefixLength <= RouteCover.MaxBroadcastPrefix), p => Assert.NotEqual(pinned, p.ToRange().End));
        Assert.Contains(pieces, p => p.Contains(pinned) && p.PrefixLength == 31);
        // Части покрывают весь маршрут, кроме исключения, и не лежат внутри исключения.
        var covered = RangeSet.From(pieces);
        Assert.True(tunnel.Subtract(covered).Count == 0);
        Assert.DoesNotContain(pieces, p => exception.Cidr.Contains(p.Network) && p.PrefixLength >= exception.Cidr.PrefixLength);
        Assert.True(pieces.Count < 40, $"частей {pieces.Count}");
    }

    /// <summary>Как выбирает Windows: самый длинный подходящий префикс.</summary>
    private static ulong? Lookup(IEnumerable<RouteKey> routes, uint address) =>
        routes.Where(r => r.Destination.Contains(address)).OrderByDescending(r => r.Destination.PrefixLength).Select(r => (ulong?)r.InterfaceLuid).FirstOrDefault();
}
