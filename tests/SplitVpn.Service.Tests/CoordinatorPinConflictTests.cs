using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task DomainPins_CapacityRejectsNewAddressesButAllowsRefreshAndExpires()
    {
        // Без включения защиты проверяем вместимость хранилища, не создавая тысячи маршрутов.
        var coordinator = await StartAsync();
        var addresses = Enumerable.Range(1, Coordinator.MaxDomainPins).Select(i => 0xC0000000u + (uint)i).ToArray();
        var notice = new PinnedRouteNotice("limit.example", "limit.example", RouteTarget.Direct, addresses, TimeSpan.FromMinutes(5));
        Assert.True(await coordinator.ObservePinnedAsync(notice, CancellationToken.None));
        var extra = 0xC0010000u;

        Assert.False(await coordinator.ObservePinnedAsync(notice with { Addresses = [addresses[0], extra] }, CancellationToken.None));
        Assert.True(await coordinator.ObservePinnedAsync(notice with { Addresses = [addresses[0], addresses[0]] }, CancellationToken.None));

        _world.Time.Advance(TimeSpan.FromMinutes(6));
        await TickAsync(coordinator);
        Assert.True(await coordinator.ObservePinnedAsync(notice with { Addresses = [extra] }, CancellationToken.None));
    }

    [Fact]
    public async Task DomainPins_ConflictingAnswerIsRejectedWithoutPartialChanges()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with
        {
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "private.example", Target = vpn },
                new DomainRuleSetting { Suffix = "public.example", Target = RouteTarget.Direct },
            ],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var shared = Ipv4.Parse("198.51.100.71");
        var extra = Ipv4.Parse("198.51.100.72");
        var first = coordinator.ObservePinnedAsync(new PinnedRouteNotice("private.example", "private.example", vpn,
            [shared], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await first);

        var conflict = coordinator.ObservePinnedAsync(new PinnedRouteNotice("public.example", "public.example", RouteTarget.Direct,
            [extra, shared], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();

        Assert.False(await conflict);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(shared).Tunnel);
        Assert.DoesNotContain(coordinator.Facts.Policy.Pins, p => p.Address == extra);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(shared, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);

        // После истечения прежнего закрепления тот же IP можно назначить другой цели.
        _world.Time.Advance(TimeSpan.FromMinutes(6));
        var replacement = coordinator.ObservePinnedAsync(new PinnedRouteNotice("public.example", "public.example", RouteTarget.Direct,
            [shared], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await replacement);
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(shared).Decision);
    }

    [Fact]
    public async Task DomainPins_ConflictBeforeFirstApplyDoesNotChangeTheFirstAnswer()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with
        {
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "private.example", Target = vpn },
                new DomainRuleSetting { Suffix = "public.example", Target = RouteTarget.Direct },
            ],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var shared = Ipv4.Parse("198.51.100.71");
        var first = coordinator.ObservePinnedAsync(new PinnedRouteNotice("private.example", "private.example", vpn,
            [shared], TimeSpan.FromMinutes(5)), CancellationToken.None);
        var second = coordinator.ObservePinnedAsync(new PinnedRouteNotice("public.example", "public.example", RouteTarget.Direct,
            [shared], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();

        Assert.True(await first);
        Assert.False(await second);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(shared).Tunnel);
    }
}
