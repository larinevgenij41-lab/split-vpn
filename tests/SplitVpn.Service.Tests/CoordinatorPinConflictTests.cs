using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
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

    /// <summary>
    /// S3: адрес сети доставки закреплён правилом пользователя за туннелем, туннель лёг и снова нужна проверка отзыва -
    /// ответ DNS узла проверки отзыва с тем же адресом не отклоняется (иначе дозвон падал бы на проверке отзыва).
    /// Адрес остаётся за правилом пользователя.
    /// </summary>
    [Fact]
    public async Task RevocationAnswer_OnAddressPinnedByUserRule_IsNotRefused()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "cdn.example", Target = vpn }] });
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));
        _world.Resolver.Answers[RevocationHost] = [RevocationAddress];
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var user = coordinator.ObservePinnedAsync(new PinnedRouteNotice("cdn.example", "cdn.example", vpn,
            [RevocationAddress], TimeSpan.FromMinutes(30)), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await user);

        // Немедленный повторный дозвон, если он случится, тоже не проходит: туннель остаётся лежать.
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));
        _world.Ras.Drop();
        await TickAsync(coordinator);
        Assert.False(coordinator.Facts.Tunnels[_profile.Id].IsUp);
        Assert.Contains(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost && d.ExactName);

        var revocation = coordinator.ObservePinnedAsync(new PinnedRouteNotice(RevocationHost, RevocationHost, RouteTarget.Direct,
            [RevocationAddress], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();

        Assert.True(await revocation);
        Assert.Equal(vpn, coordinator.Facts.Pinned[RevocationAddress].Target);
        Assert.DoesNotContain(RevocationAddress, coordinator.Facts.RevocationPins.Keys);
    }

    /// <summary>
    /// S3: пока туннель не поднят, у адреса узла проверки отзыва служебное закрепление - правило пользователя «через VPN»
    /// для домена на том же адресе не отклоняется: служебное закрепление открывает только порт ссылки, правило пользователя важнее.
    /// </summary>
    [Fact]
    public async Task UserRule_OnRevocationPinnedAddress_IsNotRefused()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "cdn.example", Target = vpn }] });
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));
        _world.Resolver.Answers[RevocationHost] = [RevocationAddress];
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));
        var coordinator = await StartAsync();
        await ConnectAfterCertificateProbeAsync(coordinator, _profile);
        Assert.False(coordinator.Facts.Tunnels[_profile.Id].IsUp);
        Assert.Contains(RevocationAddress, coordinator.Facts.RevocationPins.Keys);

        var user = coordinator.ObservePinnedAsync(new PinnedRouteNotice("cdn.example", "cdn.example", vpn,
            [RevocationAddress], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();

        Assert.True(await user);
        Assert.Equal(vpn, coordinator.Facts.Pinned[RevocationAddress].Target);
        Assert.DoesNotContain(RevocationAddress, coordinator.Facts.RevocationPins.Keys);
    }
}
