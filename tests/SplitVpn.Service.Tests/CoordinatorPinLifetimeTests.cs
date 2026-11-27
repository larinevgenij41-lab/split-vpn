using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    private static readonly uint SharedDomainAddress = Ipv4.Parse("93.184.216.34");

    private async Task<Coordinator> WithSharedDomainRulesAsync()
    {
        SaveSettings(Settings() with
        {
            DefaultTarget = RouteTarget.Direct,
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "first.example", Target = RouteTarget.Tunnel(_profile.Id) },
                new DomainRuleSetting { Suffix = "second.example", Target = RouteTarget.Tunnel(_profile.Id) },
            ],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        return coordinator;
    }

    private async Task PinSharedAddressAsync(Coordinator coordinator, string suffix, TimeSpan ttl)
    {
        var pending = coordinator.ObservePinnedAsync(new PinnedRouteNotice(suffix, suffix,
            RouteTarget.Tunnel(_profile.Id), [SharedDomainAddress], ttl), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pending);
    }

    [Fact]
    public async Task RaisingParentPriorityRevokesLiveChildPin()
    {
        var settings = Settings() with
        {
            DefaultTarget = RouteTarget.Direct,
            DomainRules = [
                new() { Suffix = "example.test", Target = RouteTarget.Direct },
                new() { Suffix = "first.example.test", Target = RouteTarget.Tunnel(_profile.Id) },
            ],
        };
        SaveSettings(settings);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        await PinSharedAddressAsync(coordinator, "first.example.test", TimeSpan.FromHours(1));
        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(settings with
        {
            DomainRules = [settings.DomainRules[0] with { Priority = RoutePriority.High }, settings.DomainRules[1]],
        }), CancellationToken.None);
        Assert.True(response.Ok);
        Assert.DoesNotContain(SharedDomainAddress, coordinator.Facts.Pinned.Keys);
        var notice = new PinnedRouteNotice("first.example.test", "example.test", RouteTarget.Direct, [SharedDomainAddress], TimeSpan.FromMinutes(2));
        var pending = coordinator.ObservePinnedAsync(notice, CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pending);
    }

    [Fact]
    public async Task LoweringParentPriorityRetainsUnchangedSiblingPin()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var settings = Settings() with
        {
            DefaultTarget = RouteTarget.Direct,
            DomainRules = [
                new() { Suffix = "example.test", Target = vpn, Priority = RoutePriority.High },
                new() { Suffix = "child.example.test", Target = RouteTarget.Direct },
            ],
        };
        SaveSettings(settings);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        foreach (var name in new[] { "api.example.test", "child.example.test" })
        {
            var wait = coordinator.ObservePinnedAsync(new PinnedRouteNotice("cdn.other.test", "example.test", vpn, [SharedDomainAddress], TimeSpan.FromHours(1)) { Origins = [name] }, CancellationToken.None);
            await coordinator.DrainAsync();
            Assert.True(await wait);
        }

        var saved = await coordinator.HandleRequestAsync(new SaveSettingsRequest(settings with
        {
            DomainRules = [settings.DomainRules[0] with { Priority = RoutePriority.Normal }, settings.DomainRules[1]],
        }), CancellationToken.None);
        Assert.True(saved.Ok);
        Assert.Equal("api.example.test", coordinator.Facts.Pinned[SharedDomainAddress].Origin);
        Assert.Equal(vpn, coordinator.Facts.Pinned[SharedDomainAddress].Target);
    }

    [Fact]
    public async Task SharedDomainIp_ShorterTtlDoesNotRemoveTheLongerPin()
    {
        var coordinator = await WithSharedDomainRulesAsync();
        await PinSharedAddressAsync(coordinator, "first.example", TimeSpan.FromHours(1));
        await PinSharedAddressAsync(coordinator, "second.example", TimeSpan.FromMinutes(1));

        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);

        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(SharedDomainAddress).Tunnel);
    }

    [Fact]
    public async Task SharedDomainIp_RemovingOneRuleKeepsTheOtherOwnersPin()
    {
        var coordinator = await WithSharedDomainRulesAsync();
        await PinSharedAddressAsync(coordinator, "first.example", TimeSpan.FromHours(1));
        await PinSharedAddressAsync(coordinator, "second.example", TimeSpan.FromHours(1));

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
        {
            DomainRules = coordinator.Settings.DomainRules.Where(r => r.Suffix != "second.example").ToList(),
        }), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(SharedDomainAddress).Tunnel);
        // После TTL закрепление держится ещё запас для UDP/QUIC (соединений TCP к адресу нет).
        _world.Time.Advance(TimeSpan.FromMinutes(61) + Coordinator.PinLingerGrace);
        await TickAsync(coordinator);
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(SharedDomainAddress).Decision);
    }

    [Fact]
    public async Task DomainPin_RevokedBeforeApplyIsNotAcknowledged()
    {
        var coordinator = await WithSharedDomainRulesAsync();
        var pending = coordinator.ObservePinnedAsync(new PinnedRouteNotice("first.example", "first.example",
            RouteTarget.Tunnel(_profile.Id), [SharedDomainAddress], TimeSpan.FromHours(1)), CancellationToken.None);

        await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with { DomainRules = [] }), CancellationToken.None);
        await coordinator.DrainAsync();

        Assert.False(await pending);
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(SharedDomainAddress).Decision);
    }

    [Fact]
    public async Task CertificateBootstrap_DoesNotReplaceAnExistingVpnPin()
    {
        var coordinator = await WithSharedDomainRulesAsync();
        await PinSharedAddressAsync(coordinator, "first.example", TimeSpan.FromHours(1));
        _world.Resolver.Answers[RevocationHost] = [SharedDomainAddress];
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        await coordinator.OnCertificateProbedAsync(_profile.Id, tunnel.CertificateProbeGeneration,
            ServerCertificate(_world.Time.GetUtcNow().AddDays(6)), "тест", CancellationToken.None);

        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(SharedDomainAddress).Tunnel);
        Assert.DoesNotContain(RevocationHost, _world.Proxy.Pinned.Keys);
        Assert.DoesNotContain(_world.Routes.Current,
            r => r.Destination == new Ipv4Cidr(SharedDomainAddress, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
    }

    [Theory]
    [InlineData(RevocationHost)]
    [InlineData("lencr.org")]
    public async Task CertificateBootstrap_RespectsExplicitDomainRules(string suffix)
    {
        SaveSettings(Settings() with
        {
            DomainRules = [new DomainRuleSetting { Suffix = suffix, Target = RouteTarget.Tunnel(_profile.Id) }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var calls = _world.Resolver.Calls;
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        await coordinator.OnCertificateProbedAsync(_profile.Id, tunnel.CertificateProbeGeneration,
            ServerCertificate(_world.Time.GetUtcNow().AddDays(6)), "тест", CancellationToken.None);

        Assert.Equal(calls, _world.Resolver.Calls);
        Assert.DoesNotContain(RevocationHost, _world.Proxy.Pinned.Keys);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes,
            r => r.Suffix == RevocationHost && r.Target == RouteTarget.Direct);
    }
}
