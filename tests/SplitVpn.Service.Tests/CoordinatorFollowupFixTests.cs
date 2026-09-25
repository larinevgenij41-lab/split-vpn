using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RecoveredPin_IsConfirmedAfterFullReconcile(bool wfpFailure)
    {
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "direct.example", Target = RouteTarget.Direct }] });
        var c = await StartAsync();
        await ConnectAsync(c);
        var host = Ipv4.Parse("13.107.1.1");
        var notice = new PinnedRouteNotice("direct.example", "direct.example", RouteTarget.Direct, [host], TimeSpan.FromMinutes(5));
        if (wfpFailure) _world.Wfp.FailNextReplace = 1;
        else _world.Routes.FailNext = 1;
        var first = c.ObservePinnedAsync(notice, CancellationToken.None);
        await c.DrainAsync();
        Assert.False(await first);
        Assert.False(await c.ObservePinnedAsync(notice, CancellationToken.None));

        await c.ReconcileAsync(CancellationToken.None);

        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(host, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
        Assert.True(await c.ObservePinnedAsync(notice, CancellationToken.None));
        Assert.Equal(0, c.QueuedCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RefreshedServerDns_RetainsActivePeerUntilDisconnect(bool restart)
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Server = "vpn.example" }] });
        var c = await StartAsync();
        await ConnectAsync(c);
        _world.Resolver.Answer = [FakeWorld.SecondServer];
        _world.Time.Advance(TimeSpan.FromHours(1));
        await c.ReconcileAsync(CancellationToken.None);
        await CompleteDialAsync(c);

        Assert.Equal([FakeWorld.SecondServer], c.Facts.Tunnels[_profile.Id].ServerAddresses);
        Assert.True(_world.Ras.Connected);
        Assert.False(_world.Routes.ServerRouteLostWhileConnected);
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.Server, 32));
        if (restart)
        {
            c = await StartAsync();
            Assert.True(_world.Ras.Connected);
            Assert.False(_world.Routes.ServerRouteLostWhileConnected);
            Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.Server, 32));
        }

        await c.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, true), CancellationToken.None);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.Server, 32));
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.SecondServer, 32));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DomainPin_CannotRedirectUpstreamDns(bool mixedAnswer)
    {
        var dns = Ipv4.Parse("1.1.1.1");
        var other = Ipv4.Parse("13.107.1.1");
        SaveSettings(Settings() with
        {
            UpstreamDns = ["1.1.1.1"],
            DomainRules = [new DomainRuleSetting { Suffix = "dns.example", Target = RouteTarget.Direct }],
        });
        var c = await StartAsync();
        await ConnectAsync(c);
        var notice = new PinnedRouteNotice("dns.example", "dns.example", RouteTarget.Direct,
            mixedAnswer ? [other, dns] : [dns], TimeSpan.FromMinutes(5));
        var answer = c.ObservePinnedAsync(notice, CancellationToken.None);
        await c.DrainAsync();

        Assert.False(await answer);
        Assert.DoesNotContain(c.Facts.Policy!.Pins, p => p.Address == dns || p.Address == other);
        Assert.Equal(FilterAction.Permit, ServiceDnsAction(dns, c.Facts.Tunnels[_profile.Id].Luid!.Value));
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(dns, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
    }

    [Fact]
    public async Task ChangedUpstreamDns_RevokesAnExistingConflictingDomainPin()
    {
        var dns = Ipv4.Parse("1.1.1.1");
        SaveSettings(Settings() with
        {
            UpstreamDns = ["8.8.8.8"],
            DomainRules = [new DomainRuleSetting { Suffix = "dns.example", Target = RouteTarget.Direct }],
        });
        var c = await StartAsync();
        await ConnectAsync(c);
        var answer = c.ObservePinnedAsync(new PinnedRouteNotice("dns.example", "dns.example", RouteTarget.Direct,
            [dns], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await c.DrainAsync();
        Assert.True(await answer);

        Assert.True((await c.HandleRequestAsync(new SaveSettingsRequest(c.Settings with { UpstreamDns = ["1.1.1.1"] }), CancellationToken.None)).Ok);

        Assert.DoesNotContain(c.Facts.Policy!.Pins, p => p.Address == dns);
        Assert.Equal(FilterAction.Permit, ServiceDnsAction(dns, c.Facts.Tunnels[_profile.Id].Luid!.Value));
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(dns, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DomainPin_CannotRedirectNegotiatedOrFallbackDns(bool fallback)
    {
        var dns = Ipv4.Parse(fallback ? "1.1.1.1" : "198.51.100.50");
        if (fallback) _world.Dns.NameServers[FakeInventory.TunnelGuid(0)] = "";
        SaveSettings(Settings() with
        {
            UpstreamDns = [],
            DomainRules = [new DomainRuleSetting { Suffix = "dns.example", Target = RouteTarget.Direct }],
        });
        var c = await StartAsync();
        await ConnectAsync(c);
        var answer = c.ObservePinnedAsync(new PinnedRouteNotice("dns.example", "dns.example", RouteTarget.Direct,
            [dns], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await c.DrainAsync();

        Assert.False(await answer);
        Assert.Equal(FilterAction.Permit, ServiceDnsAction(dns, c.Facts.Tunnels[_profile.Id].Luid!.Value));
    }

    private FilterAction ServiceDnsAction(uint address, ulong luid) => _world.Wfp.Groups.Values.SelectMany(f => f)
        .Where(f => f.Family != FilterFamily.V6 && f.Conditions.All(c => c switch
        {
            RemoteRangeV4 r => address >= r.Start && address <= r.End,
            LocalInterfaceCondition i => i.NotEqual ? luid != i.Luid : luid == i.Luid,
            ProtocolCondition p => p.Protocol == 17,
            RemotePortCondition p => p.NotEqual ? p.Port != 53 : p.Port == 53,
            AppIdCondition a => a.ExecutablePath == _world.Dependencies().ServiceExecutablePath,
            LocalSystemUserCondition => true,
            _ => false,
        }))
        .OrderByDescending(f => f.Weight).ThenByDescending(f => f.Action == FilterAction.Block).First().Action;
}
