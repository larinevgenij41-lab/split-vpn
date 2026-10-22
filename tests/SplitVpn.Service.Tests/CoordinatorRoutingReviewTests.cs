using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task RouteFailure_BlocksOldTunnelUntilNewRouteIsApplied()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var c = await StartAsync();
        await ConnectAsync(c);
        var host = Ipv4.Parse("13.107.1.1");
        _world.Routes.FailNext = 1;
        await c.HandleRequestAsync(new SaveSettingsRequest(c.Settings with
        {
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        }), CancellationToken.None);

        Assert.Equal(ConnectionState.PartiallyApplied, c.DeriveState());
        var oldRoute = _world.Routes.Current.Where(r => r.Destination.ToRange().Contains(host))
            .MaxBy(r => r.Destination.PrefixLength);
        Assert.Equal(FilterAction.Block, RoutingAction(host, oldRoute.InterfaceLuid));

        await c.ReconcileAsync(CancellationToken.None);
        var route = _world.Routes.Current.Where(r => r.Destination.ToRange().Contains(host))
            .MaxBy(r => r.Destination.PrefixLength);
        Assert.Equal(c.Facts.Tunnels[second.Id].Luid, route.InterfaceLuid);
        Assert.Equal(FilterAction.Permit, RoutingAction(host, route.InterfaceLuid));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DirectPin_ReplacesTunnelHostRouteAndOutageBlock(bool pause)
    {
        var second = SecondProfile();
        var host = Ipv4.Parse("13.107.1.1");
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "13.107.1.1/32", Target = RouteTarget.Tunnel(second.Id) }],
            DomainRules = [new DomainRuleSetting { Suffix = "direct.example", Target = RouteTarget.Direct }],
        });
        var c = await StartAsync();
        await ConnectAsync(c);
        if (pause)
        {
            await c.HandleRequestAsync(new SetTunnelPausedRequest(second.Id, true), CancellationToken.None);
        }

        var pending = c.ObservePinnedAsync(new PinnedRouteNotice("direct.example", "direct.example", RouteTarget.Direct,
            [host], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await c.DrainAsync();
        Assert.True(await pending);
        var route = Assert.Single(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(host, 32));
        Assert.Equal(FakeWorld.WiFiLuid, route.InterfaceLuid);
        Assert.Equal(FilterAction.Permit, RoutingAction(host, FakeWorld.WiFiLuid));
        Assert.Equal(FilterAction.Block, RoutingAction(host, FakeInventory.TunnelLuid(1)));

        if (!pause)
        {
            _world.Time.Advance(TimeSpan.FromMinutes(6));
            await TickAsync(c);
            var restored = Assert.Single(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(host, 32));
            Assert.Equal(FakeInventory.TunnelLuid(1), restored.InterfaceLuid);
            Assert.Equal(FilterAction.Block, RoutingAction(host, FakeWorld.WiFiLuid));
        }
    }

    private FilterAction RoutingAction(uint address, ulong luid) => _world.Wfp.Groups.Values.SelectMany(f => f)
        .Where(f => f.Family != FilterFamily.V6 && f.Conditions.All(c => c switch
        {
            RemoteRangeV4 r => address >= r.Start && address <= r.End,
            LocalInterfaceCondition i => i.NotEqual ? luid != i.Luid : luid == i.Luid,
            ProtocolCondition p => p.Protocol == 6,
            RemotePortCondition p => p.NotEqual ? p.Port != 443 : p.Port == 443,
            _ => false,
        }))
        .OrderByDescending(f => f.Weight).ThenByDescending(f => f.Action == FilterAction.Block).First().Action;
}
