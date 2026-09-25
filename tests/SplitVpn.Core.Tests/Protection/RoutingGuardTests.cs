using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Protection;

public partial class FilterPlanTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TunnelRouteGuards_UseLargeAddressGroupOnlyForLiveTunnels(bool secondUp)
    {
        var inputs = Inputs(Tunnel, secondUp ? SecondTunnel : null);
        var runtime = FilterPlanBuilder.BuildRuntime(inputs);
        var addressFilters = FilterPlanBuilder.BuildDirect(inputs);

        Assert.DoesNotContain(runtime, f => f.Weight == FilterPlanBuilder.WeightRouteGuard);
        var tunnelGuards = addressFilters.Where(f => f.Weight == FilterPlanBuilder.WeightRouteGuard
            && f.Conditions.OfType<LocalInterfaceCondition>().Any(c => c.Luid == Tunnel || c.Luid == SecondTunnel)).ToList();
        var expected = inputs.Policy.RangesFor(TunnelA).Count + (secondUp ? inputs.Policy.RangesFor(TunnelB).Count : 0);
        Assert.Equal(expected, tunnelGuards.Count);
        Assert.All(tunnelGuards, f =>
        {
            Assert.Equal(FilterGroup.Direct, f.Group);
            Assert.Equal(FilterAction.Block, f.Action);
            Assert.True(Assert.Single(f.Conditions.OfType<LocalInterfaceCondition>()).NotEqual);
        });
        Assert.Equal(FilterAction.Block, Evaluate(All(inputs), Tcp(SecondNetwork, 443, Tunnel)));
        Assert.Equal(secondUp ? FilterAction.Permit : FilterAction.Block, Evaluate(All(inputs), Tcp(SecondNetwork, 443, SecondTunnel)));
    }

    [Fact]
    public void AddressRule_BlocksWrongLiveTunnelAndPhysicalInterface()
    {
        var filters = All(Inputs(Tunnel, SecondTunnel));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(SecondNetwork, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Yandex, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(RemoteLan, 443, WiFi)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DirectDomain_OverridesSubnetAndUsesOnlyPrimary(bool secondUp)
    {
        var filters = All(Inputs(Tunnel, secondUp ? SecondTunnel : null, [new PinnedHost(SecondNetwork, RouteTarget.Direct)]));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(SecondNetwork, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(SecondNetwork, 53, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 53, WiFi)));
    }

    [Fact]
    public void Domain_OverridesAddressBlockAndOtherTunnelGuard()
    {
        var filters = All(Inputs(Tunnel, SecondTunnel,
            [new PinnedHost(BlockedByRule, RouteTarget.Tunnel(TunnelA)), new PinnedHost(SecondNetwork, RouteTarget.Tunnel(TunnelA))]));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(BlockedByRule, 443, Tunnel)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(SecondNetwork, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, SecondTunnel)));
    }

    [Fact]
    public void DirectDomain_StillObeysBlockAllOnOutage()
    {
        var inputs = Inputs(null, null, [new PinnedHost(SecondNetwork, RouteTarget.Direct)]);
        var filters = All(inputs with { OutageMode = OutageMode.BlockAllPublic });
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, WiFi)));
    }
}
