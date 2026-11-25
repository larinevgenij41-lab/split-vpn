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
    public void DirectDomain_OverridesDefaultTunnelAndUsesOnlyPrimary(bool secondUp)
    {
        var filters = All(Inputs(Tunnel, secondUp ? SecondTunnel : null, [new PinnedHost(Cloudflare, RouteTarget.Direct)]));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(Cloudflare, 53, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 53, WiFi)));
    }

    /// <summary>
    /// Итерация 12: закрепление «напрямую» не выводит из VPN адрес, который ручное правило направило в туннель:
    /// закрепление не принимается, адрес идёт по правилу.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DirectDomain_DoesNotOverrideUserRuleIntoTunnel(bool secondUp)
    {
        var inputs = Inputs(Tunnel, secondUp ? SecondTunnel : null, [new PinnedHost(SecondNetwork, RouteTarget.Direct)]);
        var filters = All(inputs);

        Assert.Empty(inputs.Policy.Pins);
        var rejected = Assert.Single(inputs.Policy.RejectedPins);
        Assert.Equal(SecondNetwork, rejected.Address);
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, Tunnel)));
        Assert.Equal(secondUp ? FilterAction.Permit : FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, SecondTunnel)));
    }

    /// <summary>
    /// Итерация 12: запрет пользователя сильнее закрепления по домену (ответ DNS выбирает сервер имён), а закрепление в
    /// туннель поверх правила в другой туннель по-прежнему действует и держит адрес только в своём туннеле.
    /// </summary>
    [Fact]
    public void UserBlock_WinsOverDomain_ButDomainOverridesOtherTunnelGuard()
    {
        var inputs = Inputs(Tunnel, SecondTunnel,
            [new PinnedHost(BlockedByRule, RouteTarget.Tunnel(TunnelA)), new PinnedHost(SecondNetwork, RouteTarget.Tunnel(TunnelA))]);
        var filters = All(inputs);
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(BlockedByRule, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(BlockedByRule, 443, WiFi)));
        Assert.Equal(Decision.Block, inputs.Policy.Classify(BlockedByRule).Decision);
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(SecondNetwork, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, SecondTunnel)));
    }

    [Fact]
    public void DirectDomain_StillObeysBlockAllOnOutage()
    {
        var inputs = Inputs(null, null, [new PinnedHost(Cloudflare, RouteTarget.Direct)]);
        var filters = All(inputs with { OutageMode = OutageMode.BlockAllPublic });
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 443, WiFi)));
    }
}
