using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;

namespace SplitVpn.Core.Tests.Protection;

public sealed class FilterPlanCacheTests
{
    [Fact]
    public void PinsOnly_ReuseLargePlanButUpdateDynamic()
    {
        var tunnel = Guid.NewGuid();
        var policyCache = new PolicyCompilationCache();
        var input = new PolicyInput { DefaultTarget = RouteTarget.Tunnel(tunnel) };
        var cache = new FilterPlanCache();
        var protection = new ProtectionInputs
        {
            Policy = policyCache.Compile(input), PrimaryLuid = 8,
            Tunnels = [new() { Id = tunnel, Luid = 9 }],
        };
        var first = cache.Build(protection);
        var nextInput = protection with
        {
            Policy = policyCache.Compile(input with { PinnedHosts = [new(0x08080808, RouteTarget.Direct)] }),
        };
        var next = cache.Build(nextInput);
        Assert.Same(first[FilterGroup.Base], next[FilterGroup.Base]);
        Assert.Same(first[FilterGroup.Direct], next[FilterGroup.Direct]);
        Assert.NotEmpty(next[FilterGroup.Dynamic]);
        Assert.True(next[FilterGroup.Dynamic].SequenceEqual(FilterPlanBuilder.BuildDynamic(nextInput), FilterSpecComparer.Instance));
    }

    [Theory]
    [InlineData("primary")]
    [InlineData("tunnel-luid")]
    [InlineData("tunnel-down")]
    [InlineData("tunnel-name")]
    [InlineData("policy")]
    public void DirectDependencies_InvalidatePlan(string changed)
    {
        var tunnel = new TunnelInput { Id = Guid.NewGuid(), Name = "first", Luid = 9 };
        var inputs = new ProtectionInputs
        {
            Policy = PolicyCompiler.Compile(new PolicyInput()), PrimaryLuid = 8, Tunnels = [tunnel],
        };
        var cache = new FilterPlanCache();
        var first = cache.Build(inputs);
        var nextInputs = changed switch
        {
            "primary" => inputs with { PrimaryLuid = 10 },
            "tunnel-luid" => inputs with { Tunnels = [tunnel with { Luid = 10 }] },
            "tunnel-down" => inputs with { Tunnels = [tunnel with { Luid = null }] },
            "tunnel-name" => inputs with { Tunnels = [tunnel with { Name = "second" }] },
            "policy" => inputs with { Policy = PolicyCompiler.Compile(new PolicyInput { DefaultTarget = RouteTarget.Blocked }) },
            _ => throw new InvalidOperationException(),
        };
        var next = cache.Build(nextInputs);
        Assert.NotSame(first[FilterGroup.Direct], next[FilterGroup.Direct]);
        Assert.True(next[FilterGroup.Direct].SequenceEqual(FilterPlanBuilder.BuildDirect(nextInputs), FilterSpecComparer.Instance));
    }

    [Fact]
    public void LocalAccessChange_RebuildsBaseWithoutRebuildingDirect()
    {
        var cache = new FilterPlanCache();
        var inputs = new ProtectionInputs { Policy = PolicyCompiler.Compile(new PolicyInput()) };
        var first = cache.Build(inputs);
        var next = cache.Build(inputs with { LocalAccess = false });
        Assert.Same(first[FilterGroup.Direct], next[FilterGroup.Direct]);
        Assert.NotSame(first[FilterGroup.Base], next[FilterGroup.Base]);
        Assert.True(next[FilterGroup.Base].SequenceEqual(FilterPlanBuilder.BuildBase(inputs with { LocalAccess = false }), FilterSpecComparer.Instance));
    }
}
