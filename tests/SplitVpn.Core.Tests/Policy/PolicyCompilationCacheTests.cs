using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

public sealed class PolicyCompilationCacheTests
{
    private static readonly Guid Tunnel = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");

    [Fact]
    public void PinChanges_ReuseAddressLayersAndPreserveInfrastructureAndOldSnapshot()
    {
        var cache = new PolicyCompilationCache();
        var input = Input();
        var first = cache.Compile(input);
        var cidrs = first.RouteCidrsFor(Tunnel);
        var nextInput = input with { PinnedHosts = [new(0x08080808, RouteTarget.Direct), new(0x01010101, RouteTarget.Blocked)] };
        var next = cache.Compile(nextInput);
        Assert.True(next.SharesAddressPolicy(first));
        Assert.Same(first.DirectRouteCidrs, next.DirectRouteCidrs);
        Assert.Same(cidrs, next.RouteCidrsFor(Tunnel));
        Assert.Equal(Decision.Direct, next.Classify(0x08080808).Decision);
        Assert.False(next.IsPinned(0x01010101)); // Сервер защищён от доменных правил.
        Assert.Empty(first.Pins);
        Equivalent(PolicyCompiler.Compile(nextInput), next);
        Assert.Empty(cache.Compile(input).Pins);
    }

    [Theory]
    [InlineData("default")]
    [InlineData("geo-target")]
    [InlineData("geo")]
    [InlineData("bypass-target")]
    [InlineData("bypass")]
    [InlineData("rules")]
    [InlineData("groups")]
    [InlineData("onlink")]
    [InlineData("servers")]
    [InlineData("dns")]
    [InlineData("networks")]
    [InlineData("hosts")]
    public void EveryAddressInputChange_InvalidatesCache(string changed)
    {
        var cache = new PolicyCompilationCache();
        var input = Input();
        var first = cache.Compile(input);
        var nextInput = changed switch
        {
            "default" => input with { DefaultTarget = RouteTarget.Direct },
            "geo-target" => input with { GeoTarget = RouteTarget.Blocked },
            "geo" => input with { Geo = RangeSet.From([Ipv4Cidr.Parse("8.0.0.0/8")]) },
            "bypass-target" => input with { BypassTarget = RouteTarget.Blocked },
            "bypass" => input with { Bypass = RangeSet.From([Ipv4Cidr.Parse("9.0.0.0/8")]) },
            "rules" => input with { Rules = [new(Ipv4Cidr.Parse("11.0.0.0/8"), RouteTarget.Blocked)] },
            "groups" => input with { Groups = [new(Guid.NewGuid(), [Tunnel])] },
            "onlink" => input with { OnLinePrefixes = [Ipv4Cidr.Parse("192.168.2.0/24")] },
            "servers" => input with { ServerAddresses = [0x02020202] },
            "dns" => input with { ServiceDnsAddresses = [0x08080404] },
            "networks" => input with { ServerNetworks = [new(RouteTarget.Tunnel(Tunnel), [Ipv4Cidr.Parse("10.0.0.0/8")])] },
            "hosts" => input with { TunnelHosts = [new(Tunnel, 0x0A000001)] },
            _ => throw new InvalidOperationException(),
        };
        var next = cache.Compile(nextInput);
        Assert.False(next.SharesAddressPolicy(first));
        Equivalent(PolicyCompiler.Compile(nextInput), next);
    }

    [Fact]
    public void MutableNestedCollections_DoNotMutateCachedKey()
    {
        var group = Guid.NewGuid();
        var members = new List<Guid> { Tunnel };
        var networks = new List<Ipv4Cidr> { Ipv4Cidr.Parse("10.1.0.0/16") };
        var input = Input() with
        {
            Groups = [new(group, members)],
            ServerNetworks = [new(RouteTarget.Group(group), networks)],
            PinnedHosts = [new(0x08080808, RouteTarget.Group(group))],
        };
        var cache = new PolicyCompilationCache();
        var first = cache.Compile(input);
        members.Clear();
        var second = cache.Compile(input);
        Assert.False(second.SharesAddressPolicy(first));
        Assert.Equal(RouteTarget.Group(group), Assert.Single(second.Pins).Target);
        networks.Add(Ipv4Cidr.Parse("10.2.0.0/16"));
        var third = cache.Compile(input);
        Assert.False(third.SharesAddressPolicy(second));
        Equivalent(PolicyCompiler.Compile(input), third);
    }

    private static PolicyInput Input() => new()
    {
        DefaultTarget = RouteTarget.Tunnel(Tunnel),
        ServerAddresses = [0x01010101],
        Geo = RangeSet.From([Ipv4Cidr.Parse("12.0.0.0/8")]),
    };

    private static void Equivalent(CompiledPolicy expected, CompiledPolicy actual)
    {
        Assert.Equal(expected.DirectRanges, actual.DirectRanges);
        Assert.Equal(expected.BlockRanges, actual.BlockRanges);
        Assert.Equal(expected.DirectRouteCidrs, actual.DirectRouteCidrs);
        Assert.Equal(expected.Pins, actual.Pins);
        Assert.Equal(expected.Tunnels, actual.Tunnels);
        foreach (var tunnel in expected.Tunnels)
        {
            Assert.Equal(expected.RangesFor(tunnel), actual.RangesFor(tunnel));
        }

        foreach (var address in new uint[] { 0x01010101, 0x08080808, 0x0A010001, 0x0B000001, 0x0C000001, 0xC0A80201 })
        {
            Assert.Equal(expected.Classify(address), actual.Classify(address));
        }
    }
}
