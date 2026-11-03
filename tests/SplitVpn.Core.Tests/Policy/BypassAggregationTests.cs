using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Policy;

/// <summary>
/// Свёртка списка обхода до подсетей: одиночные адреса дают одну подсеть вместо десятков маршрутов и фильтров,
/// но адреса RU-базы, которых в списке нет, остаются при своём решении.
/// </summary>
public class BypassAggregationTests
{
    private static RangeSet Set(params string[] cidrs) => RangeSet.From(cidrs.Select(Ipv4Cidr.Parse));

    [Fact]
    public void SingleAddressesInOneSubnet_BecomeOneRange()
    {
        var result = BypassAggregation.Aggregate(Set("8.8.8.8/32", "8.8.8.200/32", "8.8.9.1/32"), RangeSet.Empty, 24);

        Assert.Equal(Set("8.8.8.0/23"), result);
    }

    [Fact]
    public void Prefix22_FoldsNeighbouringSubnets()
    {
        var result = BypassAggregation.Aggregate(Set("8.8.8.8/32", "8.8.11.1/32"), RangeSet.Empty, 22);

        Assert.Equal(Set("8.8.8.0/22"), result);
    }

    [Fact]
    public void RussianAddressesOutsideTheList_AreNotTaken()
    {
        var geo = Set("77.88.8.128/25");
        var result = BypassAggregation.Aggregate(Set("77.88.8.8/32", "77.88.8.200/32"), geo, 24);

        Assert.True(result.Contains(Ipv4.Parse("77.88.8.8")));
        Assert.True(result.Contains(Ipv4.Parse("77.88.8.100")));
        // Адрес самого списка в RU-базе остаётся в обходе, соседние российские — нет.
        Assert.True(result.Contains(Ipv4.Parse("77.88.8.200")));
        Assert.False(result.Contains(Ipv4.Parse("77.88.8.201")));
        Assert.False(result.Contains(Ipv4.Parse("77.88.8.129")));
    }

    [Fact]
    public void Off_ReturnsListUnchanged()
    {
        var bypass = Set("8.8.8.8/32");

        Assert.Same(bypass, BypassAggregation.Aggregate(bypass, RangeSet.Empty, BypassAggregation.Off));
    }

    [Fact]
    public void WideRanges_AreNotNarrowed()
    {
        var result = BypassAggregation.Aggregate(Set("10.0.0.0/8", "8.8.8.8/32"), RangeSet.Empty, 24);

        Assert.Equal(Set("10.0.0.0/8", "8.8.8.0/24"), result);
    }

    [Fact]
    public void PolicyKeepsUserRuleOverFoldedSubnet()
    {
        var tunnel = RouteTarget.Tunnel(new Guid("aaaaaaaa-0000-0000-0000-000000000001"));
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Direct,
            BypassTarget = tunnel,
            Bypass = BypassAggregation.Aggregate(Set("8.8.8.8/32"), RangeSet.Empty, 24),
            Rules = [new UserRule(Ipv4Cidr.Parse("8.8.8.100/32"), RouteTarget.Direct)],
        });

        Assert.Equal(Decision.Vpn, policy.Classify(Ipv4.Parse("8.8.8.50")).Decision);
        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("8.8.8.100")).Decision);
    }

    [Theory]
    [InlineData(19, false)]
    [InlineData(20, true)]
    [InlineData(24, true)]
    [InlineData(32, true)]
    [InlineData(33, false)]
    public void Validator_LimitsPrefix(int prefix, bool valid)
    {
        var result = SettingsValidator.Validate(new AppSettings { BypassAggregatePrefix = prefix });

        Assert.Equal(valid, !result.Errors.Any(e => e.Contains("Свёртка списка обхода", StringComparison.Ordinal)));
    }

    [Fact]
    public void OldSettingsFile_GetsDefaultPrefix()
    {
        var json = System.Text.Json.Nodes.JsonNode.Parse(SettingsSerializer.Serialize(new AppSettings { BypassAggregatePrefix = 22 }))!.AsObject();
        Assert.True(json.Remove("bypassAggregatePrefix"));

        var loaded = SettingsSerializer.Deserialize(json.ToJsonString());

        Assert.Equal(BypassAggregation.DefaultPrefix, Assert.IsType<AppSettings>(loaded.Settings).BypassAggregatePrefix);
    }
}
