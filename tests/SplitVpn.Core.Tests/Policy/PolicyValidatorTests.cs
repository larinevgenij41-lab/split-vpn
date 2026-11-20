using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

public class PolicyValidatorTests
{
    private static readonly Guid Tunnel = new("aaaaaaaa-0000-0000-0000-000000000001");

    [Fact]
    public void SamePrefixWithDifferentTargets_IsError()
    {
        var result = PolicyValidator.ValidateRules(
            [new UserRule(Ipv4Cidr.Parse("1.2.3.0/24"), RouteTarget.Direct), new UserRule(Ipv4Cidr.Parse("1.2.3.0/24"), RouteTarget.Tunnel(Tunnel))],
            []);

        Assert.False(result.IsValid);
        Assert.Contains("противоречащие", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void SamePrefixWithSameTarget_IsAllowed()
    {
        var result = PolicyValidator.ValidateRules(
            [new UserRule(Ipv4Cidr.Parse("1.2.3.0/24"), RouteTarget.Direct), new UserRule(Ipv4Cidr.Parse("1.2.3.0/24"), RouteTarget.Direct)],
            []);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void WholeInternetRule_IsError()
    {
        var result = PolicyValidator.ValidateRules([new UserRule(Ipv4Cidr.Parse("0.0.0.0/0"), RouteTarget.Direct)], []);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void RuleOverlappingServiceAddress_IsWarning()
    {
        var result = PolicyValidator.ValidateRules(
            [new UserRule(Ipv4Cidr.Parse("185.199.108.0/24"), RouteTarget.Blocked)],
            [Ipv4.Parse("185.199.108.20")]);

        Assert.True(result.IsValid);
        Assert.Single(result.Warnings);
    }

    [Theory]
    [InlineData("198.18.0.0/15")]
    [InlineData("203.0.113.0/24")]
    [InlineData("240.0.0.0/8")]
    public void RuleOverlappingReservedRange_IsWarning(string cidr)
    {
        var result = PolicyValidator.ValidateRules([new UserRule(Ipv4Cidr.Parse(cidr), RouteTarget.Tunnel(Tunnel))], []);

        Assert.True(result.IsValid);
        Assert.Contains("зарезервированными", Assert.Single(result.Warnings), StringComparison.Ordinal);
    }

    [Fact]
    public void PrivateNetworkRule_IsNotWarned()
    {
        var result = PolicyValidator.ValidateRules([new UserRule(Ipv4Cidr.Parse("192.168.100.0/24"), RouteTarget.Tunnel(Tunnel))], []);

        Assert.True(result.IsValid);
        Assert.Empty(result.Warnings);
    }

    [Theory]
    [InlineData("169.254.0.0/16")]
    [InlineData("224.0.0.0/8")]
    [InlineData("127.0.0.0/8")]
    public void LinkScopeOrLoopbackRule_IsWarning(string cidr)
    {
        var result = PolicyValidator.ValidateRules([new UserRule(Ipv4Cidr.Parse(cidr), RouteTarget.Tunnel(Tunnel))], []);

        Assert.True(result.IsValid);
        Assert.Contains("правило не действует", Assert.Single(result.Warnings), StringComparison.Ordinal);
    }
}
