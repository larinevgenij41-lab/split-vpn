using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Net;

public class Ipv4CidrTests
{
    [Theory]
    [InlineData("0.0.0.0/0", 0u, 0)]
    [InlineData("10.0.0.0/8", 0x0A000000u, 8)]
    [InlineData("203.0.113.20/32", 0xCB007114u, 32)]
    [InlineData("203.0.113.20", 0xCB007114u, 32)]
    public void TryParse_AcceptsValidSubnets(string text, uint network, int prefix)
    {
        Assert.True(Ipv4Cidr.TryParse(text, out var cidr));
        Assert.Equal(network, cidr.Network);
        Assert.Equal(prefix, cidr.PrefixLength);
    }

    [Theory]
    [InlineData("10.0.0.1/8")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0/8")]
    [InlineData("1.2")]
    [InlineData("2001:db8::/32")]
    [InlineData("")]
    [InlineData("garbage")]
    public void TryParse_RejectsInvalid(string text)
    {
        Assert.False(Ipv4Cidr.TryParse(text, out _));
    }

    [Fact]
    public void HasHostBits_DetectsNonZeroHostPart()
    {
        Assert.True(Ipv4Cidr.HasHostBits("192.168.1.1/24"));
        Assert.False(Ipv4Cidr.HasHostBits("192.168.1.0/24"));
    }

    [Fact]
    public void Range_CoversWholeSubnet()
    {
        var cidr = Ipv4Cidr.Parse("192.168.1.0/24");

        Assert.Equal("192.168.1.0-192.168.1.255", cidr.ToRange().ToString());
        Assert.True(cidr.Contains(Ipv4.Parse("192.168.1.200")));
        Assert.False(cidr.Contains(Ipv4.Parse("192.168.2.0")));
    }
}
