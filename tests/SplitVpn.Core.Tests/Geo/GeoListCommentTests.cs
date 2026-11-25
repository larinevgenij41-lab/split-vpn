using SplitVpn.Core.Geo;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Geo;

/// <summary>Комментарий в конце строки списка подсетей — пояснение, а не ошибка разбора всего списка.</summary>
public sealed class GeoListCommentTests
{
    [Fact]
    public void TrailingHashComment_IsIgnored()
    {
        var result = GeoListParser.Parse("1.2.3.0/24 # x\r\n");

        Assert.Equal(0, result.ErrorCount);
        Assert.Equal(Ipv4Cidr.Parse("1.2.3.0/24"), Assert.Single(result.V4));
    }

    [Theory]
    [InlineData("5.6.0.0/16 ; SBL123")]
    [InlineData("5.6.0.0/16// заметка")]
    [InlineData("5.6.0.0/16\t# RU")]
    [InlineData("5.6.0.0/16#RU")]
    public void OtherTrailingComments_AreIgnored(string line)
    {
        var result = GeoListParser.Parse(line + "\n2a00:1450::/32 # IPv6\n");

        Assert.Equal(0, result.ErrorCount);
        Assert.Equal(Ipv4Cidr.Parse("5.6.0.0/16"), Assert.Single(result.V4));
        Assert.Single(result.V6);
    }

    [Fact]
    public void BadAddressBeforeComment_IsStillAnError()
    {
        var result = GeoListParser.Parse("1.2.3.4/24 # биты хоста\n");

        Assert.Equal(1, result.ErrorCount);
    }
}
