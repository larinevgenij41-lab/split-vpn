using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Net;

public class ServerAddressTests
{
    [Theory]
    [InlineData("203.0.113.10:4443", "203.0.113.10", 4443, true, "203.0.113.10:4443")]
    [InlineData("330399.fornex.cloud", "330399.fornex.cloud", 443, false, "330399.fornex.cloud")]
    [InlineData(" vpn.example.com:443 ", "vpn.example.com", 443, false, "vpn.example.com")]
    public void Parse_AcceptsHostAndOptionalPort(string text, string host, int port, bool isIp, string phonebook)
    {
        var address = ServerAddress.Parse(text);

        Assert.Equal(host, address.Host);
        Assert.Equal(port, address.Port);
        Assert.Equal(isIp, address.IsIpLiteral);
        Assert.Equal(phonebook, address.ForPhonebook);
    }

    [Theory]
    [InlineData("")]
    [InlineData("host:0")]
    [InlineData("host:70000")]
    [InlineData("bad host:443")]
    [InlineData(":443")]
    public void Parse_RejectsInvalid(string text)
    {
        Assert.False(ServerAddress.TryParse(text, out _));
    }
}
