using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed class InterfaceDnsCaptureTests
{
    [Theory]
    [InlineData("127.0.0.1", null, "127.0.0.1")]
    [InlineData("::1", null, "::1")]
    [InlineData("127.0.0.1", "", "")]
    [InlineData("127.0.0.1", "192.0.2.53", "192.0.2.53")]
    [InlineData("192.0.2.1", "192.0.2.53", "192.0.2.1")]
    public void Original_TreatsLoopbackAsOursOnlyWithPreviousBackup(string current, string? previous, string expected)
    {
        // Без копии loopback — свой резолвер пользователя: он должен вернуться после отключения, а не смениться на DHCP.
        Assert.Equal(expected, InterfaceDnsOps.Original(current, previous));
    }

    [Theory]
    [InlineData("::1", null, true, "")]
    [InlineData("::1", null, false, "::1")]
    [InlineData("::1", "2001:db8::53", true, "2001:db8::53")]
    [InlineData("2001:db8::1", null, true, "2001:db8::1")]
    [InlineData("", null, true, "")]
    public void OriginalV6_DropsOwnLoopbackLeftFromPreviousRun(string current, string? previous, bool ownsIpv6Loopback, string expected)
    {
        // Посредник держит [::1]:53 — чужого резолвера там нет, ::1 на адаптере остался от прежнего запуска.
        Assert.Equal(expected, InterfaceDnsOps.OriginalV6(current, previous, ownsIpv6Loopback));
    }

    [Theory]
    [InlineData("127.0.0.1", "", true)]
    [InlineData("127.0.0.1", "::1", true)]
    [InlineData("127.0.0.1,127.0.0.1", "::1", true)]
    [InlineData("127.0.0.1 192.0.2.53", "", false)]
    [InlineData("127.0.0.1", "2001:db8::53", false)]
    [InlineData("127.0.0.1", "::1,2001:db8::53", false)]
    [InlineData("::1", "::1", false)]
    [InlineData("", "", false)]
    public void IsOnlyProxyLoopback_MatchesExactlyTheProxySet(string v4, string v6, bool expected)
    {
        Assert.Equal(expected, InterfaceDnsOps.IsOnlyProxyLoopback(v4, v6));
    }
}
