using System.Net;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Recovery;

namespace SplitVpn.Service.Tests;

/// <summary>Правила сброса DNS адаптера без записи в копии (экстренное отключение и «Восстановить сеть»).</summary>
public sealed class OrphanDnsTests
{
    [Theory]
    // Служба остановлена: всё, что выглядит нашим, сбрасывается, даже если порт 53 кто-то слушает.
    [InlineData("127.0.0.1", "", true, true, true, true, false)]
    [InlineData("127.0.0.1", "::1", true, true, true, true, true)]
    [InlineData("192.168.1.50,127.0.0.1", "", true, true, true, true, false)] // прежний адрес адаптера, уже не его
    [InlineData("10.0.0.7 127.0.0.1", "::1", true, false, false, true, true)]
    [InlineData("8.8.8.8", "", true, false, false, false, false)]
    [InlineData("", "", true, false, false, false, false)]
    [InlineData("127.0.0.1,8.8.8.8", "", true, false, false, false, false)] // loopback не последним — не наш набор
    // Служба работает: только если на 127.0.0.1:53 никто не слушает.
    [InlineData("127.0.0.1", "::1", false, true, true, false, false)]
    [InlineData("127.0.0.1", "::1", false, false, false, true, true)]
    [InlineData("127.0.0.1", "::1", false, false, true, true, true)] // ::1 уходит вместе с нашим IPv4
    // ::1 при не нашем IPv4: только если на [::1]:53 никто не слушает.
    [InlineData("8.8.8.8", "::1", true, false, false, false, true)]
    [InlineData("8.8.8.8", "::1", true, false, true, false, false)]
    [InlineData("8.8.8.8", "2001:4860:4860::8888", true, false, false, false, false)]
    public void Decide(string v4, string v6, bool serviceStopped, bool v4Listening, bool v6Listening, bool expectV4, bool expectV6)
    {
        var reset = OrphanDns.Decide(v4, v6, serviceStopped, v4Listening, v6Listening);

        Assert.Equal(expectV4, reset.V4);
        Assert.Equal(expectV6, reset.V6);
        Assert.Equal(expectV4 || expectV6, reset.Any);
    }

    [Fact]
    public void Decide_Ipv6Unreadable_TouchesOnlyIpv4()
    {
        var reset = OrphanDns.Decide("127.0.0.1", null, serviceStopped: true, v4Listening: false, v6Listening: false);

        Assert.True(reset.V4);
        Assert.False(reset.V6);
    }

    [Fact]
    public void SearchList_ClearedOnlyWhenEveryEntryIsOurs()
    {
        var backups = new[]
        {
            new InterfaceDnsBackup(Guid.NewGuid(), "", "", "", 0, DateTimeOffset.UnixEpoch, SearchList: "home.lan", AppliedSearchList: "home.lan,corp.example.com,vpn.example.net"),
            new InterfaceDnsBackup(Guid.NewGuid(), "", "", "", 0, DateTimeOffset.UnixEpoch, SearchList: "office.lan"),
        };
        var ours = OrphanDns.OurSuffixes(backups);

        Assert.Equal(["corp.example.com", "vpn.example.net"], ours.Order());
        Assert.True(OrphanDns.ShouldClearSearchList("CORP.example.com, vpn.example.net", ours));
        Assert.False(OrphanDns.ShouldClearSearchList("corp.example.com,home.lan", ours));
        Assert.False(OrphanDns.ShouldClearSearchList("", ours));
        Assert.False(OrphanDns.ShouldClearSearchList("corp.example.com", new HashSet<string>()));
    }

    [Theory]
    [InlineData("::1", 53, true)]
    [InlineData("::", 53, true)]
    [InlineData("127.0.0.1", 53, false)]
    [InlineData("::1", 5353, false)]
    public void Ipv6LoopbackListener(string address, int port, bool expected) =>
        Assert.Equal(expected, NetworkRecovery.ServesIpv6LoopbackResolver(new IPEndPoint(IPAddress.Parse(address), port)));
}
