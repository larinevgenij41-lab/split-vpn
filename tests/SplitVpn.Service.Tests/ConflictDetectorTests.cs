using SplitVpn.Core.Net;
using SplitVpn.Windows.Diagnostics;

namespace SplitVpn.Service.Tests;

/// <summary>Чужое подключение Windows к тому же серверу, что и подключение службы.</summary>
public sealed class ConflictDetectorTests
{
    private static readonly ConflictServer[] Servers =
    [
        new("Niderland", "5.129.236.106", [Ipv4.Parse("5.129.236.106")]),
        new("Home", "kgd-keen.netcraze.club", [Ipv4.Parse("203.0.113.7")]),
    ];

    [Theory]
    [InlineData("5.129.236.106:4443", "Niderland")]
    [InlineData("5.129.236.106", "Niderland")]
    [InlineData("KGD-KEEN.netcraze.club.", "Home")]
    [InlineData("kgd-keen.netcraze.club:443", "Home")]
    [InlineData("203.0.113.7", "Home")]
    public void SameServer_MatchesByHostOrResolvedAddress(string foreign, string profile)
    {
        Assert.Equal(profile, ConflictDetector.SameServer(foreign, Servers)?.ProfileName);
    }

    [Theory]
    [InlineData("usa.bc39.ru:4443")]
    [InlineData("198.51.100.1")]
    [InlineData("")]
    [InlineData(null)]
    public void SameServer_OtherServer_IsNotMatched(string? foreign)
    {
        Assert.Null(ConflictDetector.SameServer(foreign, Servers));
    }

    [Fact]
    public void Warning_SameServer_NamesBothConnectionsAndAdvice()
    {
        var warning = ConflictDetector.ForeignConnectionWarning("SSTP Niderland", "5.129.236.106:4443", Servers);

        Assert.Equal("foreign-vpn", warning.Code);
        Assert.Equal("SSTP Niderland", warning.Subject);
        Assert.Contains("к тому же серверу, что и «Niderland»", warning.Text, StringComparison.Ordinal);
        Assert.Contains("Отключите «SSTP Niderland»", warning.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Warning_OtherServer_KeepsGeneralText()
    {
        var warning = ConflictDetector.ForeignConnectionWarning("SSTP USA", "usa.bc39.ru:4443", Servers);

        Assert.Equal("Активно другое VPN-подключение «SSTP USA»: его маршруты и DNS могут перехватывать трафик.", warning.Text);
        Assert.Equal("SSTP USA", warning.Subject);
    }
}
