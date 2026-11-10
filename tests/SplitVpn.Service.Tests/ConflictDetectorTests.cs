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

    private static readonly Guid ByAddressId = Guid.NewGuid();

    /// <summary>Сервер профиля задан IP-адресом, туннеля ещё не было: известных разрешённых адресов нет.</summary>
    private static readonly ConflictServer[] ByAddress = [new("Niderland", "5.129.236.106", [], ByAddressId)];

    private static IReadOnlyList<uint> Resolve(string host) => host.ToUpperInvariant() switch
    {
        "NL.EXAMPLE.COM" or "VPN.EXAMPLE.COM" => [Ipv4.Parse("5.129.236.106")],
        "OTHER.EXAMPLE.COM" => [Ipv4.Parse("198.51.100.1")],
        _ => [],
    };

    [Theory]
    [InlineData("vpn.example.com")]
    [InlineData("vpn.example.com:4443")]
    public void SameServer_ForeignNameResolvesToProfileAddress_IsMatched(string foreign)
    {
        Assert.Equal("Niderland", ConflictDetector.SameServer(foreign, ByAddress, Resolve)?.ProfileName);
    }

    [Fact]
    public void SameServer_TwoNamesOfOneServer_AreMatchedByResolution()
    {
        ConflictServer[] servers = [new("Niderland", "nl.example.com", [])];

        Assert.Equal("Niderland", ConflictDetector.SameServer("vpn.example.com", servers, Resolve)?.ProfileName);
    }

    [Fact]
    public void SameServer_NameOfOtherServer_IsNotMatched()
    {
        Assert.Null(ConflictDetector.SameServer("other.example.com", ByAddress, Resolve));
    }

    [Fact]
    public void SameServer_WithoutResolver_NameIsNotComparedByAddress()
    {
        Assert.Null(ConflictDetector.SameServer("vpn.example.com", ByAddress));
    }

    [Fact]
    public void Warning_SameServer_CarriesProfileId()
    {
        var warning = ConflictDetector.ForeignConnectionWarning("SSTP NL", "vpn.example.com", ByAddress, Resolve);

        Assert.Equal(ByAddressId, warning.SameServerProfileId);
    }

    [Fact]
    public void Warning_OtherServer_HasNoProfileId()
    {
        Assert.Null(ConflictDetector.ForeignConnectionWarning("SSTP USA", "other.example.com", ByAddress, Resolve).SameServerProfileId);
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
