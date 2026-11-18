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
    [InlineData("5.129.236.106:4443")]
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
    public void SharedHostingAndDifferentNames_DoesNotHangUpForeignConnection()
    {
        var servers = new[] { new ConflictServer("Work", "nl.example.com", Resolve("nl.example.com"), HangUpForeign: true) };
        var hungUp = false;
        var warning = ConflictDetector.ForeignConnectionWarning("Other", "vpn.example.com", servers, Resolve,
            hangUp: () => { hungUp = true; return null; });
        Assert.False(hungUp);
        Assert.Equal("foreign-vpn", warning.Code);
    }

    [Fact]
    public void Warning_SameServer_NamesBothConnectionsAndAdvice()
    {
        var warning = ConflictDetector.ForeignConnectionWarning("SSTP Niderland", "5.129.236.106:443", Servers);

        Assert.Equal("foreign-vpn", warning.Code);
        Assert.Equal("SSTP Niderland", warning.Subject);
        Assert.Contains("к тому же серверу, что и «Niderland»", warning.Text, StringComparison.Ordinal);
        Assert.Contains("Отключите «SSTP Niderland»", warning.Text, StringComparison.Ordinal);
    }

    /// <summary>Служба держит «Niderland» поднятым: чужое подключение к тому же серверу разрывается.</summary>
    private static readonly ConflictServer[] Held = [new("Niderland", "5.129.236.106", [Ipv4.Parse("5.129.236.106")], HangUpForeign: true)];

    [Fact]
    public void Warning_SameServerWhileHeld_HangsUpAndNamesOwner()
    {
        var calls = 0;

        var warning = ConflictDetector.ForeignConnectionWarning("IKEv2 VPN 5.129.236.106", "5.129.236.106", Held, owner: "xbox2",
            hangUp: () => { calls++; return null; });

        Assert.Equal(1, calls);
        Assert.StartsWith("Разорвано VPN-подключение Windows «IKEv2 VPN 5.129.236.106» пользователя Windows xbox2 к тому же серверу, что и «Niderland»",
            warning.Text, StringComparison.Ordinal);
        Assert.Contains("под пользователем xbox2.", warning.Text, StringComparison.Ordinal);
        Assert.Equal("foreign-vpn", warning.Code);
    }

    [Fact]
    public void Warning_SameServerWhileHeld_HangUpFailure_IsReported()
    {
        var warning = ConflictDetector.ForeignConnectionWarning("IKEv2 VPN", "5.129.236.106", Held, hangUp: () => "отказано в доступе");

        Assert.StartsWith("Активно VPN-подключение Windows «IKEv2 VPN»", warning.Text, StringComparison.Ordinal);
        Assert.EndsWith("Служба не смогла разорвать его: отказано в доступе", warning.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Warning_SameServerNotHeld_IsNotHungUp()
    {
        var calls = 0;

        var warning = ConflictDetector.ForeignConnectionWarning("IKEv2 VPN", "5.129.236.106", Servers, hangUp: () => { calls++; return null; });

        Assert.Equal(0, calls);
        Assert.StartsWith("Активно VPN-подключение Windows «IKEv2 VPN»", warning.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("не смогла", warning.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Два профиля службы к одному серверу: положенный «Work SSTP» стоит в списке раньше поднятого «Work IKEv2».
    /// Разрыв и текст предупреждения идут от поднятого.
    /// </summary>
    [Fact]
    public void Warning_TwoProfilesOfOneServer_PrefersHeldOne()
    {
        var heldId = Guid.NewGuid();
        ConflictServer[] servers =
        [
            new("Work SSTP", "5.129.236.106", [Ipv4.Parse("5.129.236.106")], Guid.NewGuid(), HangUpForeign: false),
            new("Work IKEv2", "5.129.236.106", [Ipv4.Parse("5.129.236.106")], heldId, HangUpForeign: true),
        ];
        var calls = 0;

        var warning = ConflictDetector.ForeignConnectionWarning("IKEv2 VPN", "5.129.236.106", servers, hangUp: () => { calls++; return null; });

        Assert.Equal(1, calls);
        Assert.Contains("что и «Work IKEv2»", warning.Text, StringComparison.Ordinal);
        Assert.Equal(heldId, warning.SameServerProfileId);
    }

    /// <summary>Совпадение по имени с положенным профилем не отменяет совпадения по адресу с поднятым.</summary>
    [Fact]
    public void SameServer_NameMatchNotHeld_AddressMatchHeld_PrefersHeld()
    {
        ConflictServer[] servers =
        [
            new("Work SSTP", "vpn.example.com", [], HangUpForeign: false),
            new("Work IKEv2", "5.129.236.106", [Ipv4.Parse("5.129.236.106")], HangUpForeign: true),
        ];

        Assert.Equal("Work IKEv2", ConflictDetector.SameServer("vpn.example.com", servers, Resolve)?.ProfileName);
    }

    [Fact]
    public void SameServer_TwoProfilesNoneHeld_ReturnsFirst()
    {
        ConflictServer[] servers =
        [
            new("Work SSTP", "5.129.236.106", [Ipv4.Parse("5.129.236.106")]),
            new("Work IKEv2", "5.129.236.106", [Ipv4.Parse("5.129.236.106")]),
        ];

        Assert.Equal("Work SSTP", ConflictDetector.SameServer("5.129.236.106", servers)?.ProfileName);
    }

    /// <summary>
    /// Ни один профиль не держит подключение (например, намерение «Отключено»): совпадение по имени находится сразу,
    /// и ни чужое имя, ни имена других серверов не разрешаются - медленные разрешения не тянут проверку к пределу.
    /// </summary>
    [Fact]
    public void SameServer_NoneHeld_NameMatch_DoesNotResolve()
    {
        ConflictServer[] servers =
        [
            new("Work SSTP", "vpn.example.com", []),
            new("Work IKEv2", "nl.example.com", []),
            new("Home", "home.example.com", []),
        ];
        var resolved = new List<string>();

        var same = ConflictDetector.SameServer("vpn.example.com", servers, host => { resolved.Add(host); return Resolve(host); });

        Assert.Equal("Work SSTP", same?.ProfileName);
        Assert.Empty(resolved);
    }

    /// <summary>Ни один профиль не держит подключение: по адресу берётся первый совпавший, остальные имена не разрешаются.</summary>
    [Fact]
    public void SameServer_NoneHeld_AddressMatch_StopsAtFirst()
    {
        ConflictServer[] servers =
        [
            new("Niderland", "5.129.236.106", []),
            new("Home", "home.example.com", []),
        ];
        var resolved = new List<string>();

        var same = ConflictDetector.SameServer("vpn.example.com", servers, host => { resolved.Add(host); return Resolve(host); });

        Assert.Equal("Niderland", same?.ProfileName);
        Assert.Equal("vpn.example.com", Assert.Single(resolved));
    }

    /// <summary>Проверка брошена координатором или устарела (VPN уже отключён): чужое подключение не разрывается даже по снимку «держит».</summary>
    [Fact]
    public void Warning_SameServerWhileHeld_OutdatedCheck_IsNotHungUp()
    {
        var calls = 0;

        var warning = ConflictDetector.ForeignConnectionWarning("IKEv2 VPN", "5.129.236.106", Held,
            hangUp: () => { calls++; return null; }, stillCurrent: () => false);

        Assert.Equal(0, calls);
        Assert.StartsWith("Активно VPN-подключение Windows «IKEv2 VPN»", warning.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("не смогла", warning.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Warning_SameServerWhileHeld_CurrentCheck_HangsUp()
    {
        var calls = 0;

        ConflictDetector.ForeignConnectionWarning("IKEv2 VPN", "5.129.236.106", Held, hangUp: () => { calls++; return null; }, stillCurrent: () => true);

        Assert.Equal(1, calls);
    }

    [Fact]
    public void Warning_OtherServerWhileHeld_IsNotHungUp()
    {
        var calls = 0;

        var warning = ConflictDetector.ForeignConnectionWarning("SSTP USA", "usa.bc39.ru:4443", Held, owner: "xbox2", hangUp: () => { calls++; return null; });

        Assert.Equal(0, calls);
        Assert.Equal("Активно другое VPN-подключение «SSTP USA» пользователя Windows xbox2: его маршруты и DNS могут перехватывать трафик.", warning.Text);
    }

    [Theory]
    [InlineData(@"C:\Users\xbox2\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk", "xbox2")]
    [InlineData(@"D:\Profiles\Иван Петров\appdata\roaming\microsoft\network\connections\pbk\RASPHONE.PBK", "Иван Петров")]
    [InlineData(@"C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk", null)]
    [InlineData(@"C:\ProgramData\SplitVpn\splitvpn.pbk", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void PhonebookOwner_IsProfileFolderOfUserPhonebook(string? phonebook, string? owner)
    {
        Assert.Equal(owner, ConflictDetector.PhonebookOwner(phonebook));
    }

    [Fact]
    public void Warning_OtherServer_KeepsGeneralText()
    {
        var warning = ConflictDetector.ForeignConnectionWarning("SSTP USA", "usa.bc39.ru:4443", Servers);

        Assert.Equal("Активно другое VPN-подключение «SSTP USA»: его маршруты и DNS могут перехватывать трафик.", warning.Text);
        Assert.Equal("SSTP USA", warning.Subject);
    }
}
