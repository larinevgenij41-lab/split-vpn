using SplitVpn.Core.Net;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Чистая логика слоя вызовов ОС без самих вызовов: трактовка кодов RAS, рост буферов перечисления, разбор телефонной
/// книги в том виде, в каком её пишет Windows, порядок байтов адресов и разбор списков DNS из реестра.
/// </summary>
public sealed class WindowsInteropParsingTests
{
    private const string Policy = "020000000400000003000000060000000300000000000000";

    [Theory]
    [InlineData(0u)] // ERROR_SUCCESS
    [InlineData(6u)] // ERROR_INVALID_HANDLE: дескриптор уже освобождён
    [InlineData(617u)] // ERROR_ALREADY_DISCONNECTING
    [InlineData(618u)] // ERROR_PORT_NOT_OPEN
    [InlineData(619u)] // ERROR_PORT_DISCONNECTED
    [InlineData(668u)] // ERROR_NO_CONNECTION
    [InlineData(711u)] // ERROR_RASMAN_CANNOT_INITIALIZE: соединений RasMan больше нет
    [InlineData(1058u)] // ERROR_SERVICE_DISABLED
    [InlineData(1062u)] // ERROR_SERVICE_NOT_ACTIVE
    [InlineData(1068u)] // ERROR_SERVICE_DEPENDENCY_FAIL
    public void HangUpCodesMeaningNothingLeftToDisconnect(uint code) => Assert.True(RasClient.AlreadyGone(code));

    [Theory]
    [InlineData(5u)] // ERROR_ACCESS_DENIED - настоящий отказ
    [InlineData(1168u)] // ERROR_NOT_FOUND
    [InlineData(1722u)] // RPC_S_SERVER_UNAVAILABLE: RasMan перезапускается, судьба соединения неизвестна
    [InlineData(1460u)] // ERROR_TIMEOUT
    [InlineData(603u)] // ERROR_BUFFER_TOO_SMALL
    public void HangUpFailuresAreNotSwallowed(uint code) => Assert.False(RasClient.AlreadyGone(code));

    [Fact]
    public void RasAndRpcUnavailabilityCodesAreDisjoint()
    {
        uint[] ras = [711, 1058, 1062, 1068];
        uint[] rpc = [1722, 1726, 1727];
        Assert.All(ras, c => Assert.True(RasClient.RasUnavailable(c) && !RasClient.RpcUnavailable(c)));
        Assert.All(rpc, c => Assert.True(RasClient.RpcUnavailable(c) && !RasClient.RasUnavailable(c)));
        Assert.False(RasClient.RasUnavailable(0));
        Assert.False(RasClient.RpcUnavailable(0));
    }

    [Theory]
    [InlineData(4, 10u * 100, 100, 11)] // RAS просит 10 элементов: с запасом в один
    [InlineData(4, 4u * 100, 100, 5)] // просит прежний размер: всё равно растём, иначе повтор по кругу
    [InlineData(4, 0u, 100, 5)] // размер не сообщён
    [InlineData(4, 150u, 100, 5)] // некратный размер округляется вниз и получает запас
    public void EnumerationBufferAlwaysGrows(int current, uint required, int element, int expected) =>
        Assert.Equal(expected, RasClient.GrowCapacity(current, required, element));

    [Fact]
    public void EnumerationBufferGrowthCannotOverflowTheByteSize()
    {
        var capacity = RasClient.GrowCapacity(4, uint.MaxValue, 1500);
        Assert.True((long)capacity * 1500 <= int.MaxValue);
        Assert.True(capacity > 4);
    }

    /// <summary>Раздел записи IKEv2 в том порядке, в котором его пишет Windows 10/11 (сокращено до значимых строк).</summary>
    private static string WindowsSection(string name, string server) => string.Join("\r\n",
        "[" + name + "]", "Encoding=1", "PBVersion=8", "Type=2", "VpnStrategy=7", "DataEncryption=8", "CustomAuthKey=0",
        "IpDnsSuffix=", "PreSharedKey=", "CacheCredentials=1", "NumCustomPolicy=0", "NumEku=0", "ManagementApp=", "",
        "NETCOMPONENTS=", "ms_msclient=1", "ms_server=1", "",
        "MEDIA=rastapi", "Port=VPN2-0", "Device=WAN Miniport (IKEv2)", "",
        "DEVICE=vpn", "PhoneNumber=" + server, "AreaCode=", "TryNextAlternateOnFail=1", "", "");

    [Fact]
    public void Ikev2PolicyKeysStayAmongEntryKeysNotInsideDeviceGroup()
    {
        var other = WindowsSection("Склад", "sklad.example");
        var text = other + WindowsSection("Офис", "vpn.example");

        var updated = RasPhonebook.WithIkev2Policy(text, "Офис");

        var expected = other + string.Join("\r\n",
            "[Офис]", "Encoding=1", "PBVersion=8", "Type=2", "VpnStrategy=7", "DataEncryption=256", "CustomAuthKey=0",
            "IpDnsSuffix=", "PreSharedKey=", "CacheCredentials=1", "NumCustomPolicy=1", "NumEku=0", "ManagementApp=",
            "CustomIPSecPolicies=" + Policy, "",
            "NETCOMPONENTS=", "ms_msclient=1", "ms_server=1", "",
            "MEDIA=rastapi", "Port=VPN2-0", "Device=WAN Miniport (IKEv2)", "",
            "DEVICE=vpn", "PhoneNumber=vpn.example", "AreaCode=", "TryNextAlternateOnFail=1", "", "");
        Assert.Equal(expected, updated);
    }

    /// <summary>
    /// Книга от прежней версии: CustomIPSecPolicies дописан в конец раздела, внутрь группы DEVICE. Ключ переносится к ключам
    /// записи, а копия в группе удаляется.
    /// </summary>
    [Fact]
    public void Ikev2PolicyKeyWrittenIntoDeviceGroupByOldVersionMovesToEntryKeys()
    {
        var old = string.Join("\r\n",
            "[Офис]", "Encoding=1", "PBVersion=8", "Type=2", "VpnStrategy=7", "DataEncryption=256", "CustomAuthKey=0",
            "IpDnsSuffix=", "PreSharedKey=", "CacheCredentials=1", "NumCustomPolicy=1", "NumEku=0", "ManagementApp=", "",
            "NETCOMPONENTS=", "ms_msclient=1", "ms_server=1", "",
            "MEDIA=rastapi", "Port=VPN2-0", "Device=WAN Miniport (IKEv2)", "",
            "DEVICE=vpn", "PhoneNumber=vpn.example", "AreaCode=", "TryNextAlternateOnFail=1", "CustomIPSecPolicies=" + Policy, "", "");

        var updated = RasPhonebook.WithIkev2Policy(old, "Офис");

        Assert.Equal(RasPhonebook.WithIkev2Policy(WindowsSection("Офис", "vpn.example"), "Офис"), updated);
        Assert.Single(updated.Split("\r\n"), l => l.StartsWith("CustomIPSecPolicies=", StringComparison.Ordinal));
        Assert.Contains("ManagementApp=\r\nCustomIPSecPolicies=" + Policy + "\r\n\r\nNETCOMPONENTS=", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void Ikev2PolicyIsIdempotent()
    {
        var once = RasPhonebook.WithIkev2Policy(WindowsSection("Vpn", "vpn.example"), "Vpn");
        Assert.Equal(once, RasPhonebook.WithIkev2Policy(once, "Vpn"));
        Assert.Single(once.Split("\r\n"), l => l.StartsWith("CustomIPSecPolicies=", StringComparison.Ordinal));
    }

    [Fact]
    public void Ikev2PolicyFindsEntryNamesWithBracketsAndEquals()
    {
        var text = WindowsSection("a]b", "one.example") + WindowsSection("x=y [1]", "two.example");

        var updated = RasPhonebook.WithIkev2Policy(text, "x=y [1]");

        Assert.StartsWith(WindowsSection("a]b", "one.example"), updated, StringComparison.Ordinal);
        Assert.Contains("[x=y [1]]\r\nEncoding=1", updated, StringComparison.Ordinal);
        Assert.Contains("ManagementApp=\r\nCustomIPSecPolicies=" + Policy + "\r\n\r\nNETCOMPONENTS=", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void Ikev2PolicyDoesNotTouchAnotherEntryWithSimilarName()
    {
        var text = WindowsSection("Офис 2", "two.example");
        Assert.Throws<InvalidOperationException>(() => RasPhonebook.WithIkev2Policy(text, "Офис"));
    }

    [Theory]
    [InlineData(null, "C:\\a.pbk")]
    [InlineData("", "C:\\a.pbk")]
    [InlineData("   ", "C:\\a.pbk")]
    [InlineData("C:\\a.pbk", null)]
    public void ConnectionWithoutPhonebookIsNeverOurs(string? left, string? right) =>
        Assert.False(RasClient.SamePhonebook(left, right));

    [Fact]
    public void PhonebookPathsCompareNormalizedAndCaseInsensitive()
    {
        Assert.True(RasClient.SamePhonebook(@"C:\ProgramData\SplitVpn\..\SplitVpn\Книга.pbk", @"c:\programdata\splitvpn\книга.PBK"));
        Assert.False(RasClient.SamePhonebook(@"C:\ProgramData\SplitVpn\a.pbk", @"C:\ProgramData\SplitVpn\b.pbk"));
        // Недопустимый путь не обрывает обход соединений: сравнивается как есть.
        Assert.True(RasClient.SamePhonebook("C:\\bad\0path", "C:\\BAD\0PATH"));
    }

    [Fact]
    public void SockaddrAddressesAreNetworkOrder()
    {
        var host = Ipv4.Parse("192.168.0.1");
        // В памяти sin_addr: C0 A8 00 01; на little-endian x64 это число 0x0100A8C0.
        Assert.Equal(0x0100A8C0u, NetInventory.ToNetworkOrder(host));
        Assert.Equal(host, NetInventory.ToHostOrder(0x0100A8C0u));
        Assert.Equal(0xFFFFFFFFu, NetInventory.ToHostOrder(NetInventory.ToNetworkOrder(0xFFFFFFFFu)));
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("192.0.2.1", "192.0.2.1")]
    [InlineData("192.0.2.1 192.0.2.2", "192.0.2.1 192.0.2.2")]
    [InlineData("192.0.2.1,192.0.2.2", "192.0.2.1 192.0.2.2")]
    [InlineData(" 192.0.2.1 ,, fe80::1 мусор 999.1.1.1 192.0.2.3 ", "192.0.2.1 192.0.2.3")]
    public void RegistryNameServerListsKeepOnlyIpv4(string? value, string expected) =>
        Assert.Equal(expected.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(Ipv4.Parse), NetInventory.ParseNameServers(value));
}
