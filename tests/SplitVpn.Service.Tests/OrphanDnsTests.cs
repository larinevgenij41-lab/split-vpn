using System.Net;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Recovery;

namespace SplitVpn.Service.Tests;

/// <summary>Правила сброса DNS адаптера без записи в копии (экстренное отключение и «Восстановить сеть»).</summary>
public sealed class OrphanDnsTests
{
    [Theory]
    // Служба остановлена: наш набор сбрасывается, если только порт 53 не слушают именно на 127.0.0.1 ([::1] для IPv6).
    // Слушатель только на 0.0.0.0:53 или [::]:53 (V4/V6 без Exact) — чужая программа, а не резолвер пользователя: сброс.
    [InlineData("127.0.0.1", "", true, true, true, false, false, false, true, false, false)]
    [InlineData("127.0.0.1", "::1", true, true, true, false, false, false, true, true, false)]
    // Резолвер пользователя именно на 127.0.0.1:53 (AdGuard Home, dnscrypt-proxy): адаптер не трогается целиком.
    [InlineData("127.0.0.1", "", true, true, false, true, false, false, false, false, false)]
    [InlineData("127.0.0.1", "::1", true, true, false, true, false, false, false, false, false)]
    // Слушатель именно на [::1]:53: IPv6-список остаётся, наш IPv4 без резолвера на 127.0.0.1 — сбрасывается.
    [InlineData("127.0.0.1", "::1", true, false, true, false, true, false, true, false, false)]
    [InlineData("192.168.1.50,127.0.0.1", "", true, false, false, false, false, false, true, false, false)] // прежний адрес адаптера, уже не его
    [InlineData("10.0.0.7 127.0.0.1", "::1", true, false, false, false, false, false, true, true, false)]
    [InlineData("8.8.8.8", "", true, false, false, false, false, false, false, false, false)]
    [InlineData("", "", true, false, false, false, false, false, false, false, false)]
    [InlineData("127.0.0.1,8.8.8.8", "", true, false, false, false, false, false, false, false, false)] // loopback не последним — не наш набор
    // ::1 при не нашем IPv4 (служба остановлена): только если [::1]:53 не слушают именно.
    [InlineData("8.8.8.8", "::1", true, false, false, false, false, false, false, true, false)]
    [InlineData("8.8.8.8", "::1", true, false, true, false, false, false, false, true, false)]
    [InlineData("8.8.8.8", "::1", true, false, true, false, true, false, false, false, false)]
    [InlineData("8.8.8.8", "2001:4860:4860::8888", true, false, false, false, false, false, false, false, false)]
    // Служба работает («Восстановить сеть» без посредника): только если запросы к 127.0.0.1:53 никто не принимает.
    [InlineData("127.0.0.1", "::1", false, true, true, false, false, false, false, false, false)]
    [InlineData("127.0.0.1", "::1", false, false, false, false, false, false, true, true, false)]
    [InlineData("127.0.0.1", "::1", false, false, true, false, false, false, true, true, false)] // ::1 уходит вместе с нашим IPv4
    [InlineData("8.8.8.8", "::1", false, false, true, false, false, false, false, false, false)]
    // Статический IPv4-адрес: «автоматически» оставило бы адаптер без DNS — наш IPv4-список не трогается, об этом говорится;
    // наш ::1 сбрасывается по обычным правилам (статический IPv4-адрес на IPv6 не влияет).
    [InlineData("127.0.0.1", "::1", true, false, false, false, false, true, false, true, true)]
    [InlineData("127.0.0.1", "", false, false, false, false, false, true, false, false, true)]
    [InlineData("127.0.0.1", "::1", false, false, false, false, false, true, false, true, true)] // при работающей службе ::1 — от нашего IPv4
    [InlineData("8.8.8.8", "", true, false, false, false, false, true, false, false, false)]
    [InlineData("8.8.8.8", "::1", true, false, false, false, false, true, false, true, false)] // IPv4 не наш — заметки нет
    [InlineData("8.8.8.8", "::1", true, false, true, false, true, true, false, false, false)] // резолвер на [::1]:53
    [InlineData("127.0.0.1", "::1", true, true, false, true, false, true, false, false, false)] // резолвер на 127.0.0.1:53 — целиком
    public void Decide(string v4, string v6, bool serviceStopped, bool v4Any, bool v6Any, bool v4Exact, bool v6Exact, bool staticIpv4,
        bool expectV4, bool expectV6, bool expectKept)
    {
        var reset = OrphanDns.Decide(v4, v6, serviceStopped, new LoopbackListeners(v4Any || v4Exact, v6Any || v6Exact, v4Exact, v6Exact), staticIpv4);

        Assert.Equal(expectV4, reset.V4);
        Assert.Equal(expectV6, reset.V6);
        Assert.Equal(expectV4 || expectV6, reset.Any);
        Assert.Equal(expectKept, reset.KeptStatic);
    }

    [Fact]
    public void Decide_Ipv6Unreadable_TouchesOnlyIpv4()
    {
        var reset = OrphanDns.Decide("127.0.0.1", null, serviceStopped: true, default);

        Assert.True(reset.V4);
        Assert.False(reset.V6);
    }

    [Fact]
    public void StaticNote_AsksToSetDnsManually()
    {
        var note = OrphanDnsReset.StaticNote("Ethernet", "127.0.0.1");

        Assert.Contains("адаптер «Ethernet» со статическим адресом", note, StringComparison.Ordinal);
        Assert.Contains("IPv4 DNS «127.0.0.1» программы не сброшен", note, StringComparison.Ordinal);
        Assert.Contains("DNS укажите вручную", note, StringComparison.Ordinal);
    }

    [Fact]
    public void Listeners_ExactAndWildcard_AreTold()
    {
        static IPEndPoint At(string address, int port = 53) => new(IPAddress.Parse(address), port);

        Assert.Equal(new LoopbackListeners(true, true, false, false), NetworkRecovery.ClassifyListeners([At("::")]));
        Assert.Equal(new LoopbackListeners(true, false, false, false), NetworkRecovery.ClassifyListeners([At("0.0.0.0")]));
        Assert.Equal(new LoopbackListeners(true, false, true, false), NetworkRecovery.ClassifyListeners([At("127.0.0.1")]));
        Assert.Equal(new LoopbackListeners(true, false, true, false), NetworkRecovery.ClassifyListeners([At("::ffff:127.0.0.1")]));
        Assert.Equal(new LoopbackListeners(false, true, false, true), NetworkRecovery.ClassifyListeners([At("::1")]));
        Assert.Equal(default, NetworkRecovery.ClassifyListeners([At("127.0.0.1", 5353), At("192.168.1.10")]));
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

    /// <summary>
    /// «SplitVpn.Cli recover» завершает помощники и прототипа, и установленного продукта: каталог продукта — по
    /// регистрации службы и всегда по умолчанию (Program Files\SplitVpn), без повторов.
    /// </summary>
    [Fact]
    public void RecoverCommand_StopsHelpersOfPrototypeAndInstalledProduct()
    {
        const string programFiles = @"C:\Program Files";
        Assert.Equal(@"C:\Program Files\SplitVpn.Dev\service", SplitVpn.Cli.Proto.RecoverCommand.PrototypeServiceDirectory(programFiles));
        Assert.Equal([@"C:\Program Files\SplitVpn"], SplitVpn.Cli.Proto.RecoverCommand.ProductServiceDirectories(programFiles, null));
        Assert.Equal([@"D:\Apps\SplitVpn", @"C:\Program Files\SplitVpn"],
            SplitVpn.Cli.Proto.RecoverCommand.ProductServiceDirectories(programFiles, @"D:\Apps\SplitVpn"));

        Assert.Equal([@"C:\Program Files\SplitVpn.Dev\service", @"C:\Program Files\SplitVpn"],
            NetworkRecovery.DistinctDirectories([@"C:\Program Files\SplitVpn.Dev\service\", @"C:\Program Files\SplitVpn\", @"c:\program files\splitvpn", "", null]));
    }

    [Theory]
    [InlineData("\"C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\"", "C:\\Program Files\\SplitVpn")]
    [InlineData("\"C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\" --service", "C:\\Program Files\\SplitVpn")]
    [InlineData("C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe --service", "C:\\Program Files\\SplitVpn")]
    [InlineData("\\??\\C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe --service", "C:\\Program Files\\SplitVpn")] // префикс NT
    [InlineData("\"\\??\\C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\" --service", "C:\\Program Files\\SplitVpn")]
    [InlineData("\\??\\\"C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\"", "C:\\Program Files\\SplitVpn")]
    [InlineData("\\??\\SplitVpn.Service.exe", null)]
    [InlineData("SplitVpn.Service.exe", null)] // не полный путь — каталог неизвестен
    [InlineData("\"", null)]
    [InlineData("", null)]
    public void ServiceDirectory_FromImagePath(string image, string? expected) =>
        Assert.Equal(expected, NetworkRecovery.ServiceDirectoryFromImagePath(image));

    [Theory]
    [InlineData("::1", 53, true)]
    [InlineData("::", 53, true)]
    [InlineData("127.0.0.1", 53, false)]
    [InlineData("::1", 5353, false)]
    public void Ipv6LoopbackListener(string address, int port, bool expected) =>
        Assert.Equal(expected, NetworkRecovery.ServesIpv6LoopbackResolver(new IPEndPoint(IPAddress.Parse(address), port)));
}
