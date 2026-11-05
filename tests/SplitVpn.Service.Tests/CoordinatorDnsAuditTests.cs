using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>Исправления аудита 2026-11-01 на стороне координатора: DNS-кеш, суффиксы и восстановление DNS.</summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task FailedIpv6DnsRestore_KeepsBackup()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal("::1", _world.Dns.NameServersV6[FakeWorld.WiFiGuid]);
        _world.Dns.FailIpv6Restore.Add(FakeWorld.WiFiGuid);

        await coordinator.HandleRequestAsync(new Core.Ipc.DisconnectRequest(KeepProtection: false), CancellationToken.None);

        // ::1 остался без посредника: копия с исходными IPv6 DNS нужна для следующей попытки.
        var backups = new DnsBackupStore(_world.Paths.DnsBackup).Load();
        Assert.True(backups.ContainsKey(FakeWorld.WiFiGuid));

        _world.Dns.FailIpv6Restore.Clear();
        await coordinator.HandleRequestAsync(new Core.Ipc.DisconnectRequest(KeepProtection: false), CancellationToken.None);
        Assert.Equal("", _world.Dns.NameServersV6[FakeWorld.WiFiGuid]);
        Assert.False(new DnsBackupStore(_world.Paths.DnsBackup).Load().ContainsKey(FakeWorld.WiFiGuid));
    }

    [Fact]
    public async Task NetworkChangeWithSameDns_ClearsProxyCache()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var clears = _world.Proxy.Clears;

        // Другая сеть за тем же адаптером и тем же DNS 192.168.1.1: меняется только адрес.
        _world.Inventory.WiFiAddress = Ipv4.Parse("192.168.1.77");
        await coordinator.ReconcileAsync(CancellationToken.None);

        Assert.True(_world.Proxy.Clears > clears);

        // Без смены сети повторная сверка кеш не трогает.
        clears = _world.Proxy.Clears;
        await coordinator.ReconcileAsync(CancellationToken.None);
        Assert.Equal(clears, _world.Proxy.Clears);
    }

    [Fact]
    public async Task LocalSuffixWithSpaces_ReachesProxyNormalized()
    {
        SaveSettings(Settings() with { LocalDnsSuffixes = [" Home.Arpa. "] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Equal(["home.arpa"], _world.Proxy.Configuration.LocalSuffixes);
        Assert.Same(_world.Proxy.Configuration.Local, DnsProxyServer.SelectRoute(_world.Proxy.Configuration, "nas.home.arpa").Route);
    }

    [Fact]
    public async Task UnicodeDomainRule_MatchesIdnaWireName()
    {
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "Пример.РФ", Target = RouteTarget.Direct }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var domain = DnsProxyServer.MatchDomain(_world.Proxy.Configuration, "www.xn--e1afmkfd.xn--p1ai");

        Assert.NotNull(domain);
        Assert.Equal("xn--e1afmkfd.xn--p1ai", domain.Suffix);
    }
}
