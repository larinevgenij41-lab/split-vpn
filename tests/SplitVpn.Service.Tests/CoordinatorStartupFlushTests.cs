using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Перезапуск службы после сбоя прежнего процесса, не успевшего сохранить закрепления (файла закреплений нет): первая
    /// сверка снимает их маршруты /32.
    /// Кеш DNS Windows сбрасывается раньше, пока маршрут прежнего процесса ещё стоит: адрес из кеша Windows не уходит
    /// по адресной политике в промежутке между снятием маршрута и сбросом.
    /// </summary>
    [Fact]
    public async Task Restart_FlushesWindowsDnsCacheBeforeOldPinRoutesAreRemoved()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with
        {
            DefaultTarget = RouteTarget.Direct,
            // Правила на узлы проверки отзыва и веб-проверки интернета: служебные закрепления не нужны, и сброс кеша при
            // сборке политики («проверка отзыва снова нужна») не заслоняет проверяемый порядок.
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "first.example", Target = vpn },
                new DomainRuleSetting { Suffix = "lencr.org", Target = RouteTarget.Direct },
                new DomainRuleSetting { Suffix = "msftconnecttest.com", Target = RouteTarget.Direct },
            ],
        });
        var first = await StartAsync();
        await ConnectAsync(first);
        var address = Ipv4.Parse("93.184.216.41");
        var pending = first.ObservePinnedAsync(new PinnedRouteNotice("first.example", "first.example", vpn, [address], TimeSpan.FromHours(1)), CancellationToken.None);
        await first.DrainAsync();
        Assert.True(await pending);
        var pinRoute = new Ipv4Cidr(address, 32);
        Assert.Contains(_world.Routes.Current, r => r.Destination == pinRoute);

        var dns = new FlushOrderDns(_world.Dns, () => _world.Routes.Current.Any(r => r.Destination == pinRoute));
        var restarted = new Coordinator(_world.Dependencies() with { Dns = dns });
        await restarted.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(restarted);

        Assert.NotEmpty(dns.RouteStillPresentAtFlush);
        Assert.True(dns.RouteStillPresentAtFlush[0]);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == pinRoute);
    }

    /// <summary>Сброс кеша DNS отмечает, стоял ли в этот момент маршрут закрепления прежнего процесса.</summary>
    private sealed class FlushOrderDns(IDnsOps inner, Func<bool> routePresent) : IDnsOps
    {
        public List<bool> RouteStillPresentAtFlush { get; } = [];

        public void FlushCache()
        {
            RouteStillPresentAtFlush.Add(routePresent());
            inner.FlushCache();
        }

        public string ReadNameServer(Guid interfaceGuid) => inner.ReadNameServer(interfaceGuid);

        public InterfaceDnsBackup Capture(Guid interfaceGuid, InterfaceDnsBackup? previous) => inner.Capture(interfaceGuid, previous);

        public void ApplyLoopback(Guid interfaceGuid, string? originalV6 = null, string? nameServerV4 = null, bool ipv6Known = true) =>
            inner.ApplyLoopback(interfaceGuid, originalV6, nameServerV4, ipv6Known);

        public bool Ipv6LoopbackMatches(Guid interfaceGuid, string? originalV6 = null) => inner.Ipv6LoopbackMatches(interfaceGuid, originalV6);

        public string ReadSearchList(Guid interfaceGuid) => inner.ReadSearchList(interfaceGuid);

        public void SetSearchList(Guid interfaceGuid, string searchList) => inner.SetSearchList(interfaceGuid, searchList);

        public void ClearNameServer(Guid interfaceGuid) => inner.ClearNameServer(interfaceGuid);

        public DnsRestoreOutcome Restore(Guid interfaceGuid, InterfaceDnsBackup? backup) => inner.Restore(interfaceGuid, backup);

        public string? ReadNameServerV6(Guid interfaceGuid) => inner.ReadNameServerV6(interfaceGuid);

        public bool ResetToAutomatic(Guid interfaceGuid, bool v4, bool v6) => inner.ResetToAutomatic(interfaceGuid, v4, v6);
    }
}
