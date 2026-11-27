using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;
using SplitVpn.Windows.Net;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Аудит 26.11.2026: собственные маршруты службы не становятся «сетями» доверенного адаптера; сбой сброса кеша DNS
/// не обрывает обязательных шагов снятия защиты.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Маршрут службы (метрика-маркер) через доверенный адаптер не локален: иначе широкий маршрут «напрямую» перекрыл бы
    /// правила пользователя, включая «Блокировать», а политика менялась бы вслед за своими же маршрутами.
    /// Обычный маршрут адаптера (управляемый маршрут ZeroTier) по-прежнему локален.
    /// </summary>
    [Fact]
    public async Task TrustedAdapter_ServiceOwnRoutes_AreNotItsNetworks()
    {
        var radmin = Guid.NewGuid();
        var managed = Ipv4.Parse("91.108.4.10");
        var own = Ipv4.Parse("149.154.160.5");
        _world.Inventory.RadminGuid = radmin;
        _world.Inventory.ExtraRoutes.Add(new RouteEntry(Ipv4Cidr.Parse("91.108.4.0/22"), 0, FakeWorld.RadminLuid, 19, 1, 3));
        _world.Inventory.ExtraRoutes.Add(new RouteEntry(Ipv4Cidr.Parse("149.154.160.0/20"), 0, FakeWorld.RadminLuid, 19, RouteOps.MarkerMetric, 3));
        SaveSettings(Settings() with { TrustedAdapters = [radmin] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.True(coordinator.Facts.Policy!.LocalRanges.Contains(managed));
        Assert.False(coordinator.Facts.Policy.LocalRanges.Contains(own));
        var trusted = Assert.Single(coordinator.Facts.AppliedFilters[FilterGroup.Runtime].Specs, f => f.Name == "Доверенный адаптер «Radmin VPN»");
        var ranges = Assert.Single(trusted.Conditions.OfType<RemoteRangesV4>());
        Assert.True(ranges.Contains(managed));
        Assert.False(ranges.Contains(own));
        Assert.DoesNotContain(coordinator.Facts.AppliedFilters[FilterGroup.Runtime].Specs,
            f => f.Name.StartsWith("Сеть интерфейса", StringComparison.Ordinal) && f.Conditions.OfType<RemoteRangeV4>().Any(r => r.Start <= own && own <= r.End));
    }

    /// <summary>
    /// ipconfig /flushdns не подтвердил сброс при отключении: записи телефонной книги (с ключами IPsec) всё равно удалены,
    /// ошибка видна как частичное применение, а следующая сверка сбрасывает кеш и снимает её.
    /// </summary>
    [Fact]
    public async Task Disconnect_DnsFlushFailure_StillDeletesPhonebookEntries_AndRetries()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.NotEmpty(_world.Ras.EntryNames());

        _world.Dns.FailFlush = true;
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);

        Assert.Empty(_world.Ras.EntryNames());
        Assert.NotEmpty(_world.Ras.DeletedEntries);
        Assert.NotNull(coordinator.Facts.PartialError);

        var flushes = _world.Dns.Flushes;
        _world.Dns.FailFlush = false;
        await coordinator.ReconcileAsync(CancellationToken.None);

        Assert.True(_world.Dns.Flushes > flushes);
        Assert.Null(coordinator.Facts.PartialError);
        Assert.False(coordinator.Facts.ForceProtection);
    }

    /// <summary>Сбой сброса кеша DNS при настройке DNS адаптеров не мешает освободить ушедшие адреса посредника.</summary>
    [Fact]
    public async Task EnsureDns_FlushFailure_StillReleasesWithdrawnAddresses()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var stale = Ipv4.Parse("127.0.0.77");
        _world.Proxy.Claimed.Add(stale);

        _world.Dns.FailFlush = true;
        // Сеть сменилась (DHCP выдал второй DNS): посредник перенастраивается и сбрасывает кеш.
        _world.Inventory.WiFiDnsServers = [FakeWorld.Gateway, Ipv4.Parse("192.168.1.2")];
        await coordinator.ReconcileAsync(CancellationToken.None);

        Assert.DoesNotContain(stale, _world.Proxy.Claimed);
        Assert.NotNull(coordinator.Facts.PartialError);
    }
}
