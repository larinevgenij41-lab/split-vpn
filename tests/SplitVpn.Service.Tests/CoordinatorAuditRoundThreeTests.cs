using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>Исправления третьего круга аудита: сбой сброса кеша DNS при закреплении и «Отключить» посреди дозвона.</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Устойчивый сбой сброса кеша DNS (служба Dnscache остановлена) не делает каждое закрепление неудачным: маршруты и
    /// фильтры применены, ответ отдаётся, полная сверка не назначается. Сброс остаётся отложенным и выполняется, как только
    /// снова удаётся.
    /// </summary>
    [Fact]
    public async Task PersistentDnsFlushFailure_DoesNotFailPinApplication()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();

        // Сеть сменилась, а сброс кеша не удаётся: сверка сообщает о неполном применении, сброс отложен.
        _world.Dns.FailFlush = true;
        _world.Inventory.WiFiDnsServers = [FakeWorld.Gateway, Ipv4.Parse("192.168.1.2")];
        await coordinator.ReconcileAsync(CancellationToken.None);
        Assert.NotNull(coordinator.Facts.PartialError);
        coordinator.Facts.ForceProtection = false;

        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromMinutes(5), Ipv4.Parse("93.184.216.61")));
        Assert.False(coordinator.Facts.ForceProtection);
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromMinutes(5), Ipv4.Parse("93.184.216.62")));
        Assert.False(coordinator.Facts.ForceProtection);
        Assert.Equal(vpn, coordinator.Facts.Pinned[Ipv4.Parse("93.184.216.62")].Target);

        // Сброс снова работает: отложенный выполняется при следующем применении закреплений.
        _world.Dns.FailFlush = false;
        var flushes = _world.Dns.Flushes;
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromMinutes(5), Ipv4.Parse("93.184.216.63")));
        Assert.True(_world.Dns.Flushes > flushes);
    }

    /// <summary>
    /// «Отключить» посреди дозвона: снятие защиты не трогает записи телефонной книги, пока туннель дозванивается. Конец
    /// дозвона (отказ или успех, который тут же разрывается) повторяет снятие, и записи с ключами IPsec удаляются.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisconnectDuringDial_FinishedDialRemovesPhonebookEntries(bool dialSucceeded)
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        tunnel.Dialing = true;
        tunnel.DialSettled = false;

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        Assert.Contains(tunnel.EntryName, _world.Ras.EntryNames());

        var result = dialSucceeded
            ? new RasDialResult(true, new RasConnectionHandle(0x5150 + _world.Ras.Slot(tunnel.EntryName)), 0, null)
            : new RasDialResult(false, null, 809, "отказ");
        await coordinator.OnDialFinishedAsync(_profile.Id, result, tunnel.DialGeneration, CancellationToken.None);

        Assert.Empty(_world.Ras.EntryNames());
        Assert.False(_world.Ras.Connected);
    }
}