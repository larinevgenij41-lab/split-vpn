using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Итерация 9: занятый чужой программой 127.0.0.1:53 при запуске службы, освобождение адреса :53 отключившегося адаптера,
/// срок ожидания остановки службы и перевод часов, замеченный потоком DNS-посредника посреди работы актора.
/// </summary>
public sealed partial class CoordinatorTests
{
    private const string OriginalWiFiDns = "192.168.1.1";

    /// <summary>
    /// S1: служба перезапускается, пока 127.0.0.1:53 держит чужая программа. Адаптеры не остаются направленными на неё:
    /// DNS возвращается из копий, наш 127.0.0.1 снимается и с туннеля, причина видна в ошибке сверки, DNS-страж защиты
    /// стоит (запросы к исходным серверам не уходят мимо политики). Порт освободился - сверка снова ставит посредника.
    /// </summary>
    [Fact]
    public async Task ProxyCannotBindLoopback_AdapterDnsRestored_ThenReappliedWhenPortFrees()
    {
        _world.Dns.NameServers[FakeWorld.WiFiGuid] = OriginalWiFiDns;
        _world.Proxy.ServesAdapterAddresses = true;
        var first = await StartAsync();
        await ConnectAsync(first);
        Assert.Equal("192.168.1.100,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.TunnelGuid]);

        // Служба упала; пока её нет, порт занят чужой программой. Новый процесс - новый посредник.
        var proxy = new FakeProxy { ServesAdapterAddresses = true, FailStart = true };
        var restarted = new Coordinator(_world.Dependencies() with { DnsProxy = proxy });
        await restarted.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(restarted);

        Assert.False(proxy.IsRunning);
        Assert.Equal(OriginalWiFiDns, _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.False(InterfaceDnsOps.IsLoopback(_world.Dns.NameServers[FakeWorld.TunnelGuid]));
        Assert.Empty(new DnsBackupStore(_world.Paths.DnsBackup).Load());
        Assert.Contains("порт 53 на 127.0.0.1 занят другой программой", restarted.Facts.PartialError, StringComparison.Ordinal);
        // Защита закрыта для DNS: обычный порт 53 блокирует страж, пропуская только loopback, службу и туннель.
        var guard = _world.Wfp.Group(FilterGroup.Base).Where(f => f.Name.StartsWith("DNS-страж", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, guard.Count);
        Assert.All(guard, f => Assert.Equal(FilterAction.Block, f.Action));

        // Повтор по паузе после ошибки, пока порт ещё занят: адаптеры не трогаются.
        _world.Time.Advance(TimeSpan.FromSeconds(3));
        await TickAsync(restarted);
        Assert.Equal(OriginalWiFiDns, _world.Dns.NameServers[FakeWorld.WiFiGuid]);

        // Чужая программа освободила порт: следующая сверка запускает посредник и снова ставит его адаптерам.
        proxy.FailStart = false;
        _world.Time.Advance(TimeSpan.FromSeconds(10));
        await TickAsync(restarted);

        Assert.True(proxy.IsRunning);
        Assert.Null(restarted.Facts.PartialError);
        Assert.Equal("192.168.1.100,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal(OriginalWiFiDns, new DnsBackupStore(_world.Paths.DnsBackup).Load()[FakeWorld.WiFiGuid].NameServerV4);
    }

    /// <summary>
    /// S2: основной адаптер отключился и выпал из обработки - его список «свой адрес, 127.0.0.1» переписывается на
    /// одиночный 127.0.0.1 до освобождения адреса: после переподключения Windows не спросит освобождённый адрес:53.
    /// </summary>
    [Fact]
    public async Task AdapterGoesDown_OwnAddressWithdrawnFromItsDnsBeforeRelease()
    {
        _world.Proxy.ServesAdapterAddresses = true;
        var released = new List<uint>();
        _world.Proxy.OnRelease = address =>
        {
            Assert.DoesNotContain(Ipv4.Format(address), _world.Dns.NameServers.Values.SelectMany(v => v.Split(',')));
            released.Add(address);
        };
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal([FakeWorld.WiFiAddress], _world.Proxy.Claimed);

        _world.Inventory.WiFiUp = false;
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal([FakeWorld.WiFiAddress], released);
        Assert.Empty(_world.Proxy.Claimed);
    }

    /// <summary>S2: переписать DNS отключившегося адаптера не удалось - его адрес остаётся занятым посредником.</summary>
    [Fact]
    public async Task AdapterGoesDown_RewriteFails_AddressStaysClaimed()
    {
        _world.Proxy.ServesAdapterAddresses = true;
        var released = new List<uint>();
        _world.Proxy.OnRelease = released.Add;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        _world.Dns.FailLoopback.Add(FakeWorld.WiFiGuid);
        _world.Inventory.WiFiUp = false;
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        Assert.Equal("192.168.1.100,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Empty(released);
        Assert.Contains(FakeWorld.WiFiAddress, _world.Proxy.Claimed);

        // Запись снова проходит - адрес убирается из списка и только потом освобождается.
        _world.Dns.FailLoopback.Clear();
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal([FakeWorld.WiFiAddress], released);
    }

    /// <summary>S3: служба завершается принудительно только после своего срока штатной остановки.</summary>
    [Fact]
    public void ServiceStopWait_CoversHostShutdownTimeout()
    {
        Assert.Equal(CoordinatorHost.ShutdownTimeout + TimeSpan.FromSeconds(2), ServiceRecovery.StopWaitBeforeKill);
    }

    /// <summary>
    /// S4: перевод часов замечен потоком DNS-посредника посреди сверки; срок повтора после ошибки, записанный той же
    /// сверкой уже по новым часам, отложенный сдвиг не трогает, а отметки, записанные до неё, сдвигаются.
    /// </summary>
    [Fact]
    public async Task ClockSetBackSeenByDnsThreadMidWork_LaterDeadlineIsNotShiftedTwice()
    {
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithClockAsync(clock);
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var sessionStarted = tunnel.SessionStartedUtc!.Value;

        var notice = new PinnedRouteNotice("x.example", "x.example", RouteTarget.Direct, [Ipv4.Parse("93.184.216.40")], TimeSpan.FromMinutes(5))
        {
            IsCurrent = () => false,
        };
        _world.Wfp.FailNextReplace = 1;
        Task<bool>? observed = null;
        _world.Wfp.BeforeReplace = () =>
        {
            _world.Wfp.BeforeReplace = null;
            clock.Offset = -TimeSpan.FromHours(1);
            // Ответ DNS на потоке посредника первым замечает перевод часов.
            observed = coordinator.ObservePinnedAsync(notice, CancellationToken.None).AsTask();
        };
        // Сменился адаптер: защита перестраивается, и запись фильтров падает.
        _world.Inventory.WiFiLuid = 9;
        _world.Inventory.WiFiAddress = Ipv4.Parse("192.168.1.150");
        await coordinator.TickAsync(CancellationToken.None);
        Assert.NotNull(observed);
        Assert.False(await observed);
        Assert.NotNull(coordinator.Facts.PartialError);
        var retryAt = coordinator.Facts.PartialErrorRetryAt;
        Assert.InRange(retryAt - clock.GetUtcNow(), TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(1));

        // Следующая работа очереди применяет отложенный сдвиг.
        await coordinator.EnqueueAsync("test", () => Task.CompletedTask);
        await coordinator.DrainAsync();

        Assert.Equal(retryAt, coordinator.Facts.PartialErrorRetryAt);
        Assert.Equal(sessionStarted - TimeSpan.FromHours(1), tunnel.SessionStartedUtc);
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("Часы Windows переведены назад", StringComparison.Ordinal));
    }

    /// <summary>S4: перевод замечен потоком DNS-посредника между работами - сроки актора сдвигаются, повтор дозвона не ждёт час.</summary>
    [Fact]
    public async Task ClockSetBackSeenByDnsThreadBetweenWorks_DialRetryIsNotPostponed()
    {
        var clock = new ShiftedTimeProvider(_world.Time);
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        var coordinator = await StartWithClockAsync(clock);
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        Assert.Equal(1, _world.Ras.Dials);
        var backoff = coordinator.Facts.Tunnels[_profile.Id].NextDialAt - clock.GetUtcNow();

        clock.Offset = -TimeSpan.FromHours(3);
        var notice = new PinnedRouteNotice("x.example", "x.example", RouteTarget.Direct, [Ipv4.Parse("93.184.216.40")], TimeSpan.FromMinutes(5))
        {
            IsCurrent = () => false,
        };
        Assert.False(await coordinator.ObservePinnedAsync(notice, CancellationToken.None));
        _world.Time.Advance((backoff > TimeSpan.Zero ? backoff : TimeSpan.Zero) + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.Ras.Dials);
    }
}
