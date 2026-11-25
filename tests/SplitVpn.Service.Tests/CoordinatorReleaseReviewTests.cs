using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Итоговое ревью службы перед выпуском 0.18.0: перевод часов во время стартовой сверки и между ответом DNS и тиком,
/// несовпавшее соединение одного профиля и очередь подъёма, падение сеанса с отложенным разрывом, освобождение адресов
/// :53 при сбое чужого адаптера, имена узлов шлюза в маскированном отчёте.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>V-1: часы перевели назад во время стартовой сверки, до первого тика - периодическая сверка не откладывается.</summary>
    [Fact]
    public async Task ClockSetBackDuringStartup_PeriodicReconcileIsNotPostponed()
    {
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithClockAsync(clock);

        clock.Offset = -TimeSpan.FromHours(1);
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        Assert.Equal(clock.GetUtcNow(), coordinator.Facts.LastForcedReconcile);
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("Часы Windows переведены назад", StringComparison.Ordinal));
    }

    /// <summary>
    /// V-1: стартовое применение не удалось (WFP), часы перевели назад до первого тика - повтор после ошибки идёт по своей
    /// паузе, а не через час. Сбой WFP, а не снимка сети: изменившийся снимок сам запустил бы сверку и скрыл дефект.
    /// </summary>
    [Fact]
    public async Task ClockSetBackDuringStartup_PartialErrorRetryIsNotPostponed()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Protected });
        _world.Wfp.FailNextReplace = 1;
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithClockAsync(clock);
        Assert.NotNull(coordinator.Facts.PartialError);

        clock.Offset = -TimeSpan.FromHours(1);
        for (var i = 0; i < 2 && coordinator.Facts.PartialError is not null; i++)
        {
            _world.Time.Advance(Coordinator.TickInterval);
            await TickAsync(coordinator);
        }

        Assert.Null(coordinator.Facts.PartialError);
        Assert.Contains(FilterGroup.Base, _world.Wfp.Groups.Keys);
    }

    /// <summary>
    /// V-2: закрепление, созданное посредником уже после перевода часов назад, но до тика, не сдвигается второй раз и
    /// не снимается; созданное до перевода истекает через свои 300 с реального времени.
    /// </summary>
    [Fact]
    public async Task ClockSetBack_PinCreatedBeforeTick_IsNotShiftedTwice()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "secure.example", Target = vpn }] });
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithClockAsync(clock);
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        var early = Ipv4.Parse("93.184.216.34");
        var late = Ipv4.Parse("93.184.216.35");
        var ttl = TimeSpan.FromSeconds(300);

        var before = coordinator.ObservePinnedAsync(new PinnedRouteNotice("secure.example", "secure.example", vpn, [early], ttl), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await before);

        _world.Time.Advance(TimeSpan.FromSeconds(100));
        clock.Offset = -TimeSpan.FromHours(1);
        var after = coordinator.ObservePinnedAsync(new PinnedRouteNotice("secure.example", "secure.example", vpn, [late], ttl), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await after);
        await TickAsync(coordinator);

        Assert.Contains(late, coordinator.Facts.Pinned.Keys);
        Assert.Contains(early, coordinator.Facts.Pinned.Keys);
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(late, 32));

        // Через 301 с реального времени от первого ответа: первое закрепление истекло, второе ещё живо.
        _world.Time.Advance(TimeSpan.FromSeconds(201));
        await TickAsync(coordinator);
        Assert.DoesNotContain(early, coordinator.Facts.Pinned.Keys);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(early, 32));
        Assert.Contains(late, coordinator.Facts.Pinned.Keys);
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(late, 32));

        // И второе истекает через свои 300 с.
        _world.Time.Advance(TimeSpan.FromSeconds(100));
        await TickAsync(coordinator);
        Assert.DoesNotContain(late, coordinator.Facts.Pinned.Keys);
    }

    /// <summary>
    /// V-3: соединение профиля A поднято с другими параметрами входа, и его разрыв не удаётся - дозвон держится только у A,
    /// профиль B поднимается.
    /// </summary>
    [Fact]
    public async Task MismatchedConnectionHangUpFailure_BlocksOnlyItsOwnTunnel()
    {
        var first = _profile with { Protocol = VpnProtocol.L2tpIpsec };
        var second = SecondProfile() with { Protocol = VpnProtocol.L2tpIpsec };
        SaveSettings(Settings() with { Profiles = [first, second] });
        _world.Secrets.Save(first.Id, "key", SecretKind.PreSharedKey);
        _world.Secrets.Save(second.Id, "key", SecretKind.PreSharedKey);
        var firstEntry = Coordinator.EntryNameFor(first);
        var secondEntry = Coordinator.EntryNameFor(second);
        _world.Ras.SaveEntry(firstEntry, first, "key");
        await _world.Ras.DialAsync(firstEntry, "user", "secret".AsMemory(), null, CancellationToken.None);
        var dialed = _world.Ras.DialOrder.Count;
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 668);
        // Служба запускается с намерением «подключено» (перезапуск, автоподключение): подхват идёт в стартовой сверке.
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected });

        var coordinator = await StartAsync();
        await TickAsync(coordinator);

        Assert.True(_world.Ras.HangUps > 0, Dump(coordinator));
        Assert.Contains(secondEntry, _world.Ras.ConnectedEntries);
        Assert.NotNull(coordinator.Facts.Tunnels[second.Id].Connection);
        Assert.False(_world.Ras.DialOrder.Skip(dialed).Contains(firstEntry), Dump(coordinator));
        Assert.Null(coordinator.Facts.Tunnels[first.Id].Connection);
        Assert.NotNull(coordinator.Facts.PartialError);
    }

    /// <summary>
    /// V-4: подъём по очереди, первым идёт AnyConnect, у которого не читается пароль, - очередь отпускает следующий
    /// туннель, он дозванивается.
    /// </summary>
    [Fact]
    public async Task SequentialDial_AnyConnectPreparationFailure_ReleasesQueue()
    {
        var anyConnect = _anyConnect with { SavePassword = true };
        var l2tp = _profile with { Protocol = VpnProtocol.L2tpIpsec };
        _world.Resolver.Answers[Gateway] = [GatewayAddress];
        SaveSettings(Settings() with { Profiles = [anyConnect, l2tp], SequentialDial = true });
        _world.Secrets.Save(l2tp.Id, "key", SecretKind.PreSharedKey);
        _world.Secrets.FailLoad.Add(anyConnect.Id);
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.Empty(_world.AnyConnect.Sessions);
        Assert.Contains("пароль", coordinator.Facts.Tunnels[anyConnect.Id].LastErrorText, StringComparison.Ordinal);
        Assert.Contains(Coordinator.EntryNameFor(l2tp), _world.Ras.ConnectedEntries);
        Assert.NotNull(coordinator.Facts.Tunnels[l2tp.Id].Connection);
    }

    /// <summary>
    /// V-5: проверка не пройдена, разрыв не удался (отложен), и сеанс упал сам - неудача не засчитывается второй раз,
    /// назначенный срок дозвона сохраняется.
    /// </summary>
    [Fact]
    public async Task DeferredHangUp_SessionDropsByItself_KeepsScheduledRetry()
    {
        _world.Probes.TunnelWorks = false;
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 668);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        for (var i = 0; i < Coordinator.VerifyProbeAttempts + 1 && tunnel.VerifyFailures == 0; i++)
        {
            _world.Time.Advance(Coordinator.VerifyProbeInterval);
            await TickAsync(coordinator);
        }

        Assert.True(tunnel.HangUpPending, Dump(coordinator));
        Assert.Equal(1, tunnel.DialAttempt);
        var scheduled = tunnel.NextDialAt;
        Assert.True(scheduled > _world.Time.GetUtcNow());

        _world.Ras.StatusOverride[Coordinator.EntryNameFor(_profile)] = RasConnectionStatus.Disconnected;
        await TickAsync(coordinator);

        Assert.Null(tunnel.Connection);
        Assert.False(tunnel.HangUpPending);
        Assert.Equal(scheduled, tunnel.NextDialAt);
        Assert.Equal(1, tunnel.DialAttempt);
        Assert.Equal(1, _world.Ras.Dials);
    }

    /// <summary>
    /// V-6: запись DNS не удаётся на постороннем адаптере (на нём прежнего адреса Wi-Fi нет) - сменившийся адрес Wi-Fi
    /// всё равно освобождается, а сбой по-прежнему виден как неполное применение.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OtherAdapterDnsWriteFailure_DoesNotHoldReleasedAddress(bool tunnelAdapter)
    {
        var radmin = Guid.NewGuid();
        _world.Inventory.RadminGuid = radmin;
        _world.Inventory.RadminDnsServers = [Ipv4.Parse("26.0.0.53")];
        _world.Proxy.ServesAdapterAddresses = true;
        var released = new List<uint>();
        _world.Proxy.OnRelease = released.Add;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal([FakeWorld.WiFiAddress], _world.Proxy.Claimed);

        var failing = tunnelAdapter ? FakeWorld.TunnelGuid : radmin;
        // DNS, изменённый извне: сверка пытается вернуть посредника, и запись падает.
        _world.Dns.NameServers[failing] = "26.0.0.53";
        _world.Dns.FailLoopback.Add(failing);
        var next = Ipv4.Parse("192.168.1.101");
        _world.Inventory.WiFiAddress = next;
        await TickAsync(coordinator);

        Assert.Equal("192.168.1.101,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal([FakeWorld.WiFiAddress], released);
        Assert.Equal([next], _world.Proxy.Claimed);
        Assert.NotNull(coordinator.Facts.PartialError);
    }

    /// <summary>V-6: запись DNS не удалась на самом адаптере, где прежний адрес ещё стоит DNS-сервером, - он остаётся занятым.</summary>
    [Fact]
    public async Task OwnAdapterDnsWriteFailure_KeepsAddressStillListed()
    {
        _world.Proxy.ServesAdapterAddresses = true;
        var released = new List<uint>();
        _world.Proxy.OnRelease = released.Add;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal("192.168.1.100,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);

        _world.Dns.FailLoopback.Add(FakeWorld.WiFiGuid);
        _world.Inventory.WiFiAddress = Ipv4.Parse("192.168.1.101");
        await TickAsync(coordinator);

        Assert.Equal("192.168.1.100,127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Empty(released);
        Assert.Contains(FakeWorld.WiFiAddress, _world.Proxy.Claimed);
    }

    /// <summary>V-7: узел шлюза сверх предела узлов попадает в журнал - маскированный отчёт его скрывает.</summary>
    [Fact]
    public async Task AnyConnect_NodeOverLimit_IsMaskedInReport()
    {
        const string hidden = "hidden-over.corp-secret.example";
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        for (var i = 0; i < 8; i++)
        {
            session.Emit(new ResolveHostEvent(Ipv4.Format(Ipv4.Parse("203.0.113.10") + (uint)i)));
            await CompleteDialAsync(coordinator);
        }

        session.Emit(new ResolveHostEvent(hidden));
        await CompleteDialAsync(coordinator);

        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("слишком много узлов", StringComparison.Ordinal) && e.Text.Contains(hidden, StringComparison.Ordinal));
        var masked = (await coordinator.HandleRequestAsync(new ExportReportRequest(MaskPersonalData: true), CancellationToken.None)).ResultAs<string>()!;
        Assert.DoesNotContain(hidden, masked, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>V-7: порт узла шлюза сверх предела портов попадает в журнал - маскированный отчёт скрывает имя узла.</summary>
    [Fact]
    public async Task AnyConnect_NodePortOverLimit_IsMaskedInReport()
    {
        const string hidden = "hidden-port.corp-secret.example";
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        for (var i = 0; i < 8; i++)
        {
            session.Emit(new ResolveHostEvent(Gateway, 9001 + i));
            await CompleteDialAsync(coordinator);
        }

        session.Emit(new ResolveHostEvent(hidden, 9100));
        await CompleteDialAsync(coordinator);

        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("превышает ограничения", StringComparison.Ordinal) && e.Text.Contains(hidden, StringComparison.Ordinal));
        var masked = (await coordinator.HandleRequestAsync(new ExportReportRequest(MaskPersonalData: true), CancellationToken.None)).ResultAs<string>()!;
        Assert.DoesNotContain(hidden, masked, StringComparison.OrdinalIgnoreCase);
    }
}
