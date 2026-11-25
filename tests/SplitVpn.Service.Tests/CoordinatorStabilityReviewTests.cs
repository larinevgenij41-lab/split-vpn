using System.Security.Cryptography;
using System.Text;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Ревью стабильности 2026-11-24: сбой RAS не останавливает сверку, перевод часов назад не замораживает сроки, сбой
/// шага тика не обходит паузу, запись состояния после отключения извне, запуск помощника AnyConnect, остановка
/// службы, копии сертификатов, список суффиксов DNS и повреждённая RU-база.
/// </summary>
public sealed partial class CoordinatorTests
{
    private async Task<Coordinator> StartWithClockAsync(TimeProvider clock)
    {
        var coordinator = new Coordinator(_world.Dependencies() with { Time = clock });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        return coordinator;
    }

    private static bool UsesInterface(FilterSpec filter, ulong luid) =>
        filter.Conditions.OfType<LocalInterfaceCondition>().Any(c => c.Luid == luid);

    /// <summary>S-1: RasMan сбоит, а Wi-Fi сменился - защита всё равно перестраивается под новый адаптер.</summary>
    [Fact]
    public async Task RasEnumerationFailure_NetworkChange_StillRebuildsProtection()
    {
        const ulong NewWiFiLuid = 9;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Contains(_world.Wfp.Groups.Values.SelectMany(g => g), f => UsesInterface(f, FakeWorld.WiFiLuid));

        _world.Ras.FailFind = true;
        _world.Inventory.WiFiLuid = NewWiFiLuid;
        _world.Inventory.WiFiAddress = Ipv4.Parse("192.168.1.150");
        await TickAsync(coordinator);

        Assert.Equal(NewWiFiLuid, coordinator.Facts.Primary!.Luid);
        var filters = _world.Wfp.Groups.Values.SelectMany(g => g).ToList();
        Assert.Contains(FilterGroup.Base, _world.Wfp.Groups.Keys);
        Assert.Contains(filters, f => UsesInterface(f, NewWiFiLuid));
        Assert.DoesNotContain(filters, f => UsesInterface(f, FakeWorld.WiFiLuid));
        Assert.NotNull(coordinator.Facts.PartialError);
    }

    /// <summary>S-1: служба запускается при сбоящем RasMan - посредник DNS и фильтры есть, дозвона поверх неизвестного сеанса нет.</summary>
    [Fact]
    public async Task RasEnumerationFailure_AtStartup_StillStartsDnsAndProtection()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected });
        _world.Ras.FailFind = true;

        var coordinator = await StartAsync();

        Assert.True(_world.Proxy.IsRunning);
        Assert.Contains(FilterGroup.Base, _world.Wfp.Groups.Keys);
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.NotNull(coordinator.Facts.PartialError);

        // RasMan ожил: повтор по паузе после ошибки поднимает туннель.
        _world.Ras.FailFind = false;
        _world.Time.Advance(TimeSpan.FromSeconds(2));
        await TickAsync(coordinator);
        Assert.Equal(1, _world.Ras.Dials);
        Assert.Null(coordinator.Facts.PartialError);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>S-2: неудачный дозвон, затем часы перевели назад на 3 часа - повтор идёт через обычную паузу.</summary>
    [Fact]
    public async Task ClockSetBack_DialRetryIsNotPostponed()
    {
        var clock = new ShiftedTimeProvider(_world.Time);
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        var coordinator = await StartWithClockAsync(clock);
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        Assert.Equal(1, _world.Ras.Dials);
        var backoff = coordinator.Facts.Tunnels[_profile.Id].NextDialAt - clock.GetUtcNow();

        clock.Offset = -TimeSpan.FromHours(3);
        _world.Time.Advance((backoff > TimeSpan.Zero ? backoff : TimeSpan.Zero) + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("Часы Windows переведены назад", StringComparison.Ordinal));
    }

    /// <summary>S-2: ожидание после подключения Wi-Fi не растягивается на величину перевода часов назад.</summary>
    [Fact]
    public async Task ClockSetBack_WifiHoldDoesNotStretch()
    {
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithClockAsync(clock);
        coordinator.OnWifiEvent(new WifiEvent(WifiEventKind.Connected, FakeWorld.WiFiGuid, clock.GetUtcNow(), ""));
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        Assert.Equal(0, _world.Ras.Dials);

        clock.Offset = -TimeSpan.FromHours(1);
        _world.Time.Advance(TimeSpan.FromSeconds(25));
        await TickAsync(coordinator);

        Assert.True(_world.Ras.Dials > 0, Dump(coordinator));
        Assert.True(_world.Ras.Connected, Dump(coordinator));
    }

    /// <summary>S-2: часы ушли вперёд (сон, поправка вперёд) - сроки не трогаются и записи о переводе нет.</summary>
    [Fact]
    public async Task ClockJumpForward_IsNotTreatedAsSetBack()
    {
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithClockAsync(clock);
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);

        clock.Offset = TimeSpan.FromHours(2);
        await TickAsync(coordinator);

        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.Contains("Часы Windows переведены назад", StringComparison.Ordinal));
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>S-3: шаг тика падает на каждом тике - полная сверка идёт по нарастающей паузе, а не каждые 2 с.</summary>
    [Fact]
    public async Task FailingTickStep_DoesNotBypassRetryPause()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Inventory.FailCapture = true;

        var reconciles = 0;
        for (var i = 0; i < 10; i++)
        {
            _world.Time.Advance(Coordinator.TickInterval);
            await TickAsync(coordinator);
            if (coordinator.Facts.LastFullReconcile == _world.Time.GetUtcNow())
            {
                reconciles++;
            }
        }

        Assert.InRange(reconciles, 1, 4);
    }

    /// <summary>S-4: отключение из меню Windows при занятом файле состояния - решение в журнале и потом на диске.</summary>
    [Fact]
    public async Task ExternalDisconnect_StateFileLocked_JournalsAndWritesLater()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.TerminationReason = 631;

        using (new FileStream(_world.Paths.State, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            _world.Ras.Drop();
            await TickAsync(coordinator);

            Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("отключён из меню сети Windows", StringComparison.Ordinal));
            Assert.Equal(Intent.Protected, coordinator.State.Intent);
        }

        await TickAsync(coordinator);
        Assert.Equal(Intent.Protected, new ServiceStores(_world.Paths).LoadState().Intent);
    }

    /// <summary>S-5: часы поправили назад в том же сеансе Windows - перезапуск службы не отменяет «Отключить».</summary>
    [Fact]
    public async Task AutoConnect_ClockCorrectedAfterBoot_RestartKeepsUserDisconnect()
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        _world.Uptime = TimeSpan.FromMinutes(1);
        var clock = new ShiftedTimeProvider(_world.Time);
        var first = await StartWithClockAsync(clock);
        Assert.Equal(Intent.Connected, first.State.Intent);
        await first.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        await TickAsync(first);

        clock.Offset = -TimeSpan.FromHours(1);
        await TickAsync(first);

        var restarted = await StartWithClockAsync(clock);
        Assert.Equal(Intent.Off, restarted.State.Intent);
    }

    /// <summary>S-6: secrets.bin занят при запуске помощника - сеанса без команды Start нет, вход не снят, потом сеанс начинается.</summary>
    [Fact]
    public async Task AnyConnect_PasswordReadFailure_DoesNotLeaveHelperWithoutStart()
    {
        var anyConnect = _anyConnect with { SavePassword = true };
        _world.Resolver.Answers[Gateway] = [GatewayAddress];
        SaveSettings(Settings() with { Profiles = [_profile, anyConnect] });
        _world.Secrets.FailLoad.Add(anyConnect.Id);
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[anyConnect.Id];
        Assert.Empty(_world.AnyConnect.Sessions);
        Assert.Null(tunnel.AnyConnect);
        Assert.Contains("пароль", tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.Contains(anyConnect.Id, coordinator.Facts.SignInApproved);

        _world.Secrets.FailLoad.Clear();
        await coordinator.ReconcileAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);

        var session = Assert.Single(_world.AnyConnect.Sessions);
        var start = Assert.IsType<StartCommand>(session.Commands[0]);
        Assert.Equal("secret", new string(start.Password));
    }

    /// <summary>S-8: снимок сети при остановке падает не IOException - помощник всё равно получает Stop.</summary>
    [Fact]
    public async Task ShutdownAnyConnect_UnexpectedRouteFailure_StillStopsHelpers()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        _world.Inventory.CaptureFailure = new UnauthorizedAccessException("нет доступа");

        var exits = coordinator.ShutdownAnyConnect();

        Assert.Contains(session.Commands, c => c is StopCommand);
        Assert.True(session.Disposed);
        session.ExitSource.TrySetResult();
        await exits.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
    }

    /// <summary>S-9: удаление ненужной копии сертификата не удалось - отпечаток уходит из списка, повтора нет.</summary>
    [Fact]
    public async Task CertificateCopyRemovalFailure_IsNotRetriedEveryReconcile()
    {
        const string Thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { AnyConnectCertificateCopies = [Thumbprint] });
        _world.AnyConnect.RemoveFailure = new CryptographicException("хранилище недоступно");

        var coordinator = await StartAsync();
        await coordinator.ReconcileAsync(CancellationToken.None);

        Assert.Single(_world.AnyConnect.RemovedCopies);
        Assert.Empty(coordinator.State.AnyConnectCertificateCopies!);
        Assert.Empty(new ServiceStores(_world.Paths).LoadState().AnyConnectCertificateCopies!);
    }

    /// <summary>S-10: запись списка суффиксов не удалась - суффикс прежнего шлюза не становится «исходным».</summary>
    [Fact]
    public async Task SearchListWriteFailure_GatewaySuffixDoesNotBecomeOriginal()
    {
        _world.Dns.SearchLists[FakeWorld.WiFiGuid] = "corp.example";
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        Assert.Equal("corp.example,office.example.org", _world.Dns.SearchLists[FakeWorld.WiFiGuid]);

        _world.Dns.FailSetSearchList = true;
        _world.Inventory.RemoveTunnel(AnyConnectSlot);
        session.Emit(new TerminatedEvent(TerminationKind.NetworkError, "DTLS и TLS не отвечают"));
        await CompleteDialAsync(coordinator);
        await coordinator.ReconcileAsync(CancellationToken.None);
        await coordinator.ReconcileAsync(CancellationToken.None);

        var backup = new DnsBackupStore(_world.Paths.DnsBackup).Load()[FakeWorld.WiFiGuid];
        Assert.DoesNotContain("office.example.org", backup.SearchList, StringComparison.OrdinalIgnoreCase);

        _world.Dns.FailSetSearchList = false;
        await coordinator.ReconcileAsync(CancellationToken.None);
        Assert.Equal("corp.example", _world.Dns.SearchLists[FakeWorld.WiFiGuid]);
    }

    /// <summary>S-7: список активной версии RU-базы повреждён - работает предыдущая, и база сразу скачивается заново.</summary>
    [Fact]
    public async Task GeoActiveRevisionDamaged_UsesPreviousAndRefetchesAtOnce()
    {
        var store = new GeoStore(_world.Paths.Geo);
        var bytes = Encoding.UTF8.GetBytes(GeoContent(1));
        var candidate = GeoStore.ComputeId(bytes);
        store.SaveRevision(bytes, new GeoRevision { Id = candidate, SourceId = "custom-url", V4Count = 1202 });
        store.Activate(candidate);
        await File.WriteAllTextAsync(Path.Combine(_world.Paths.Geo, "revisions", candidate, "list.txt"),
            "11.0.1.0/24", TestContext.Current.CancellationToken);
        var source = new GeoHttpSource();

        var coordinator = await StartGeoAsync(source);
        await ConnectAsync(coordinator);

        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "no-geo");
        Assert.Equal(DecisionSource.Geo, coordinator.Facts.Policy!.Classify(Ipv4.Parse("77.88.8.8")).Source);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("активная версия повреждена", StringComparison.Ordinal));
        Assert.True(new GeoStore(_world.Paths.Geo).LoadState().NextCheckUtc <= _world.Time.GetUtcNow());

        await coordinator.TickAsync(CancellationToken.None);
        await PumpAsync(coordinator, coordinator.GeoWork);

        var request = Assert.Single(source.Requests);
        Assert.Empty(request.ETag);
        Assert.Equal(DecisionSource.Geo, coordinator.Facts.Policy!.Classify(Ipv4.Parse("11.0.1.1")).Source);
        Assert.Equal(candidate, coordinator.BuildStatus().GeoRevision);
    }
}
