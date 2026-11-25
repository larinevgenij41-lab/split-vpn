using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Recovery;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;

namespace SplitVpn.Service.Tests;

/// <summary>Служба после экстренного отключения («пустая»), сброс DNS без копии и запоминание DNS, сменённого извне.</summary>
public sealed partial class CoordinatorTests
{
    private static readonly DateTimeOffset EmergencySince = new(2026, 11, 25, 8, 0, 0, TimeSpan.Zero);

    private int _wcmDisables;
    private int _manualStartChecks;

    private ServiceDependencies EmergencyDependencies() => _world.Dependencies() with
    {
        EmergencyFlag = () => new EmergencyFlag(EmergencySince),
        EnsureManualStart = () => { _manualStartChecks++; return "был тип запуска auto"; },
        DisableWifiBadStateTracking = () => { _wcmDisables++; return true; },
    };

    private async Task<Coordinator> StartInertAsync()
    {
        var coordinator = new Coordinator(EmergencyDependencies());
        await coordinator.StartupAsync(CancellationToken.None);
        return coordinator;
    }

    [Fact]
    public async Task Emergency_InertStart_AppliesNothing_EvenWithConnectedIntent()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected });

        var coordinator = await StartInertAsync();
        for (var i = 0; i < 3; i++)
        {
            _world.Time.Advance(Coordinator.FullReconcileInterval);
            await TickAsync(coordinator);
        }

        Assert.Equal(0, _wcmDisables);
        Assert.Equal(1, _manualStartChecks);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.Empty(_world.Wfp.Groups);
        Assert.Equal(0, _world.Wfp.Replacements);
        Assert.Empty(_world.Routes.Current);
        Assert.False(_world.Proxy.IsRunning);
        var status = coordinator.BuildStatus();
        Assert.True(status.EmergencyOff);
        Assert.Equal(EmergencySince, status.EmergencyOffSinceUtc);
        Assert.Equal(ConnectionState.Disconnected, status.State);
    }

    [Fact]
    public async Task Emergency_InertStart_HealsLeftoversOfPartialOff()
    {
        // Остатки неполного отключения: фильтры, свой маршрут, DNS из копии и наш loopback без копии.
        _world.Wfp.Groups[FilterGroup.Base] = [];
        _world.Routes.Current.Add(new RouteKey(Ipv4Cidr.Parse("10.0.0.0/8"), FakeWorld.Gateway, FakeWorld.WiFiLuid));
        _world.Dns.NameServers[FakeWorld.WiFiGuid] = "192.168.1.100,127.0.0.1";
        _world.Dns.NameServersV6[FakeWorld.WiFiGuid] = "::1";
        new DnsBackupStore(_world.Paths.DnsBackup).Upsert(new InterfaceDnsBackup(FakeWorld.WiFiGuid, "77.88.8.8", "", "", 0, DateTimeOffset.UnixEpoch));
        var orphan = FakeInventory.TunnelGuid(2);
        _world.Dns.NameServers[orphan] = "127.0.0.1";
        _world.Inventory.Extra.Add(Adapter(orphan, "Ethernet 2"));

        await StartInertAsync();

        Assert.Empty(_world.Wfp.Groups);
        Assert.Empty(_world.Routes.Current);
        Assert.Equal("77.88.8.8", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal("", _world.Dns.NameServersV6[FakeWorld.WiFiGuid]);
        Assert.Equal("", _world.Dns.NameServers[orphan]);
        Assert.Empty(new DnsBackupStore(_world.Paths.DnsBackup).Load());
    }

    [Fact]
    public async Task Emergency_IntentRequests_AreRefused_ReadsAndRecoverWork()
    {
        var coordinator = await StartInertAsync();

        foreach (var request in new IpcRequest[]
        {
            new ConnectRequest(null, null), new DisconnectRequest(KeepProtection: true), new TestProfileRequest(_profile.Id),
            new SetTunnelPausedRequest(_profile.Id, Paused: false), new GeoUpdateNowRequest(),
        })
        {
            var direct = await coordinator.HandleRequestAsync(request, CancellationToken.None);
            var queued = await coordinator.SubmitAsync(request, CancellationToken.None);
            foreach (var response in new[] { direct, queued })
            {
                Assert.False(response.Ok, request.GetType().Name);
                Assert.Equal(IpcErrorCodes.EmergencyOff, response.ErrorCode);
                Assert.Equal(IpcErrorCodes.EmergencyOffMessage, response.ErrorMessage);
            }
        }

        Assert.True((await coordinator.HandleRequestAsync(new GetStatusRequest(), CancellationToken.None)).Ok);
        Assert.True((await coordinator.HandleRequestAsync(new GetSettingsRequest(), CancellationToken.None)).Ok);

        // «Восстановить сеть» повторяет очистку, а не меняет намерение.
        _world.Wfp.Groups[FilterGroup.Base] = [];
        var recover = await coordinator.HandleRequestAsync(new RecoverNetworkRequest(), CancellationToken.None);
        Assert.True(recover.Ok);
        Assert.Empty(_world.Wfp.Groups);
        Assert.Equal(0, _world.Ras.Dials);
    }

    /// <summary>
    /// Программу могли выключить из-за ошибки, которую исправляет обновление: проверка и загрузка по команде
    /// пользователя работают, а сама «пустая» служба выпуски не проверяет.
    /// </summary>
    [Fact]
    public async Task Emergency_UserUpdateRequests_Work_BackgroundCheckStaysOff()
    {
        var source = new UpdateSource(Manifest());
        _world.HttpHandler = source;
        var coordinator = await StartInertAsync();

        for (var i = 0; i < 3; i++)
        {
            _world.Time.Advance(TimeSpan.FromDays(2));
            await TickAsync(coordinator);
        }

        await PumpAsync(coordinator);
        Assert.Equal(0, source.ManifestCalls);

        var check = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, check);
        var checkResponse = await check;
        Assert.True(checkResponse.Ok, checkResponse.ErrorMessage);
        Assert.True(source.ManifestCalls > 0);
        Assert.Equal("0.9.0", Status(coordinator).AvailableVersion);

        foreach (var request in new IpcRequest[] { new CheckUpdateRequest(), new DownloadUpdateRequest("0.9.0"), new InstallUpdateRequest("0.9.0") })
        {
            var queued = coordinator.SubmitAsync(request, CancellationToken.None);
            await PumpAsync(coordinator, queued);
            Assert.NotEqual(IpcErrorCodes.EmergencyOff, (await queued).ErrorCode);
        }
    }

    [Fact]
    public async Task Emergency_ReadFailure_RunsNormally()
    {
        var coordinator = new Coordinator(_world.Dependencies() with { EmergencyFlag = () => throw new UnauthorizedAccessException("нет доступа") });
        await coordinator.StartupAsync(CancellationToken.None);

        Assert.False(coordinator.BuildStatus().EmergencyOff);
    }

    /// <summary>«Восстановить сеть» работающей службы сбрасывает наш DNS, оставшийся без копии, как и команда без службы.</summary>
    [Fact]
    public async Task RecoverNetwork_ResetsOrphanLoopbackDns()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var orphan = FakeInventory.TunnelGuid(2);
        _world.Dns.NameServers[orphan] = "10.9.9.9,127.0.0.1";
        _world.Dns.NameServersV6[orphan] = "::1";
        _world.Inventory.Extra.Add(Adapter(orphan, "Ethernet 2"));

        var response = await coordinator.HandleRequestAsync(new RecoverNetworkRequest(), CancellationToken.None);

        Assert.True(response.Ok, response.ErrorMessage);
        Assert.Equal("", _world.Dns.NameServers[orphan]);
        Assert.Equal("", _world.Dns.NameServersV6[orphan]);
        Assert.Equal("", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Contains(_world.Dns.Resets, r => r.Interface == orphan && r.V4 && r.V6);
    }

    /// <summary>
    /// Без посредника (порт 53 не наш) loopback адаптера без копии, который слушает чужой резолвер, — DNS пользователя:
    /// «Восстановить сеть» его не трогает.
    /// </summary>
    [Fact]
    public async Task RecoverNetwork_KeepsUserResolverLoopback_WhenSomeoneListens()
    {
        var coordinator = new Coordinator(_world.Dependencies() with { LoopbackResolverListeners = () => (true, true) });
        await coordinator.StartupAsync(CancellationToken.None);
        var orphan = FakeInventory.TunnelGuid(2);
        _world.Dns.NameServers[orphan] = "127.0.0.1";
        _world.Inventory.Extra.Add(Adapter(orphan, "Ethernet 2"));
        Assert.False(_world.Proxy.IsRunning);

        await coordinator.HandleRequestAsync(new RecoverNetworkRequest(), CancellationToken.None);

        Assert.Equal("127.0.0.1", _world.Dns.NameServers[orphan]);
    }

    /// <summary>
    /// DNS адаптера сменили на не наш, пока VPN включён: новое значение — последний выбор пользователя. Оно записывается в
    /// копию до того, как адаптеру снова ставится посредник, и возвращается при отключении.
    /// </summary>
    [Fact]
    public async Task ExternalDnsChange_BecomesBackup_ThenProxyReapplied()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal("", new DnsBackupStore(_world.Paths.DnsBackup).Load()[FakeWorld.WiFiGuid].NameServerV4);

        _world.Dns.NameServers[FakeWorld.WiFiGuid] = "1.1.1.1 9.9.9.9";
        _world.Dns.NameServersV6[FakeWorld.WiFiGuid] = "2606:4700::1111";
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        var backup = new DnsBackupStore(_world.Paths.DnsBackup).Load()[FakeWorld.WiFiGuid];
        Assert.Equal("1.1.1.1 9.9.9.9", backup.NameServerV4);
        Assert.Equal("2606:4700::1111", backup.NameServerV6);
        Assert.True(InterfaceDnsOps.IsProxySet(_world.Dns.NameServers[FakeWorld.WiFiGuid]));
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("запомнено как исходное", StringComparison.Ordinal));

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        Assert.Equal("1.1.1.1 9.9.9.9", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal("2606:4700::1111", _world.Dns.NameServersV6[FakeWorld.WiFiGuid]);
    }

    /// <summary>Запись посредника не удалась, и на адаптере остался исходный DNS: это не правка пользователя, копия прежняя.</summary>
    [Fact]
    public async Task FailedLoopbackWrite_DoesNotRewriteBackup()
    {
        _world.Dns.NameServers[FakeWorld.WiFiGuid] = "192.168.1.1";
        var coordinator = await StartAsync();
        _world.Dns.FailLoopback.Add(FakeWorld.WiFiGuid);
        await ConnectAsync(coordinator);
        var before = new DnsBackupStore(_world.Paths.DnsBackup).Load()[FakeWorld.WiFiGuid];

        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        Assert.Equal(before, new DnsBackupStore(_world.Paths.DnsBackup).Load()[FakeWorld.WiFiGuid]);
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.Contains("запомнено как исходное", StringComparison.Ordinal));
    }

    private static AdapterCandidate Adapter(Guid guid, string name) => new()
    {
        Luid = 77,
        InterfaceIndex = 77,
        InterfaceGuid = guid,
        Name = name,
        Description = "Ethernet",
        IfType = 6,
        IsUp = false,
    };
}
