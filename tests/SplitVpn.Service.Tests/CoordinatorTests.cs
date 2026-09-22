using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests : IDisposable
{
    private readonly FakeWorld _world = new();
    private readonly ConnectionProfile _profile = new() { Name = "Нидерланды", Server = "203.0.113.10:4443", UserName = "user", Role = ProfileRole.Primary };

    public CoordinatorTests()
    {
        SeedGeo();
        new ServiceStores(_world.Paths).SaveSettings(Settings());
        _world.Secrets.Save(_profile.Id, "secret");
    }

    private AppSettings Settings() => new()
    {
        Profiles = [_profile],
        DefaultTarget = RouteTarget.Tunnel(_profile.Id),
    };

    public void Dispose() => _world.Dispose();

    [Fact]
    public async Task Connect_AppliesProtectionRoutesDnsAndVerifies()
    {
        var coordinator = await StartAsync();

        var response = await ConnectAsync(coordinator);

        Assert.True(response.Ok);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.Equal("203.0.113.10:4443", _world.Ras.SavedServer);
        Assert.True(_world.Wfp.HasTunnelPermit);
        Assert.Contains(_world.Routes.Current, r => r.Destination.PrefixLength == 1 && r.InterfaceLuid == FakeWorld.TunnelLuid);
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.Server, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
        Assert.Contains(_world.Routes.Current, r => r.Destination == Ipv4Cidr.Parse("77.88.0.0/18"));
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.TunnelGuid]);
        Assert.Equal(DnsProxyMode.Online, _world.Proxy.Configuration.Mode);
        Assert.Contains(_world.Proxy.Configuration.Tunnel!.Servers, s => s.Address.ToString() == "198.51.100.50");
    }

    [Fact]
    public async Task Protected_KeepsFiltersWithoutTunnel_AndNeverDials()
    {
        var coordinator = await StartAsync();

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);

        Assert.Equal(0, _world.Ras.Dials);
        Assert.Contains(FilterGroup.Base, _world.Wfp.Groups.Keys);
        Assert.False(_world.Wfp.HasTunnelPermit);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination.PrefixLength == 1);
        Assert.Equal(ConnectionState.Disconnected, coordinator.DeriveState());
        Assert.True(coordinator.BuildStatus().ProtectionActive);
    }

    [Fact]
    public async Task Off_RemovesEverything_AndRestoresDns()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);

        Assert.Empty(_world.Wfp.Groups);
        Assert.Empty(_world.Routes.Current);
        Assert.False(_world.Ras.Connected);
        Assert.Equal("", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.False(coordinator.BuildStatus().ProtectionActive);
    }

    [Fact]
    public async Task AuthenticationFailure_StopsRetries()
    {
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 691, "Отказано в доступе"));
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(5));
        await TickAsync(coordinator);

        Assert.Equal(1, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Error, coordinator.DeriveState());
        Assert.Equal(ErrorCategory.Authentication, coordinator.BuildStatus().ErrorCategory);
    }

    [Fact]
    public async Task TransientFailure_RetriesWithBackoff()
    {
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);
        Assert.Equal(ConnectionState.Connecting, coordinator.DeriveState());
        await TickAsync(coordinator);
        Assert.Equal(1, _world.Ras.Dials);

        _world.Time.Advance(TimeSpan.FromSeconds(3));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task ConnectionDrop_BlocksAndRedials()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        _world.Ras.Drop();
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        await TickAsync(coordinator);

        Assert.False(_world.Wfp.HasTunnelPermit);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination.PrefixLength == 1);
        Assert.Equal(ConnectionState.Reconnecting, coordinator.DeriveState());
        Assert.Equal(DnsProxyMode.Offline, _world.Proxy.Configuration.Mode);

        // Сеанс оборвался, не продержавшись минуты: следующий дозвон идёт с паузой, а не сразу.
        _world.Time.Advance(TimeSpan.FromSeconds(3));
        await TickAsync(coordinator);
        Assert.Equal(2, _world.Ras.Dials);

        _world.Time.Advance(TimeSpan.FromSeconds(5));
        await TickAsync(coordinator);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.Equal(3, _world.Ras.Dials);
    }

    [Fact]
    public async Task Startup_AdoptsExistingConnection_WithoutDialing()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected });
        _world.Ras.SaveEntry(Coordinator.EntryNameFor(_profile), _profile, []);
        await _world.Ras.DialAsync(Coordinator.EntryNameFor(_profile), "user", "secret".AsMemory(), null, CancellationToken.None);
        var dials = _world.Ras.Dials;

        var coordinator = await StartAsync();
        await TickAsync(coordinator);

        Assert.Equal(dials, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.True(_world.Wfp.HasTunnelPermit);
    }

    [Fact]
    public async Task WfpFailure_IsPartialApplication_ThenRecovers()
    {
        var coordinator = await StartAsync();
        _world.Wfp.FailNextReplace = 1;

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);

        Assert.Equal(ConnectionState.PartiallyApplied, coordinator.DeriveState());
        Assert.Contains("Неполное применение", coordinator.BuildStatus().ErrorText, StringComparison.Ordinal);
        Assert.True(_world.Wfp.Reopens > 0);

        // Повтор сверки после неполного применения ждёт паузу (первая — 2 с).
        _world.Time.Advance(TimeSpan.FromSeconds(2));
        await TickAsync(coordinator);

        Assert.Equal(ConnectionState.Disconnected, coordinator.DeriveState());
        Assert.Contains(FilterGroup.Base, _world.Wfp.Groups.Keys);
    }

    [Fact]
    public async Task PeriodicReconcile_RestoresExternalDrift()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var directCount = _world.Wfp.Groups[FilterGroup.Direct].Count;
        var routeCount = _world.Routes.Current.Count;
        var replacements = _world.Wfp.Replacements;

        _world.Wfp.RemoveOne(FilterGroup.Direct);
        _world.Routes.Current.Remove(_world.Routes.Current.First(r => r.Destination.PrefixLength > 1));
        _world.Dns.NameServers[FakeWorld.WiFiGuid] = "8.8.8.8";
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        Assert.Equal(directCount, _world.Wfp.Groups[FilterGroup.Direct].Count);
        Assert.Equal(routeCount, _world.Routes.Current.Count);
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal(replacements + 1, _world.Wfp.Replacements);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());

        // Внешний DNS не становится «исходным»: после отключения возвращается исходный (пустой, DHCP).
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        Assert.Equal("", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
    }

    [Fact]
    public async Task Suspended_AppliesNothing_UntilConnect()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected, ProtectionSuspended = true });

        var coordinator = await StartAsync();
        await TickAsync(coordinator);

        Assert.Empty(_world.Wfp.Groups);
        Assert.Equal(0, _world.Ras.Dials);

        await ConnectAsync(coordinator);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.False(coordinator.State.ProtectionSuspended);
    }

    [Fact]
    public async Task MissingPassword_IsReported_AndConnectWithPasswordWorks()
    {
        _world.Secrets.Delete(_profile.Id);
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);
        Assert.Equal(ConnectionState.PasswordRequired, coordinator.DeriveState());

        var response = await coordinator.HandleRequestAsync(new ConnectRequest(null, "new-secret"), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(response.Ok);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.Equal("new-secret", _world.Secrets.Saved[_profile.Id]);
    }

    [Fact]
    public async Task DisablingSavePassword_DeletesStoredSecret_KeepsMemoryPassword()
    {
        var coordinator = await StartAsync();
        var settings = coordinator.Settings with { Profiles = [_profile with { SavePassword = false }] };

        await coordinator.HandleRequestAsync(new SaveSettingsRequest(settings), CancellationToken.None);
        Assert.False(_world.Secrets.Contains(_profile.Id));

        await coordinator.HandleRequestAsync(new SetPasswordRequest(_profile.Id, "memory-only"), CancellationToken.None);
        await ConnectAsync(coordinator);

        Assert.False(_world.Secrets.Contains(_profile.Id));
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task VerificationFailure_HangsUpAndRetries()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);
        // Живой сеанс рвёт только исчерпанный счёт проб: одна непройденная проба его сохраняет.
        await ExhaustProbesAsync(coordinator, coordinator.Facts.Tunnels[_profile.Id]);

        Assert.NotEqual(ConnectionState.Connected, coordinator.DeriveState());
        Assert.False(_world.Ras.Connected);
        Assert.Equal(ErrorCategory.NoInternetInTunnel, coordinator.BuildStatus().ErrorCategory);
    }

    [Fact]
    public async Task InvalidSettings_AreRejected_WithoutChanges()
    {
        var coordinator = await StartAsync();
        var bad = coordinator.Settings with { Rules = [new UserRuleSetting { Cidr = "2a00::/16" }] };

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(bad), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidSettings, response.ErrorCode);
        Assert.Empty(coordinator.Settings.Rules);
    }

    [Fact]
    public async Task CheckAddress_ExplainsDecision()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var response = await coordinator.HandleRequestAsync(new CheckAddressRequest("77.88.55.242"), CancellationToken.None);
        var result = response.ResultAs<AddressCheckDto>()!;

        var item = Assert.Single(result.Items);
        Assert.Equal("Direct", item.Decision);
        Assert.Equal("напрямую", item.TargetName);
        Assert.Equal("Беспроводная сеть", item.ExpectedInterface);
    }

    [Fact]
    public async Task NoGeoBase_SendsEverythingToDefaultTarget_WithWarning()
    {
        Directory.Delete(_world.Paths.Geo, recursive: true);
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        var status = coordinator.BuildStatus();
        Assert.Equal(status.DefaultTargetName, status.GeoTargetName);
        Assert.Contains(status.Warnings, w => w.Code == "no-geo");
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == Ipv4Cidr.Parse("77.88.0.0/18"));
    }

    [Fact]
    public async Task SettingsThatDisableConnectedProfile_AreRejected()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var response = await coordinator.HandleRequestAsync(
            new SaveSettingsRequest(coordinator.Settings with { Profiles = [_profile with { Role = ProfileRole.Off }] }),
            CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidSettings, response.ErrorCode);
        Assert.True(_world.Ras.Connected);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task ConnectedIntent_WithoutProfile_IsError_AndDisconnectRestores()
    {
        // Настройки без профилей на диске, намерение «Подключено» (например, после ручной правки файла).
        new ServiceStores(_world.Paths).SaveSettings(new AppSettings());
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected });

        var coordinator = await StartAsync();
        await TickAsync(coordinator);

        Assert.Equal(ConnectionState.Error, coordinator.DeriveState());
        Assert.Contains("подключени", coordinator.BuildStatus().ErrorText, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, _world.Ras.Dials);

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        Assert.Empty(_world.Wfp.Groups);
        Assert.Equal(ConnectionState.Disconnected, coordinator.DeriveState());
    }

    [Fact]
    public async Task ExternalDisconnect_KeepsProtection_AndWaitsForUser()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var dials = _world.Ras.Dials;

        _world.TerminationReason = 631;
        _world.Ras.Drop();
        await TickAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);

        Assert.Equal(dials, _world.Ras.Dials);
        Assert.Equal(ConnectionState.DisconnectedExternally, coordinator.DeriveState());
        Assert.Equal(Intent.Protected, coordinator.State.Intent);
        Assert.True(coordinator.BuildStatus().ProtectionActive);
        Assert.False(_world.Wfp.HasTunnelPermit);

        await ConnectAsync(coordinator);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task ExternalDisconnect_WithAutoConnect_Redials()
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        _world.TerminationReason = 631;
        _world.Ras.Drop();
        await TickAsync(coordinator);
        // Короткий сеанс: повтор не сразу, а после паузы.
        _world.Time.Advance(TimeSpan.FromSeconds(3));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(60, false)]
    public async Task AutoConnect_OnlyRightAfterBoot(int uptimeMinutes, bool expectConnected)
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        _world.Uptime = TimeSpan.FromMinutes(uptimeMinutes);

        var coordinator = await StartAsync();
        await CompleteDialAsync(coordinator);

        Assert.Equal(expectConnected ? Intent.Connected : Intent.Off, coordinator.State.Intent);
        Assert.Equal(expectConnected ? 1 : 0, _world.Ras.Dials);
    }

    [Fact]
    public async Task AutoConnect_RequiresSavedPassword()
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        _world.Secrets.Delete(_profile.Id);
        _world.Uptime = TimeSpan.FromMinutes(1);

        var coordinator = await StartAsync();

        Assert.Equal(Intent.Off, coordinator.State.Intent);
        Assert.Equal(0, _world.Ras.Dials);
    }

    [Fact]
    public async Task ProfileTest_WhenOff_DialsAndHangsUp()
    {
        var coordinator = await StartAsync();

        var response = await coordinator.BeginProfileTest(_profile.Id);
        var result = response.ResultAs<ProfileTestDto>()!;

        Assert.True(response.Ok);
        Assert.True(result.Success, result.Text);
        Assert.Contains("192.168.44.20", result.Text, StringComparison.Ordinal);
        Assert.False(_world.Ras.Connected);
        Assert.Equal(Intent.Off, coordinator.State.Intent);
        Assert.Empty(_world.Wfp.Groups);
    }

    [Fact]
    public async Task ProfileTest_WhenConnected_ReportsSession()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var result = (await coordinator.BeginProfileTest(_profile.Id)).ResultAs<ProfileTestDto>()!;

        Assert.True(result.Success);
        Assert.Contains("подключено", result.Text, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, _world.Ras.Dials);
    }

    [Fact]
    public async Task ProfileTest_WhenProtected_IsRefused()
    {
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);

        var response = await coordinator.BeginProfileTest(_profile.Id);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Busy, response.ErrorCode);
    }

    [Fact]
    public async Task ProfileTest_ClassifiesAuthenticationFailure()
    {
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 691, "Отказано в доступе"));
        var coordinator = await StartAsync();

        var result = (await coordinator.BeginProfileTest(_profile.Id)).ResultAs<ProfileTestDto>()!;

        Assert.False(result.Success);
        Assert.Contains("691", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GeoUpdate_IsDeferredOnMeteredNetwork()
    {
        _world.Metered = true;
        var coordinator = await StartAsync();

        _world.Time.Advance(TimeSpan.FromDays(2));
        await TickAsync(coordinator);

        var status = coordinator.BuildStatus();
        Assert.Contains("лимитная", status.GeoLastResult, StringComparison.OrdinalIgnoreCase);
        Assert.True(status.GeoNextCheckUtc > _world.Time.GetUtcNow());
    }

    [Fact]
    public async Task Conflicts_AreReportedAsWarnings_Once()
    {
        _world.Conflicts.Add(new StatusWarning("foreign-vpn", "Активно другое VPN-подключение «Garant».", null));
        var coordinator = await StartAsync();

        await TickAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(6));
        await TickAsync(coordinator);

        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "foreign-vpn");
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("Конфликт", StringComparison.Ordinal));
    }

    // --- Несколько туннелей ---

    [Fact]
    public async Task TwoTunnels_EachGetsItsOwnRoutesAndPermit()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.Equal(2, _world.Ras.Dials);
        Assert.Equal(2, _world.Wfp.TunnelPermits);
        Assert.True(_world.Routes.HasHalfRoutesOn(FakeInventory.TunnelLuid(0)));
        Assert.False(_world.Routes.HasHalfRoutesOn(FakeInventory.TunnelLuid(1)));
        Assert.Contains(Ipv4Cidr.Parse("13.107.0.0/16"), _world.Routes.On(FakeInventory.TunnelLuid(1)));
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.SecondServer, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);

        var status = coordinator.BuildStatus();
        Assert.Equal(2, status.Tunnels.Count);
        Assert.All(status.Tunnels, t => Assert.Equal(ConnectionState.Connected, t.State));
        Assert.Single(status.Tunnels, t => t.IsAnchor);
    }

    [Fact]
    public async Task SecondTunnelDown_BlocksItsNetworks_AndMainStaysConnected()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        });
        _world.Ras.ResultsByEntry[Coordinator.EntryNameFor(second)] = new Queue<RasDialResult>([new RasDialResult(false, null, 809, "Нет ответа")]);
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.Equal(1, _world.Wfp.TunnelPermits);
        Assert.Contains(_world.Wfp.Group(FilterGroup.Runtime), f => f.Action == FilterAction.Block && f.Name.Contains("Туннель недоступен", StringComparison.Ordinal));
        Assert.DoesNotContain(Ipv4Cidr.Parse("13.107.0.0/16"), _world.Routes.On(FakeInventory.TunnelLuid(1)));
        Assert.True(_world.Routes.HasHalfRoutesOn(FakeInventory.TunnelLuid(0)));

        var status = coordinator.BuildStatus();
        Assert.Equal(ConnectionState.Connecting, status.Tunnels.Single(t => t.ProfileId == second.Id).State);
        Assert.Equal(ConnectionState.Connected, status.Tunnels.Single(t => t.ProfileId == _profile.Id).State);
    }

    [Fact]
    public async Task BalancedGroup_SplitsTraffic_AndFailsOverWhenMemberDrops()
    {
        var second = SecondProfile();
        var group = new TunnelGroupSetting { Name = "Балансировка", Members = [_profile.Id, second.Id] };
        SaveSettings(Settings() with
        {
            Profiles = [_profile with { Role = ProfileRole.Primary }, second],
            Groups = [group],
            DefaultTarget = RouteTarget.Group(group.Id),
        });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        // Обоим туннелям достались свои доли адресного пространства, пары /1 нет ни у кого.
        Assert.True(coordinator.DeriveState() == ConnectionState.Connected, Dump(coordinator));
        Assert.Equal(2, _world.Wfp.TunnelPermits);
        Assert.False(_world.Routes.HasHalfRoutesOn(FakeInventory.TunnelLuid(0)));
        Assert.NotEmpty(_world.Routes.On(FakeInventory.TunnelLuid(0)));
        Assert.NotEmpty(_world.Routes.On(FakeInventory.TunnelLuid(1)));
        var firstShare = _world.Routes.On(FakeInventory.TunnelLuid(0)).Count();

        // Второй участник лёг: его доля переходит первому.
        _world.Ras.Drop(Coordinator.EntryNameFor(second));
        _world.Ras.ResultsByEntry[Coordinator.EntryNameFor(second)] = new Queue<RasDialResult>([new RasDialResult(false, null, 809, "Нет ответа")]);
        await TickAsync(coordinator);

        Assert.Empty(_world.Routes.On(FakeInventory.TunnelLuid(1)));
        Assert.True(_world.Routes.On(FakeInventory.TunnelLuid(0)).Count() > firstShare);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "group-degraded");
    }

    [Fact]
    public async Task GroupWithAllMembersDown_IsOutage()
    {
        var second = SecondProfile();
        var group = new TunnelGroupSetting { Name = "Балансировка", Members = [_profile.Id, second.Id] };
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Groups = [group],
            DefaultTarget = RouteTarget.Group(group.Id),
        });
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.Equal(0, _world.Wfp.TunnelPermits);
        Assert.Equal(ConnectionState.Connecting, coordinator.DeriveState());
        Assert.Equal(DnsProxyMode.Offline, _world.Proxy.Configuration.Mode);
    }

    [Fact]
    public async Task DomainRule_PinsRoute_AndDropsItWhenTtlExpires()
    {
        SaveSettings(Settings() with
        {
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var address = Ipv4.Parse("203.0.113.20");
        var pinned = coordinator.ObservePinnedAsync(
            new PinnedRouteNotice("www.example.org", "example.org", RouteTarget.Direct, [address], TimeSpan.FromMinutes(5)),
            CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pinned);

        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(address, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
        Assert.Contains(_world.Wfp.Group(FilterGroup.Dynamic), f => f.Action == FilterAction.Permit);
        Assert.Contains(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "example.org");

        _world.Time.Advance(TimeSpan.FromMinutes(6));
        await TickAsync(coordinator);

        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(address, 32));
        Assert.Empty(_world.Wfp.Group(FilterGroup.Dynamic));
    }

    [Fact]
    public async Task DomainRule_ChangedTarget_RevokesThePreviousPin()
    {
        SaveSettings(Settings() with
        {
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var address = Ipv4.Parse("203.0.113.20");
        var direct = new Ipv4Cidr(address, 32);
        var pinned = coordinator.ObservePinnedAsync(
            new PinnedRouteNotice("www.example.org", "example.org", RouteTarget.Direct, [address], TimeSpan.FromHours(1)),
            CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pinned);
        Assert.Contains(_world.Routes.Current, r => r.Destination == direct && r.InterfaceLuid == FakeWorld.WiFiLuid);

        // «Домен напрямую» меняется на «домен через VPN»: прежний прямой путь обязан исчезнуть сразу,
        // а не дожить до конца TTL закрепления.
        var response = await coordinator.HandleRequestAsync(
            new SaveSettingsRequest(coordinator.Settings with
            {
                DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Tunnel(_profile.Id) }],
            }),
            CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(response.Ok);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == direct && r.InterfaceLuid == FakeWorld.WiFiLuid);
        Assert.Empty(_world.Wfp.Group(FilterGroup.Dynamic));
    }

    [Fact]
    public async Task DomainRule_IntoTunnelThatIsDown_BlocksTheAddress()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            DomainRules = [new DomainRuleSetting { Suffix = "corp.example", Target = RouteTarget.Tunnel(second.Id) }],
        });
        _world.Ras.ResultsByEntry[Coordinator.EntryNameFor(second)] = new Queue<RasDialResult>([new RasDialResult(false, null, 809, "Нет ответа")]);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var address = Ipv4.Parse("198.51.100.77");
        var pinned = coordinator.ObservePinnedAsync(
            new PinnedRouteNotice("srv.corp.example", "corp.example", RouteTarget.Tunnel(second.Id), [address], TimeSpan.FromHours(1)),
            CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pinned);

        // Дополнительный туннель не поднят: адрес не выпускается ни напрямую, ни в чужой туннель.
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(address, 32));
        Assert.Contains(_world.Wfp.Group(FilterGroup.Dynamic), f => f.Action == FilterAction.Block && f.Name.Contains("198.51.100.77", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DomainRule_WhenRoutesFail_IsNotReportedAsApplied()
    {
        SaveSettings(Settings() with
        {
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        _world.Routes.FailNext = 1;
        var pinned = coordinator.ObservePinnedAsync(
            new PinnedRouteNotice("www.example.org", "example.org", RouteTarget.Direct, [Ipv4.Parse("203.0.113.20")], TimeSpan.FromHours(1)),
            CancellationToken.None);
        await coordinator.DrainAsync();

        // Маршрут не применился: посредник обязан ответить отказом, а не адресом без защиты.
        Assert.False(await pinned);
    }

    [Fact]
    public async Task DomainRule_ParallelAnswers_ShareOneApply()
    {
        SaveSettings(Settings() with
        {
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var addresses = Enumerable.Range(1, 5).Select(i => Ipv4.Parse("203.0.113." + i)).ToList();
        var waiting = addresses
            .Select(a => coordinator.ObservePinnedAsync(
                new PinnedRouteNotice("www.example.org", "example.org", RouteTarget.Direct, [a], TimeSpan.FromHours(1)),
                CancellationToken.None))
            .ToList();

        // Пять ответов подряд разбираются одной работой очереди, и ни один не отвечает раньше применения.
        Assert.Equal(1, coordinator.QueuedCount);
        await coordinator.DrainAsync();
        foreach (var pending in waiting)
        {
            Assert.True(await pending);
        }

        Assert.All(addresses, a => Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(a, 32)));
    }

    [Fact]
    public async Task SetProfileRole_MakesTunnelSecondary_AndKeepsItConnected()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second with { Role = ProfileRole.Off }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal(1, _world.Ras.Dials);

        var response = await coordinator.HandleRequestAsync(new SetProfileRoleRequest(second.Id, ProfileRole.Secondary), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(response.Ok);
        Assert.Equal(2, _world.Ras.Dials);
        var status = coordinator.BuildStatus();
        Assert.Equal(2, status.Tunnels.Count);
        Assert.Equal(ProfileRole.Secondary, status.Tunnels.Single(t => t.ProfileId == second.Id).Role);
    }

    [Fact]
    public async Task RemovedProfile_LosesItsPhonebookEntry()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var entry = Coordinator.EntryNameFor(second);
        Assert.Contains(entry, _world.Ras.EntryNames());

        await coordinator.HandleRequestAsync(new SetProfileRoleRequest(second.Id, ProfileRole.Off), CancellationToken.None);
        await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with { Profiles = [_profile] }), CancellationToken.None);
        await TickAsync(coordinator);

        Assert.DoesNotContain(entry, _world.Ras.EntryNames());
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    private string Dump(Coordinator coordinator) =>
        string.Join("; ", coordinator.Facts.Tunnels.Values.Select(t => $"{t.Name}: conn={t.Connection is not null} verified={t.Verified} adapter={t.Adapter?.Name} err={t.LastErrorText}"))
        + " | " + string.Join(" / ", _world.Journal.Since(0).Select(e => e.Text));

    [Fact]
    public async Task SettingsOfSchemaV1_AreMigrated_AndOldFileKept()
    {
        var id = Guid.NewGuid();
        var json = $$"""
        {
          "schemaVersion": 1,
          "profiles": [{ "id": "{{id}}", "name": "Старый", "server": "203.0.113.10:4443", "userName": "user" }],
          "activeProfileId": "{{id}}",
          "routingMode": "RussiaDirect",
          "rules": [{ "cidr": "1.2.3.0/24", "action": "Vpn" }]
        }
        """;
        await File.WriteAllTextAsync(_world.Paths.Settings, json, TestContext.Current.CancellationToken);
        _world.Secrets.Save(id, "secret");

        var coordinator = await StartAsync();

        Assert.Equal(ProfileRole.Primary, coordinator.Settings.Profiles[0].Role);
        Assert.Equal(RouteTarget.Tunnel(id), coordinator.Settings.DefaultTarget);
        Assert.Equal(RouteTarget.Tunnel(id), coordinator.Settings.Rules[0].Target);
        Assert.True(File.Exists(new ServiceStores(_world.Paths).PreviousSchemaBackup));
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("новую схему", StringComparison.Ordinal));

        await ConnectAsync(coordinator);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    private ConnectionProfile SecondProfile() => new()
    {
        Name = "Резерв",
        Server = Ipv4.Format(FakeWorld.SecondServer),
        UserName = "user2",
        Role = ProfileRole.Secondary,
    };

    private void SaveSettings(AppSettings settings)
    {
        new ServiceStores(_world.Paths).SaveSettings(settings);
        foreach (var profile in settings.Profiles)
        {
            _world.Secrets.Save(profile.Id, "secret");
        }
    }

    private async Task<Coordinator> StartAsync()
    {
        var coordinator = new Coordinator(_world.Dependencies());
        await coordinator.StartupAsync(CancellationToken.None);
        return coordinator;
    }

    private static async Task<IpcResponse> ConnectAsync(Coordinator coordinator)
    {
        var response = await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        return response;
    }

    private static async Task TickAsync(Coordinator coordinator)
    {
        await coordinator.TickAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
    }

    /// <summary>
    /// Дозвон и проверка готовности идут в фоновых задачах и возвращают результат в очередь актора.
    /// Обработка результата может начать дозвон следующего туннеля, поэтому ждём, пока и очередь,
    /// и фоновые задачи не затихнут дважды подряд.
    /// </summary>
    private static async Task CompleteDialAsync(Coordinator coordinator)
    {
        var quiet = 0;
        for (var i = 0; i < 600 && quiet < 2; i++)
        {
            if (coordinator.QueuedCount > 0)
            {
                await coordinator.DrainAsync();
                quiet = 0;
                continue;
            }

            if (coordinator.Facts.Tunnels.Values.Any(t => t.Dialing || t.Verifying || t.CertificateProbeRunning))
            {
                quiet = 0;
                await Task.Delay(5);
                continue;
            }

            quiet++;
            await Task.Delay(5);
        }

        await coordinator.DrainAsync();
    }

    private void SeedGeo()
    {
        var store = new GeoStore(_world.Paths.Geo);
        var text = string.Join('\n', Enumerable.Range(0, 1200).Select(i => $"5.{i / 250}.{i % 250}.0/24").Append("77.88.0.0/18"));
        var bytes = GeoUpdateEvaluator.ToStoredBytes(text);
        var id = GeoStore.ComputeId(bytes);
        store.SaveRevision(bytes, new GeoRevision { Id = id, SourceId = LoyalsoldierSource.SourceId, V4Count = 1201 });
        store.Activate(id);
    }
}
