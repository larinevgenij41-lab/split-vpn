using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>Исправления по код-ревью 0.9.6: адреса отзыва, пароли, разрывы, наблюдение за соединением.</summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task UntrustedCertificate_RevocationHostsAreNotOpened()
    {
        // Сертификат мог предъявить кто угодно на адресе сервера (MITM в Wi-Fi): его адреса отзыва не открываются.
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6)) with
        {
            ChainProblem = "корневой сертификат издателя не установлен в хранилище компьютера",
            RevocationUrls = ["http://com/x"],
            RevocationHosts = ["com", RevocationHost],
        };
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Empty(tunnel.RevocationHosts);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix is "com" or RevocationHost);
        Assert.Empty(coordinator.State.Servers.Single().RevocationHosts ?? []);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ServerByName_RevocationHostsNeedMatchingCertificateName(bool nameMatches)
    {
        var named = _profile with { Server = "vpn.example.org:4443" };
        SaveSettings(Settings() with { Profiles = [named] });
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6)) with { NameMatches = nameMatches };

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var hosts = coordinator.Facts.Tunnels[named.Id].RevocationHosts;
        Assert.Equal(nameMatches, hosts.Contains(RevocationHost));
    }

    [Fact]
    public async Task RevocationHosts_AreReplaced_AndSingleLabelIgnored()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Contains(RevocationHost, tunnel.RevocationHosts);

        var renewed = ServerCertificate(_world.Time.GetUtcNow().AddDays(6)) with
        {
            Thumbprint = "CCDD",
            RevocationHosts = ["com", "crl.other.example"],
        };
        await coordinator.OnCertificateProbedAsync(_profile.Id, tunnel.CertificateProbeGeneration, renewed, "тест", CancellationToken.None);

        Assert.Equal(["crl.other.example"], tunnel.RevocationHosts);
        Assert.Equal(["crl.other.example"], coordinator.State.Servers.Single().RevocationHosts!);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "com" || d.Suffix == RevocationHost);
    }

    [Fact]
    public async Task CachedSingleLabelRevocationHost_IsDroppedOnLoad()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile
        {
            Intent = Intent.Protected,
            Servers = [new ServerCacheEntry(_profile.Id, [Ipv4.Format(FakeWorld.Server)], _world.Time.GetUtcNow(), null, ["com", RevocationHost], RevocationHostsTrusted: true)],
        });

        var coordinator = await StartAsync();

        Assert.Equal([RevocationHost], coordinator.Facts.Tunnels[_profile.Id].RevocationHosts);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "com");
    }

    [Fact]
    public async Task MemoryPasswords_AreKeptPerProfile()
    {
        var first = _profile with { SavePassword = false };
        var second = SecondProfile() with { SavePassword = false };
        SaveSettings(Settings() with { Profiles = [first, second] });
        var coordinator = await StartAsync();

        await coordinator.HandleRequestAsync(new SetPasswordRequest(first.Id, "first-secret"), CancellationToken.None);
        await coordinator.HandleRequestAsync(new SetPasswordRequest(second.Id, "second-secret"), CancellationToken.None);

        Assert.Equal("first-secret", new string(coordinator.Facts.MemoryPasswords[first.Id]));
        Assert.Equal("second-secret", new string(coordinator.Facts.MemoryPasswords[second.Id]));

        var removed = coordinator.Facts.MemoryPasswords[second.Id];
        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with { Profiles = [first] }), CancellationToken.None)).Ok);

        Assert.False(coordinator.Facts.MemoryPasswords.ContainsKey(second.Id));
        Assert.All(removed, c => Assert.Equal('\0', c));
        Assert.Equal("first-secret", new string(coordinator.Facts.MemoryPasswords[first.Id]));
    }

    [Fact]
    public async Task CheckAddress_ThroughQueue_Answers()
    {
        var coordinator = new Coordinator(_world.Dependencies());
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);
        await WaitQueueAsync(coordinator);

        var response = await coordinator.SubmitAsync(new CheckAddressRequest("77.88.8.8"), TestContext.Current.CancellationToken)
            .WaitAsync(QueueWait, TestContext.Current.CancellationToken);

        Assert.True(response.Ok);
        Assert.Equal("77.88.8.8", Assert.Single(response.ResultAs<AddressCheckDto>()!.Items).Address);
        await StopAsync(cancellation, run);
    }

    [Fact]
    public async Task PauseTunnel_HangUpFailure_KeepsTunnelUnpaused_AndSchedulesReconcile()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 5);

        var request = coordinator.SubmitAsync(new SetTunnelPausedRequest(second.Id, true), CancellationToken.None);
        await coordinator.DrainAsync();
        var response = await request;

        Assert.False(response.Ok);
        var tunnel = coordinator.Facts.Tunnels[second.Id];
        Assert.False(tunnel.Paused);
        Assert.NotNull(tunnel.Connection);
        Assert.NotNull(coordinator.Facts.PartialError);
        Assert.True(coordinator.Facts.ForceProtection);

        _world.Ras.HangUpFailure = null;
        await TickAsync(coordinator);
        Assert.Null(coordinator.Facts.PartialError);
    }

    [Fact]
    public async Task SaveSettings_HangUpFailure_SchedulesReconcile()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 5);
        var changed = coordinator.Settings with { Profiles = [_profile with { Server = "203.0.113.11:4443" }] };

        var request = coordinator.SubmitAsync(new SaveSettingsRequest(changed), CancellationToken.None);
        await coordinator.DrainAsync();

        Assert.False((await request).Ok);
        Assert.NotNull(coordinator.Facts.PartialError);
        Assert.True(coordinator.Facts.ForceProtection);
        Assert.True(coordinator.Facts.PartialErrorRetryAt <= _world.Time.GetUtcNow());
    }

    [Fact]
    public async Task Teardown_LeavesProfileTestDialAlone_AndConnectIsBusy()
    {
        var coordinator = await StartAsync();
        var entry = Coordinator.EntryNameFor(_profile);
        coordinator.Facts.ProfileTestRunning = true;
        await _world.Ras.DialAsync(entry, "user", "secret".AsMemory(), null, CancellationToken.None);

        await coordinator.ReconcileAsync(CancellationToken.None);
        var connect = await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);

        Assert.Contains(entry, _world.Ras.ConnectedEntries);
        Assert.False(connect.Ok);
        Assert.Equal(IpcErrorCodes.Busy, connect.ErrorCode);

        coordinator.Facts.ProfileTestRunning = false;
        await coordinator.ReconcileAsync(CancellationToken.None);
        Assert.DoesNotContain(entry, _world.Ras.ConnectedEntries);
    }

    [Fact]
    public async Task UserDisconnectOfAnotherEntry_IsTreatedAsDrop()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        // 631 в журнале относится к чужому соединению: наш обрыв — это обрыв, а не решение пользователя.
        _world.TerminationReason = 631;
        _world.TerminationEntry = "IKEv2 VPN 5.129.236.106";
        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.Equal(Intent.Connected, coordinator.State.Intent);
        Assert.False(coordinator.Facts.Tunnels[_profile.Id].ExternallyDisconnected);
    }

    [Fact]
    public async Task OwnRecentHangUp631_IsTreatedAsDrop()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        _world.Time.Advance(TimeSpan.FromMinutes(30));
        tunnel.LastOwnHangUpUtc = _world.Time.GetUtcNow();

        // Событие 631 записано через секунду после своего RasHangUp — это след своего разрыва.
        _world.TerminationReason = 631;
        _world.TerminationTimeUtc = _world.Time.GetUtcNow().AddSeconds(1);
        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.Equal(Intent.Connected, coordinator.State.Intent);
        Assert.False(tunnel.ExternallyDisconnected);
    }

    [Fact]
    public async Task OwnHangUpBeforeSession_DoesNotMaskLaterUserDisconnect()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        // Быстрое переподключение: свой разрыв прошлого сеанса за пару секунд до начала нынешнего.
        tunnel.LastOwnHangUpUtc = tunnel.SessionStartedUtc!.Value.AddSeconds(-2);

        _world.Time.Advance(TimeSpan.FromHours(1));
        _world.TerminationReason = 631;
        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.True(tunnel.ExternallyDisconnected);
        Assert.Equal(ConnectionState.DisconnectedExternally, coordinator.DeriveState());
    }

    [Fact]
    public async Task TerminationEventBeforeSession_IsIgnored()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        // 631 прошлого соединения записи (до начала сеанса) не говорит о решении пользователя сейчас.
        _world.TerminationReason = 631;
        _world.TerminationTimeUtc = tunnel.SessionStartedUtc!.Value.AddSeconds(-1);
        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.False(tunnel.ExternallyDisconnected);
        Assert.Equal(Intent.Connected, coordinator.State.Intent);
    }

    [Fact]
    public async Task ConnectingStatus_IsNotADropAtOnce()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var entry = Coordinator.EntryNameFor(_profile);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var handle = tunnel.Connection;
        _world.Ras.StatusOverride[entry] = RasConnectionStatus.Connecting;

        await coordinator.TickAsync(CancellationToken.None);
        await coordinator.TickAsync(CancellationToken.None);
        Assert.Equal(handle, tunnel.Connection);
        Assert.Equal(0, _world.Ras.HangUps);

        await coordinator.TickAsync(CancellationToken.None);
        // Зависшее «подключается» отпускается RasHangUp, а не просто забывается.
        Assert.Equal(1, _world.Ras.HangUps);
        Assert.NotEqual(handle, tunnel.Connection);
    }

    [Fact]
    public async Task DisconnectedStatus_HangsUpHandle()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Ras.StatusOverride[Coordinator.EntryNameFor(_profile)] = RasConnectionStatus.Disconnected;

        await coordinator.TickAsync(CancellationToken.None);

        Assert.Equal(1, _world.Ras.HangUps);
    }

    [Fact]
    public async Task GeoActivation_UnrelatedDnsFailure_DoesNotFailImport()
    {
        _world.Proxy.FailStart = true;
        var coordinator = await StartGeoAsync(new GeoHttpSource());
        await ConnectAsync(coordinator);
        Assert.NotNull(coordinator.Facts.PartialError);

        var response = await coordinator.HandleRequestAsync(new GeoImportRequest(GeoContent(1)), CancellationToken.None);

        Assert.True(response.Ok, response.ErrorMessage);
        Assert.Equal(DecisionSource.Geo, coordinator.Facts.Policy!.Classify(Ipv4.Parse("11.0.1.1")).Source);
    }

    [Fact]
    public async Task NetworkPath_IsAllowed_WithPausedSecondaryTunnel()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        await PauseAsync(coordinator, second.Id, paused: true);

        Assert.True(coordinator.Facts.Tunnels[_profile.Id].Verified);
        Assert.True(coordinator.NetworkPathAllowed);
    }

    [Fact]
    public async Task FailedPinApply_IsRetriedAfterPause()
    {
        var coordinator = await WithSharedDomainRulesAsync();
        var notice = new PinnedRouteNotice("first.example", "first.example", RouteTarget.Tunnel(_profile.Id), [SharedDomainAddress], TimeSpan.FromHours(1));
        _world.Routes.FailNext = 1;

        var failed = coordinator.ObservePinnedAsync(notice, CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.False(await failed);

        // Тот же ответ сразу — отказ без пересборки политики на каждый запрос.
        Assert.False(await coordinator.ObservePinnedAsync(notice, CancellationToken.None));

        _world.Time.Advance(TimeSpan.FromSeconds(6));
        var retried = coordinator.ObservePinnedAsync(notice, CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await retried);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(SharedDomainAddress).Tunnel);
    }

    [Fact]
    public async Task MaskedReport_HidesServerNamesFromCertificateAndGateway()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6)) with
        {
            Subject = "vpn.secret-corp.example",
            Names = ["vpn.secret-corp.example", "*.inner.secret-corp.example"],
        };
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        coordinator.Journal("Сведения", "узел шлюза node7.inner.secret-corp.example");

        var response = await coordinator.HandleRequestAsync(new ExportReportRequest(MaskPersonalData: true), CancellationToken.None);
        var report = response.ResultAs<string>()!;

        Assert.DoesNotContain("secret-corp", report, StringComparison.OrdinalIgnoreCase);
    }
}
