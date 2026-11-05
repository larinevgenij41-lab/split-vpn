using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Круг 3 код-ревью, зона защиты и политики: частные сети носителя «остального интернета» (S1), служебное
/// закрепление узлов проверки отзыва (S3), положенный носитель при «Разрешить всё» (S5), интерфейс RAS только
/// не аппаратный (M1), несколько контрольных целей, временные сбои телефонной книги и описание закреплённого адаптера.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly uint ForeignProbeAddress = Ipv4.Parse("1.1.1.1");
    private static readonly uint RevocationAddress = Ipv4.Parse("23.215.0.136");

    private async Task<Coordinator> StartWithAsync(Func<ServiceDependencies, ServiceDependencies> customize)
    {
        var coordinator = new Coordinator(customize(_world.Dependencies()));
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        return coordinator;
    }

    /// <summary>S1: положенный носитель «остального интернета» не выпускает назначенную ему частную сеть в Wi-Fi.</summary>
    [Fact]
    public async Task PausedAnchor_PrivateNetworkAssignedToIt_IsBlocked()
    {
        SaveSettings(Settings() with { Rules = [new UserRuleSetting { Cidr = "10.20.0.0/16", Target = RouteTarget.Tunnel(_profile.Id) }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.DoesNotContain(_world.Wfp.Group(FilterGroup.Runtime), f => f.Name.StartsWith("Туннель недоступен", StringComparison.Ordinal));

        await PauseAsync(coordinator, _profile.Id, paused: true);

        var block = Assert.Single(_world.Wfp.Group(FilterGroup.Runtime), f => f.Name.StartsWith("Туннель недоступен «Нидерланды»", StringComparison.Ordinal));
        Assert.Equal(FilterAction.Block, block.Action);
        Assert.Equal(FilterPlanBuilder.WeightUserBlock, block.Weight);
        var ranges = Assert.IsType<RemoteRangesV4>(Assert.Single(block.Conditions));
        Assert.True(ranges.Contains(Ipv4.Parse("10.20.1.1")));
        Assert.False(ranges.Contains(Ipv4.Parse("192.168.1.50")));
    }

    /// <summary>S5: «Разрешить всё» и положенный носитель - не обрыв: трафик и DNS заблокированы, и интерфейс говорит это.</summary>
    [Fact]
    public async Task AllowAll_PausedAnchor_KeepsTrafficBlocked_AndSaysSo()
    {
        SaveSettings(Settings() with { OutageMode = OutageMode.AllowAll });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        await PauseAsync(coordinator, _profile.Id, paused: true);

        Assert.DoesNotContain(_world.Wfp.Group(FilterGroup.Runtime), f => f.Name == "Обрыв: разрешить всё");
        Assert.Equal(DnsProxyMode.Offline, _world.Proxy.Configuration.Mode);
        var status = coordinator.BuildStatus();
        Assert.Equal(ConnectionState.TrafficBlocked, status.State);
        Assert.Contains("Остальные адреса → заблокированы", StatusText.Format(status), StringComparison.Ordinal);
        var check = await coordinator.HandleRequestAsync(new CheckAddressRequest("1.1.1.1"), CancellationToken.None);
        Assert.True(Assert.Single(check.ResultAs<AddressCheckDto>()!.Items).Blocked);
    }

    /// <summary>S5, обратная сторона: настоящий обрыв при «Разрешить всё» по-прежнему выпускает трафик напрямую.</summary>
    [Fact]
    public async Task AllowAll_RealOutage_StillOpensTraffic()
    {
        SaveSettings(Settings() with { OutageMode = OutageMode.AllowAll });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.False(coordinator.Facts.Tunnels[_profile.Id].IsUp);
        Assert.Contains(_world.Wfp.Group(FilterGroup.Runtime), f => f.Name == "Обрыв: разрешить всё");
        Assert.Equal(DnsProxyMode.DirectAllowed, _world.Proxy.Configuration.Mode);
        Assert.Contains("разрешено при обрыве", StatusText.Format(coordinator.BuildStatus()), StringComparison.Ordinal);
        var check = await coordinator.HandleRequestAsync(new CheckAddressRequest("1.1.1.1"), CancellationToken.None);
        Assert.False(Assert.Single(check.ResultAs<AddressCheckDto>()!.Items).Blocked);
    }

    /// <summary>
    /// S3: пока туннелю нужна проверка отзыва, к узлу открыт только TCP на порт ссылки через основной адаптер; адрес
    /// не закрепляется напрямую целиком. Туннель поднялся - разрешение и служебный маршрут DNS сняты.
    /// </summary>
    [Theory]
    [InlineData("http://" + RevocationHost + "/112.crl", 80)]
    [InlineData("http://" + RevocationHost + ":8080/112.crl", 8080)]
    public async Task RevocationPin_OpensOnlyTcpPort_WhileTunnelNeedsTheCheck(string url, int port)
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6)) with { RevocationUrls = [url] };
        _world.Resolver.Answers[RevocationHost] = [RevocationAddress];
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.False(tunnel.IsUp);

        var permit = Assert.Single(_world.Wfp.Group(FilterGroup.Dynamic), f => f.Conditions.Contains(new RemoteRangeV4(RevocationAddress, RevocationAddress)));
        Assert.Equal(FilterAction.Permit, permit.Action);
        Assert.Contains(new ProtocolCondition(FilterPlanBuilder.ProtocolTcp), permit.Conditions);
        Assert.Contains(new RemotePortCondition((ushort)port), permit.Conditions);
        Assert.Contains(new LocalInterfaceCondition(FakeWorld.WiFiLuid, NotEqual: false), permit.Conditions);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(RevocationAddress, 32));
        Assert.NotEqual(DecisionSource.DomainRule, coordinator.Facts.Policy!.Classify(RevocationAddress).Source);

        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.True(tunnel.IsUp);
        Assert.DoesNotContain(_world.Wfp.Group(FilterGroup.Dynamic), f => f.Conditions.Contains(new RemoteRangeV4(RevocationAddress, RevocationAddress)));
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost);
    }

    /// <summary>S3: туннель снова лёг - узел проверки отзыва снова открывается, а кеш DNS Windows сбрасывается.</summary>
    [Fact]
    public async Task RevocationRoute_ReturnsWhenTunnelDrops_AndFlushesDnsCache()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.True(coordinator.Facts.Tunnels[_profile.Id].IsUp);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost);
        var flushes = _world.Dns.Flushes;

        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.Contains(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost && d.Target == RouteTarget.Direct);
        Assert.True(_world.Dns.Flushes > flushes);
    }

    /// <summary>S3: положенному туннелю проверка сертификата не нужна - он не дозванивается.</summary>
    [Fact]
    public async Task RevocationRoute_IsNotOpenedForPausedTunnel()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        await PauseAsync(coordinator, _profile.Id, paused: true);

        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost);
    }

    /// <summary>M1: адрес соединения RAS нашёлся только у Wi-Fi - это не интерфейс туннеля.</summary>
    [Fact]
    public async Task RasAddressOnlyOnWiFi_IsNotTakenAsTunnelInterface()
    {
        _world.Inventory.HideTunnel(0);
        _world.Inventory.WiFiAddress = FakeWorld.TunnelAddress;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.NotNull(tunnel.Connection);
        Assert.Null(tunnel.Adapter);
        Assert.False(_world.Wfp.HasTunnelPermit);

        _world.Inventory.HideTunnel(0, hidden: false);
        await TickAsync(coordinator);

        Assert.Equal(FakeWorld.TunnelLuid, tunnel.Adapter?.Luid);
    }

    /// <summary>Ни одна цель не ответила: туннель не рабочий.</summary>
    [Fact]
    public async Task ProbeTargets_AllTimedOut_IsNotWorkingTunnel()
    {
        var probes = await StartWithTwoTargetsAsync(ProbeAnswer.Timeout, ProbeAnswer.Timeout);
        var coordinator = probes.Coordinator;
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.False(tunnel.Verified);
        Assert.Equal(1, tunnel.VerifyProbeFailures);
        Assert.Contains((ForeignProbeAddress, (ushort)80), probes.Probes.Calls);
        Assert.NotEqual(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>
    /// Сброс от одной цели и молчание другой: ответ прошёл туннель. Сервер мог потерять выход в интернет, а мог просто
    /// не выпускать порт 80; разрыв не помог бы ни в том, ни в другом случае, поэтому туннель рабочий.
    /// </summary>
    [Theory]
    [InlineData(ProbeAnswer.Refused, ProbeAnswer.Connected)]
    [InlineData(ProbeAnswer.Timeout, ProbeAnswer.Connected)]
    [InlineData(ProbeAnswer.Refused, ProbeAnswer.Refused)]
    [InlineData(ProbeAnswer.Refused, ProbeAnswer.Timeout)]
    public async Task ProbeTargets_AnyAnswer_IsWorkingTunnel(ProbeAnswer first, ProbeAnswer second)
    {
        var probes = await StartWithTwoTargetsAsync(first, second);
        var coordinator = probes.Coordinator;
        await ConnectAsync(coordinator);

        Assert.True(coordinator.Facts.Tunnels[_profile.Id].Verified);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public void ProbeTargets_AreParsedFromList()
    {
        var targets = Coordinator.ParseTargets("1.1.1.1:443, 1.1.1.1:80;8.8.8.8:53  мусор 1.2.3.4:0 1.1.1.1:443");

        string[] expected = ["1.1.1.1:443", "1.1.1.1:80", "8.8.8.8:53"];
        Assert.Equal(expected, targets.Select(t => t.ToString()).ToArray());
    }

    private async Task<(Coordinator Coordinator, ScriptedProbes Probes)> StartWithTwoTargetsAsync(ProbeAnswer first, ProbeAnswer second)
    {
        SaveSettings(Settings() with { CheckTargets = new CheckTargets { Foreign = "1.1.1.1:443, 1.1.1.1:80" } });
        var probes = new ScriptedProbes(_world.Probes);
        probes.Answers[(ForeignProbeAddress, 443)] = first;
        probes.Answers[(ForeignProbeAddress, 80)] = second;
        return (await StartWithAsync(d => d with { Probes = probes }), probes);
    }

    /// <summary>Телефонная книга временно не открывается: это не ошибка сертификата, повтор идёт сам.</summary>
    [Theory]
    [InlineData(0x26D)]
    [InlineData(32)]
    public async Task PhonebookBusy_IsRetried_NotTreatedAsCertificateError(int code)
    {
        var ras = new FlakyPhonebookRas(_world.Ras);
        ras.SaveFailures.Enqueue(new NativeCallException("RasDeleteEntry", (uint)code));
        await AssertPrepareFailureIsRetriedAsync(ras);
    }

    [Fact]
    public async Task PhonebookIoError_IsRetried()
    {
        var ras = new FlakyPhonebookRas(_world.Ras);
        ras.SaveFailures.Enqueue(new IOException("Процесс не может получить доступ к файлу"));
        await AssertPrepareFailureIsRetriedAsync(ras);
    }

    /// <summary>Неверные параметры записи по-прежнему останавливают повторы: от них повтор не поможет.</summary>
    [Fact]
    public async Task InvalidEntryParameters_StillStopRetries()
    {
        var ras = new FlakyPhonebookRas(_world.Ras);
        ras.SaveFailures.Enqueue(new InvalidOperationException("Недопустимые параметры VPN-записи."));
        var coordinator = await StartWithAsync(d => d with { Ras = ras });
        await ConnectAsync(coordinator);

        Assert.NotEqual(ErrorCategory.None, coordinator.Facts.Tunnels[_profile.Id].BlockingError);
    }

    private async Task AssertPrepareFailureIsRetriedAsync(FlakyPhonebookRas ras)
    {
        var coordinator = await StartWithAsync(d => d with { Ras = ras });
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.Equal(ErrorCategory.Other, tunnel.LastErrorCategory);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow());

        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.True(_world.Ras.Connected);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>Описание адаптера запоминается у всех профилей, закреплённых за ним: опорным может стать любой.</summary>
    [Fact]
    public async Task PinnedAdapter_DescriptionLearned_ForEveryProfilePinnedToIt()
    {
        var second = SecondProfile() with { PrimaryAdapter = AdapterSelection.Pinned, PinnedInterfaceGuid = FakeWorld.WiFiGuid };
        SaveSettings(Settings() with { Profiles = [Pinned(FakeWorld.WiFiGuid, description: null), second] });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.All(coordinator.Settings.Profiles, p => Assert.Equal(_world.Inventory.WiFiDescription, p.PinnedAdapterDescription));
    }

    /// <summary>После сброса сети закрепление переносится у всех профилей, закреплённых за прежним GUID.</summary>
    [Fact]
    public async Task PinnedAdapter_Rebound_MovesEveryProfilePinnedToOldGuid()
    {
        var old = Guid.NewGuid();
        var description = _world.Inventory.WiFiDescription;
        var second = SecondProfile() with { PrimaryAdapter = AdapterSelection.Pinned, PinnedInterfaceGuid = old, PinnedAdapterDescription = description };
        SaveSettings(Settings() with { Profiles = [Pinned(old, description), second] });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.All(coordinator.Settings.Profiles, p => Assert.Equal(FakeWorld.WiFiGuid, p.PinnedInterfaceGuid));
    }

    /// <summary>Постоянный сбой записи не повторяется на каждой сверке; изменился адаптер - запись повторяется.</summary>
    [Fact]
    public async Task PinnedAdapter_FailedSave_IsNotRetriedUntilSomethingChanges()
    {
        var log = new WarningLog();
        _world.Logger = log;
        var pinned = Guid.NewGuid();
        SaveSettings(Settings() with { Profiles = [Pinned(pinned, description: null)] });
        var coordinator = await StartAsync();
        const string Failure = "Не удалось запомнить закреплённый адаптер";

        using (new FileStream(_world.Paths.Settings, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            // Адаптер с закреплённым GUID появился: описание надо запомнить, но файл настроек занят.
            _world.Inventory.WiFiGuid = pinned;
            for (var i = 0; i < 3; i++)
            {
                await coordinator.ReconcileAsync(CancellationToken.None);
            }

            Assert.Equal(1, log.Count(Failure));
            Assert.Null(coordinator.Settings.Profiles[0].PinnedAdapterDescription);
        }

        await coordinator.ReconcileAsync(CancellationToken.None);
        Assert.Equal(1, log.Count(Failure));

        _world.Inventory.WiFiDescription = "Intel(R) Wi-Fi 7 BE200";
        await coordinator.ReconcileAsync(CancellationToken.None);

        Assert.Equal("Intel(R) Wi-Fi 7 BE200", coordinator.Settings.Profiles[0].PinnedAdapterDescription);
        Assert.Equal(1, log.Count(Failure));
    }
}
