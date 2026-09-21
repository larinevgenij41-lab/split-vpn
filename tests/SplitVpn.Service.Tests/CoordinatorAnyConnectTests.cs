using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    private const string Gateway = "avpn.example.org";
    private const int AnyConnectSlot = 2;
    private static readonly uint GatewayAddress = Ipv4.Parse("198.51.100.10");
    private static readonly uint GatewayDns = Ipv4.Parse("10.0.16.21");

    private readonly ConnectionProfile _anyConnect = new()
    {
        Name = "Офис",
        Server = Gateway,
        Protocol = VpnProtocol.AnyConnect,
        AuthMethod = AuthMethod.GatewayForm,
        Role = ProfileRole.Secondary,
    };

    private static SessionInfo GatewaySession() => new()
    {
        Address = "10.0.7.190",
        Netmask = "255.255.255.255",
        Mtu = 1230,
        Dns = ["10.0.16.21"],
        SplitDns = ["office.example.org", "local"],
        SplitIncludes = ["10.0.0.0/255.0.0.0", "172.16.5.0/255.255.255.0"],
        SessionTimeoutSeconds = 36000,
        DtlsActive = true,
    };

    private async Task<Coordinator> StartWithAnyConnectAsync(AppSettings? settings = null)
    {
        _world.Resolver.Answers[Gateway] = [GatewayAddress];
        SaveSettings(settings ?? Settings() with { Profiles = [_profile, _anyConnect] });
        _world.Secrets.Delete(_anyConnect.Id);
        return await StartAsync();
    }

    /// <summary>Вход через SSO и установленный сеанс на адаптере слота 2.</summary>
    private async Task<FakeAnyConnectSession> EstablishAsync(Coordinator coordinator)
    {
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var request = Guid.NewGuid();
        session.Emit(new SsoOpenEvent(request, "https://" + Gateway + "/+CSCOE+/saml/sp/login", Gateway));
        await CompleteDialAsync(coordinator);
        session.Emit(new SsoResultEvent(request, true, null));
        _world.Inventory.AddTunnel(AnyConnectSlot);
        session.Emit(new EstablishedEvent(FakeInventory.TunnelLuid(AnyConnectSlot), "SplitVpn AC", GatewaySession()));
        await CompleteDialAsync(coordinator);
        return session;
    }

    private TunnelStatusDto AnyConnectStatus(Coordinator coordinator) =>
        coordinator.BuildStatus().Tunnels.Single(t => t.ProfileId == _anyConnect.Id);

    [Fact]
    public async Task AnyConnect_AfterServiceRestart_WaitsForSignInWithoutStartingHelper()
    {
        var first = await StartWithAnyConnectAsync();
        await ConnectAsync(first);
        Assert.Single(_world.AnyConnect.Sessions);

        var restarted = await StartAsync();
        await TickAsync(restarted);

        Assert.Single(_world.AnyConnect.Sessions);
        var status = AnyConnectStatus(restarted);
        Assert.Equal(ConnectionState.PasswordRequired, status.State);
        Assert.Equal(SignInKind.Required, status.SignIn?.Kind);
        Assert.Equal(Gateway, status.SignIn?.GatewayHost);
        Assert.Equal(ConnectionState.Connected, restarted.DeriveState());
        Assert.Contains(restarted.BuildStatus().Warnings, w => w.Code == "sign-in-required");

        await restarted.HandleRequestAsync(new BeginSignInRequest(_anyConnect.Id), CancellationToken.None);
        Assert.Equal(2, _world.AnyConnect.Sessions.Count);
    }

    [Fact]
    public async Task AnyConnect_SsoSession_RoutesGatewayNetworksAndDnsSuffixes()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var start = Assert.IsType<StartCommand>(session.Commands[0]);
        Assert.Equal("https://" + Gateway + "/", start.GatewayUrl);
        Assert.Null(start.Password);

        var request = Guid.NewGuid();
        session.Emit(new SsoOpenEvent(request, "https://" + Gateway + "/saml", Gateway));
        await CompleteDialAsync(coordinator);
        Assert.Equal(SignInKind.Browser, AnyConnectStatus(coordinator).SignIn?.Kind);
        var navigation = await coordinator.HandleRequestAsync(new SsoNavigationRequest(_anyConnect.Id, request, "https://" + Gateway + "/done", [new SsoCookie("acSamlv2Token", "t")]), CancellationToken.None);
        Assert.True(navigation.Ok);
        Assert.Contains(session.Commands, c => c is WebviewLoadCommand { Cookies.Count: 1 });

        session.Emit(new ResolveHostEvent(Gateway));
        await CompleteDialAsync(coordinator);
        Assert.Contains(session.Commands, c => c is ResolveReplyCommand { Address: "198.51.100.10" });
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(GatewayAddress, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);

        session.Emit(new SsoResultEvent(request, true, null));
        _world.Inventory.AddTunnel(AnyConnectSlot);
        session.Emit(new EstablishedEvent(FakeInventory.TunnelLuid(AnyConnectSlot), "SplitVpn AC", GatewaySession()));
        await CompleteDialAsync(coordinator);

        var luid = FakeInventory.TunnelLuid(AnyConnectSlot);
        var routes = _world.Routes.On(luid).ToList();
        Assert.Contains(Ipv4Cidr.Parse("10.0.0.0/8"), routes);
        Assert.Contains(Ipv4Cidr.Parse("172.16.5.0/24"), routes);
        Assert.Equal(DecisionSource.TunnelInfrastructure, coordinator.Facts.Policy!.Classify(GatewayDns).Source);
        Assert.DoesNotContain(_world.Routes.On(luid), r => r.Contains(GatewayAddress));

        var domains = _world.Proxy.Configuration.DomainRoutes;
        var office = Assert.Single(domains, d => d.Suffix == "office.example.org");
        Assert.False(office.PinAddresses);
        Assert.Equal([GatewayDns], office.Route!.Servers.Select(s => Ipv4.ToUInt(s.Address)));
        Assert.DoesNotContain(domains, d => d.Suffix == "local");
        Assert.Equal(FakeWorld.TunnelLuid, coordinator.DnsAnchor?.Adapter?.Luid);

        var status = AnyConnectStatus(coordinator);
        Assert.Equal(ConnectionState.Connected, status.State);
        Assert.Null(status.SignIn);
        Assert.Equal(2, status.ServerNetworks?.Networks.Count);
        Assert.Equal(1230, status.ServerNetworks?.Mtu);
        Assert.Equal(Decision.Vpn, coordinator.Facts.Policy!.Classify(Ipv4.Parse("10.1.2.3")).Decision);
        Assert.Equal(_anyConnect.Id, coordinator.Facts.Policy!.Classify(Ipv4.Parse("10.1.2.3")).Tunnel);
    }

    [Fact]
    public async Task AnyConnect_DomainRuleDoesNotPinGatewayAddressIntoTunnel()
    {
        var settings = Settings() with
        {
            Profiles = [_profile, _anyConnect],
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Tunnel(_profile.Id) }],
        };
        var coordinator = await StartWithAnyConnectAsync(settings);
        await ConnectAsync(coordinator);

        await coordinator.ObservePinnedAsync(new PinnedRouteNotice(Gateway, RouteTarget.Tunnel(_profile.Id), [GatewayAddress, Ipv4.Parse("203.0.113.5")], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        var sstp = _world.Routes.On(FakeWorld.TunnelLuid).ToList();
        Assert.Contains(Ipv4Cidr.Parse("203.0.113.5/32"), sstp);
        Assert.DoesNotContain(new Ipv4Cidr(GatewayAddress, 32), sstp);
    }

    [Fact]
    public async Task AnyConnect_DropRemovesNetworksAndWaitsForNewSignIn()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);

        _world.Inventory.RemoveTunnel(AnyConnectSlot);
        session.Emit(new TerminatedEvent(TerminationKind.NetworkError, "DTLS и TLS не отвечают"));
        await CompleteDialAsync(coordinator);
        await TickAsync(coordinator);

        Assert.True(session.Disposed);
        Assert.Single(_world.AnyConnect.Sessions);
        Assert.Empty(_world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)));
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "office.example.org");
        var status = AnyConnectStatus(coordinator);
        Assert.Equal(SignInKind.Required, status.SignIn?.Kind);
        Assert.Equal("«Офис»: DTLS и TLS не отвечают", status.SignIn?.Error);
        Assert.Null(status.ServerNetworks);
        Assert.NotEqual(Decision.Vpn, coordinator.Facts.Policy!.Classify(Ipv4.Parse("10.1.2.3")).Decision);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task AnyConnect_GatewayForm_ForwardsOnlyCurrentRequest()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var request = Guid.NewGuid();
        session.Emit(new AuthFormEvent(request, "Вход", null, "Неверный пароль",
            [new AuthFieldDto("password", "Пароль", AuthFieldKind.Password, [], null)]));
        await CompleteDialAsync(coordinator);
        Assert.Equal(SignInKind.Form, AnyConnectStatus(coordinator).SignIn?.Kind);
        Assert.Equal("Неверный пароль", AnyConnectStatus(coordinator).SignIn?.Error);

        var stale = await coordinator.HandleRequestAsync(new SubmitAuthFormRequest(_anyConnect.Id, Guid.NewGuid(), new Dictionary<string, string> { ["password"] = "x" }, false), CancellationToken.None);
        var current = await coordinator.HandleRequestAsync(new SubmitAuthFormRequest(_anyConnect.Id, request, new Dictionary<string, string> { ["password"] = "x" }, false), CancellationToken.None);

        Assert.Equal(IpcErrorCodes.NotFound, stale.ErrorCode);
        Assert.True(current.Ok);
        Assert.Single(session.Commands.OfType<FormReplyCommand>());
        Assert.Null(AnyConnectStatus(coordinator).SignIn);
    }

    [Fact]
    public async Task AnyConnect_ClosingSignInWindow_CancelsAndDoesNotRestart()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var request = Guid.NewGuid();
        session.Emit(new SsoOpenEvent(request, "https://" + Gateway + "/saml", Gateway));
        await CompleteDialAsync(coordinator);

        await coordinator.HandleRequestAsync(new CancelSignInRequest(_anyConnect.Id, request), CancellationToken.None);
        session.Emit(new TerminatedEvent(TerminationKind.Cancelled, "вход отменён"));
        await CompleteDialAsync(coordinator);
        await TickAsync(coordinator);

        Assert.Contains(session.Commands, c => c is WebviewClosedCommand);
        Assert.Single(_world.AnyConnect.Sessions);
        Assert.Equal(SignInKind.Required, AnyConnectStatus(coordinator).SignIn?.Kind);
    }

    [Fact]
    public async Task AnyConnect_Disconnect_StopsHelperAndIgnoresLateEvents()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        session.Emit(new TerminatedEvent(TerminationKind.NetworkError, "поздно"));
        await CompleteDialAsync(coordinator);

        Assert.IsType<StopCommand>(session.Commands[^1]);
        Assert.True(session.Disposed);
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.Contains("поздно", StringComparison.Ordinal));
        Assert.Empty(_world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)));
        Assert.Null(coordinator.Facts.Tunnels[_anyConnect.Id].AnyConnect);
    }

    [Fact]
    public async Task AnyConnect_ServiceShutdown_WithdrawsNetworksAndSendsStop()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);

        coordinator.ShutdownAnyConnect();

        Assert.Empty(_world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)));
        Assert.NotEqual(Decision.Vpn, coordinator.Facts.Policy!.Classify(Ipv4.Parse("10.1.2.3")).Decision);
        Assert.IsType<StopCommand>(session.Commands[^1]);
        Assert.True(session.Disposed);
        Assert.True(_world.Ras.Connected);
    }

    [Fact]
    public async Task AnyConnect_CertificateRejected_StopsRetriesUntilUserAction()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        _world.AnyConnect.Last!.Emit(new TerminatedEvent(TerminationKind.CertificateRejected, "issuer unknown"));
        await CompleteDialAsync(coordinator);
        await coordinator.HandleRequestAsync(new BeginSignInRequest(_anyConnect.Id), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.Equal(2, _world.AnyConnect.Sessions.Count);
        _world.AnyConnect.Last!.Emit(new TerminatedEvent(TerminationKind.CertificateRejected, "issuer unknown"));
        await CompleteDialAsync(coordinator);
        await TickAsync(coordinator);

        var status = AnyConnectStatus(coordinator);
        Assert.Equal(ConnectionState.Error, status.State);
        Assert.Equal(ErrorCategory.Certificate, status.ErrorCategory);
        Assert.Null(status.SignIn);
        Assert.Equal(2, _world.AnyConnect.Sessions.Count);
    }

    [Fact]
    public async Task AnyConnect_MissingHelper_ReportsErrorWithoutBreakingOtherTunnels()
    {
        _world.AnyConnect.FailStart = true;
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);

        var status = AnyConnectStatus(coordinator);
        Assert.Equal(ConnectionState.Error, status.State);
        Assert.Contains("помощник AnyConnect", status.ErrorText, StringComparison.Ordinal);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task AnyConnect_ProfileTest_PointsToConnect()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var response = await coordinator.BeginProfileTest(_anyConnect.Id);
        Assert.False(response.Ok);
        Assert.Empty(_world.AnyConnect.Sessions);
    }

    [Fact]
    public async Task AnyConnect_SessionSuffixesJoinAdapterSearchListAndLeaveWithSession()
    {
        _world.Dns.SearchLists[FakeWorld.WiFiGuid] = "corp.example";
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        Assert.Equal("corp.example", _world.Dns.SearchLists[FakeWorld.WiFiGuid]);

        var session = await EstablishAsync(coordinator);
        Assert.Equal("corp.example,office.example.org,local", _world.Dns.SearchLists[FakeWorld.WiFiGuid]);

        _world.Inventory.RemoveTunnel(AnyConnectSlot);
        session.Emit(new TerminatedEvent(TerminationKind.NetworkError, "DTLS и TLS не отвечают"));
        await CompleteDialAsync(coordinator);
        await TickAsync(coordinator);
        Assert.Equal("corp.example", _world.Dns.SearchLists[FakeWorld.WiFiGuid]);
    }

    [Fact]
    public async Task AnyConnect_OnlyTunnelWithDirectInternet_KeepsDnsDirectBeforeSignIn()
    {
        var coordinator = await StartWithAnyConnectAsync(new AppSettings { Profiles = [_anyConnect], DefaultTarget = RouteTarget.Direct });

        await ConnectAsync(coordinator);

        Assert.Equal(DnsProxyMode.DirectAllowed, _world.Proxy.Configuration.Mode);
        Assert.NotNull(_world.Proxy.Configuration.Direct);
    }
}
