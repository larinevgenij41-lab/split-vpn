using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Данные недоверенного шлюза AnyConnect: адрес туннеля, узлы перенаправления, DNS шлюза, хост PAC, тексты входа.
/// Шлюз не должен отнять у машины адрес маршрутизатора, локальной сети, DNS или сервера VPN.
/// </summary>
public sealed partial class CoordinatorTests
{
    private async Task<FakeAnyConnectSession> EstablishSessionAsync(Coordinator coordinator, SessionInfo gatewaySession)
    {
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        _world.Inventory.AddTunnel(AnyConnectSlot);
        session.Emit(new EstablishedEvent(FakeInventory.TunnelLuid(AnyConnectSlot), "SplitVpn AC", gatewaySession));
        await CompleteDialAsync(coordinator);
        return session;
    }

    [Theory]
    [InlineData("192.168.1.1", "маршрутизатора")]
    [InlineData("192.168.1.77", "локальной сети")]
    [InlineData("198.51.100.10", "сервера VPN")]
    [InlineData("127.0.0.1", "служебный диапазон")]
    [InlineData("169.254.3.3", "служебный диапазон")]
    [InlineData("192.168.44.20", "занят подключением")]
    public async Task AnyConnect_ConflictingTunnelAddress_StopsSessionWithBlockingError(string address, string cause)
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishSessionAsync(coordinator, GatewaySession() with { Address = address });

        var tunnel = coordinator.Facts.Tunnels[_anyConnect.Id];
        Assert.Null(tunnel.AnyConnect);
        Assert.False(tunnel.IsUp);
        Assert.Equal(ErrorCategory.Other, tunnel.BlockingError);
        Assert.Contains(cause, tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.Contains(address, tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.Contains(session.Commands, c => c is StopCommand);
        Assert.True(session.Disposed);
        Assert.DoesNotContain(_world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)), r => r.Contains(Ipv4.Parse("10.1.2.3")));
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Ошибка" && e.Text.Contains(cause, StringComparison.Ordinal));

        // Блокирующая ошибка: помощник сам не перезапускается.
        await TickAsync(coordinator);
        Assert.Single(_world.AnyConnect.Sessions);
    }

    [Fact]
    public async Task AnyConnect_ServiceDnsTunnelAddress_IsRejected()
    {
        var coordinator = await StartWithAnyConnectAsync(Settings() with { Profiles = [_profile, _anyConnect], LocalDnsServer = "9.9.9.9" });
        await EstablishSessionAsync(coordinator, GatewaySession() with { Address = "9.9.9.9" });

        var tunnel = coordinator.Facts.Tunnels[_anyConnect.Id];
        Assert.Null(tunnel.AnyConnect);
        Assert.Contains("DNS-сервера", tunnel.LastErrorText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnyConnect_IpInfoChangedToRouterAddress_StopsSession()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        Assert.True(coordinator.Facts.Tunnels[_anyConnect.Id].IsUp);

        session.Emit(new IpInfoChangedEvent(GatewaySession() with { Address = "192.168.1.1" }));
        await CompleteDialAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_anyConnect.Id];
        Assert.Null(tunnel.AnyConnect);
        Assert.False(tunnel.IsUp);
        Assert.Equal(ErrorCategory.Other, tunnel.BlockingError);
        Assert.Contains("маршрутизатора", tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.Contains(session.Commands, c => c is StopCommand);
        Assert.NotEqual(Decision.Vpn, coordinator.Facts.Policy!.Classify(Ipv4.Parse("10.1.2.3")).Decision);
    }

    [Fact]
    public async Task AnyConnect_OrdinaryTunnelAddress_IsAccepted()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_anyConnect.Id];
        Assert.True(tunnel.IsUp);
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
    }

    /// <summary>Перенаправление на адрес локальной сети, loopback и т. п. не открывает к нему прямой путь.</summary>
    [Theory]
    [InlineData("192.168.1.7")]
    [InlineData("192.168.1.1")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.1.1")]
    [InlineData("239.1.1.1")]
    [InlineData("0.0.0.0")]
    public async Task AnyConnect_RedirectToForbiddenLiteral_IsNotOpened(string literal)
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;

        session.Emit(new ResolveHostEvent(literal, 443));
        await CompleteDialAsync(coordinator);

        Assert.Contains(session.Commands, c => c is ResolveReplyCommand { Address: null } reply && reply.Host == literal);
        Assert.DoesNotContain(Ipv4.Parse(literal), coordinator.Facts.Policy!.ServerAddresses);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(Ipv4.Parse(literal), 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("отброшены адреса " + literal, StringComparison.Ordinal));
    }

    /// <summary>У узла кластера с адресами разного сорта открываются только допустимые; запрет пользователя действует.</summary>
    [Fact]
    public async Task AnyConnect_RedirectNodeAddresses_AreFiltered()
    {
        var good = Ipv4.Parse("198.51.100.20");
        var blocked = Ipv4.Parse("93.184.216.66");
        _world.Resolver.Answers["node2.example.org"] = [Ipv4.Parse("127.0.0.1"), Ipv4.Parse("192.168.1.9"), blocked, Ipv4.Parse("169.254.9.9"), good, FakeWorld.Gateway];
        var coordinator = await StartWithAnyConnectAsync(Settings() with
        {
            Profiles = [_profile, _anyConnect],
            Rules = [new UserRuleSetting { Cidr = "93.184.216.64/30", Target = RouteTarget.Blocked }],
        });
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;

        session.Emit(new ResolveHostEvent("node2.example.org", 443));
        await CompleteDialAsync(coordinator);

        var reply = Assert.Single(session.Commands.OfType<ResolveReplyCommand>(), c => c.Host == "node2.example.org");
        Assert.Equal("198.51.100.20", reply.Address);
        Assert.Equal(["198.51.100.20"], reply.Addresses);
        Assert.Contains(good, coordinator.Facts.Policy!.ServerAddresses);
        Assert.DoesNotContain(blocked, coordinator.Facts.Policy!.ServerAddresses);
        Assert.Equal(Decision.Block, coordinator.Facts.Policy!.Classify(blocked).Decision);
        Assert.Equal(DecisionSource.OnLink, coordinator.Facts.Policy!.Classify(Ipv4.Parse("192.168.1.9")).Source);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("запрещён правилом пользователя", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnyConnect_RedirectNodeWithOnlyForbiddenAddresses_IsNotOpened()
    {
        _world.Resolver.Answers["node3.example.org"] = [Ipv4.Parse("127.0.0.1"), FakeWorld.Gateway];
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;

        session.Emit(new ResolveHostEvent("node3.example.org", 443));
        await CompleteDialAsync(coordinator);

        var reply = Assert.Single(session.Commands.OfType<ResolveReplyCommand>(), c => c.Host == "node3.example.org");
        Assert.Null(reply.Address);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("нет допустимых адресов", StringComparison.Ordinal));
    }

    /// <summary>Сам шлюз профиля - выбор пользователя: его адрес не фильтруется, даже если он в локальной сети.</summary>
    [Fact]
    public void GatewayNodeAddressProblem_NamesEachCause()
    {
        var primary = new AdapterCandidate
        {
            InterfaceGuid = Guid.NewGuid(), Name = "Wi-Fi", DefaultGateway = Ipv4.Parse("192.168.1.1"),
            OnLinkPrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")], Addresses = [Ipv4.Parse("192.168.1.100")],
        };
        IReadOnlyList<UserRule> rules =
        [
            new(Ipv4Cidr.Parse("203.0.113.0/24"), RouteTarget.Blocked),
            new(Ipv4Cidr.Parse("203.0.113.8/29"), RouteTarget.Direct),
        ];
        uint[] dns = [Ipv4.Parse("9.9.9.9")];

        string? Problem(string address) => Coordinator.GatewayNodeAddressProblem(Ipv4.Parse(address), primary, dns, rules);

        Assert.Equal("служебный диапазон", Problem("255.255.255.255"));
        Assert.Equal("маршрутизатор локальной сети", Problem("192.168.1.1"));
        Assert.Equal("локальная сеть", Problem("192.168.1.50"));
        Assert.Equal("DNS-сервер сети", Problem("9.9.9.9"));
        Assert.Equal("запрещён правилом пользователя", Problem("203.0.113.1"));
        Assert.Null(Problem("203.0.113.9"));
        Assert.Null(Problem("198.51.100.20"));
    }

    /// <summary>DNS шлюза из домашней сети: локальная сеть важнее, адрес уходит из DNS туннеля с предупреждением.</summary>
    [Fact]
    public async Task AnyConnect_GatewayDnsInLan_StaysLocalAndWarns()
    {
        var lanHost = Ipv4.Parse("192.168.1.10");
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishSessionAsync(coordinator, GatewaySession() with { Dns = ["192.168.1.10", "10.0.16.21", "169.254.1.1"] });

        var tunnel = coordinator.Facts.Tunnels[_anyConnect.Id];
        Assert.True(tunnel.IsUp);
        Assert.Equal([GatewayDns], tunnel.VpnDns);
        Assert.Equal(DecisionSource.OnLink, coordinator.Facts.Policy!.Classify(lanHost).Source);
        Assert.Equal(DecisionSource.TunnelInfrastructure, coordinator.Facts.Policy!.Classify(GatewayDns).Source);
        var office = Assert.Single(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "office.example.org");
        Assert.Equal([GatewayDns], office.Route!.Servers.Select(s => Ipv4.ToUInt(s.Address)));
        var warning = Assert.Single(coordinator.BuildStatus().Warnings, w => w.Code == "gateway-dns-lan");
        Assert.Contains("192.168.1.10", warning.Text, StringComparison.Ordinal);
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("совпадает с локальной сетью", StringComparison.Ordinal));

        // Повторная сверка не повторяет запись в журнале.
        await TickAsync(coordinator);
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("совпадает с локальной сетью", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnyConnect_OrdinaryGatewayDns_HasNoLanWarning()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishAsync(coordinator);

        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "gateway-dns-lan");
    }

    /// <summary>Хост PAC идёт к DNS шлюза только при применении прокси шлюза и только годным именем.</summary>
    [Fact]
    public void GatewayDnsNames_PacHostOnlyWithAppliedProxyAndValidName()
    {
        var session = new SessionInfo { SplitDns = ["office.example.org"], ProxyPac = "http://pac.corp.example.net/proxy.pac" };

        Assert.Equal(["office.example.org"], Coordinator.GatewayDnsNames(session, includePac: false));
        Assert.Equal(["office.example.org", "pac.corp.example.net"], Coordinator.GatewayDnsNames(session, includePac: true));
        Assert.Equal(["office.example.org"], Coordinator.GatewayDnsNames(session with { ProxyPac = "http://wpad/proxy.pac" }, includePac: true));
        Assert.Equal(["office.example.org"], Coordinator.GatewayDnsNames(session with { ProxyPac = "http://com.ru/proxy.pac" }, includePac: true));
    }

    [Fact]
    public async Task AnyConnect_HugeAuthForm_IsCappedInStatus()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var choices = Enumerable.Range(0, 1000).Select(i => new AuthChoiceDto("g" + i, "группа " + i)).ToList();
        var fields = Enumerable.Range(0, 100).Select(i => new AuthFieldDto("f" + i, new string('l', 1000), AuthFieldKind.Select, choices, null)).ToList();

        session.Emit(new AuthFormEvent(Guid.NewGuid(), new string('b', 1_900_000), "m", null, fields));
        await CompleteDialAsync(coordinator);

        var prompt = AnyConnectStatus(coordinator).SignIn!;
        Assert.Equal(SignInKind.Form, prompt.Kind);
        Assert.Equal(HelperLimits.MaxFormText, prompt.Title!.Length);
        Assert.InRange(prompt.Fields.Count, 1, HelperLimits.MaxFormFields);
        Assert.Equal(HelperLimits.MaxChoices, prompt.Fields[0].Choices.Count);
        Assert.All(prompt.Fields, f => Assert.Equal(HelperLimits.MaxLabel, f.Label.Length));
        Assert.True(IpcSerializer.SerializeResponse(IpcResponse.Success(coordinator.BuildStatus())).Length < FrameCodec.MaxFrameBytes);
    }

    [Fact]
    public async Task AnyConnect_TooLongSsoUri_IsRejectedNotTruncated()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;

        session.Emit(new SsoOpenEvent(Guid.NewGuid(), "https://" + Gateway + "/saml?" + new string('a', HelperLimits.MaxSsoUri), Gateway));
        await CompleteDialAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_anyConnect.Id];
        Assert.Null(tunnel.SignIn);
        Assert.Null(tunnel.AnyConnect);
        Assert.Equal(ErrorCategory.Other, tunnel.BlockingError);
        Assert.Contains("слишком длинный адрес страницы входа", tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.Contains(session.Commands, c => c is StopCommand);
    }

    [Fact]
    public async Task AnyConnect_SsoUriWithinLimit_IsShown()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var uri = "https://" + Gateway + "/saml?" + new string('a', 4000);

        session.Emit(new SsoOpenEvent(Guid.NewGuid(), uri, Gateway));
        await CompleteDialAsync(coordinator);

        Assert.Equal(uri, AnyConnectStatus(coordinator).SignIn?.Uri);
    }

    /// <summary>Сеанс, урезанный помощником, служба отмечает в журнале и на главной.</summary>
    [Fact]
    public async Task AnyConnect_TruncatedSession_IsJournaledAndWarned()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishSessionAsync(coordinator, GatewaySession() with { Truncated = ["сети шлюза (split-include): взято 16384 из 70000"] });

        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Предупреждение" && e.Text.Contains("взято 16384 из 70000", StringComparison.Ordinal));
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "gateway-session-truncated");
    }
}
