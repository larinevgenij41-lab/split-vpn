using System.Net;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Итерация 13: исправления по состязательной проверке ядра решений итерации 12 - закрепления по домену на частных
/// адресах и под ручными правилами, отказ вместо адреса мимо правила, предупреждения о публичной сети адаптера,
/// доверие к виртуальным сетям, DNS шлюза AnyConnect под широким правилом, узлы шлюза в публичной сети адаптера.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly uint CorpAddress = Ipv4.Parse("10.20.30.40");

    private Task<bool> ObservePin(Coordinator coordinator, string suffix, RouteTarget target, uint address) =>
        coordinator.ObservePinnedAsync(new PinnedRouteNotice(suffix, suffix, target, [address], TimeSpan.FromMinutes(5)), CancellationToken.None).AsTask();

    /// <summary>
    /// П.1: «corp.example → туннель», имена в 10.x. Адрес закрепляется за туннелем (маршрут /32 в туннель), ответ отдаётся;
    /// когда туннель лежит, адрес блокируется, а не уходит в сеть гостиницы или по маршруту по умолчанию.
    /// </summary>
    [Fact]
    public async Task CorpDomainInPrivateRange_IsPinnedIntoTunnel_AndBlockedWhileTunnelDown()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "corp.example", Target = vpn }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var pin = ObservePin(coordinator, "corp.example", vpn, CorpAddress);
        await coordinator.DrainAsync();

        Assert.True(await pin);
        Assert.Contains(coordinator.Facts.Policy!.Pins, p => p.Address == CorpAddress && p.Target == vpn);
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(CorpAddress, 32) && r.InterfaceLuid == FakeInventory.TunnelLuid(0));
        Assert.Equal(FilterAction.Block, RoutingAction(CorpAddress, FakeWorld.WiFiLuid));
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "domain-pin-rejected");

        _world.Ras.Results.Enqueue(Failed(800));
        _world.Ras.Results.Enqueue(Failed(800));
        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.False(coordinator.Facts.Tunnels[_profile.Id].IsUp);
        Assert.Contains(coordinator.Facts.Policy!.Pins, p => p.Address == CorpAddress);
        Assert.Equal(FilterAction.Block, RoutingAction(CorpAddress, FakeWorld.WiFiLuid));
    }

    /// <summary>
    /// П.1, п.8: «напрямую» на частный адрес молча не закрепляется (ответ отдаётся, адрес локален) и не мешает другому
    /// домену закрепить тот же адрес за туннелем - отказа из-за конфликта нет.
    /// </summary>
    [Fact]
    public async Task IgnoredDirectPinOnPrivateAddress_DoesNotConflictWithTunnelPin()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with
        {
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "ru", Target = RouteTarget.Direct },
                new DomainRuleSetting { Suffix = "corp.example", Target = vpn },
            ],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var direct = ObservePin(coordinator, "ru", RouteTarget.Direct, CorpAddress);
        await coordinator.DrainAsync();
        Assert.True(await direct);
        Assert.DoesNotContain(coordinator.Facts.Policy!.Pins, p => p.Address == CorpAddress);
        Assert.Equal(Decision.Local, coordinator.Facts.Policy.Classify(CorpAddress).Decision);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(CorpAddress, 32));

        var tunnel = ObservePin(coordinator, "corp.example", vpn, CorpAddress);
        await coordinator.DrainAsync();
        Assert.True(await tunnel);
        Assert.Equal(vpn, coordinator.Facts.Policy!.PinTarget(CorpAddress));
        Assert.Equal(FilterAction.Block, RoutingAction(CorpAddress, FakeWorld.WiFiLuid));
    }

    /// <summary>
    /// П.2: «104.16.0.0/12 → туннель» и «bank.ru → Напрямую» с равным приоритетом - домен важнее (как в 0.18.0): адрес
    /// идёт напрямую. При более высоком приоритете CIDR-правила - отказ (SERVFAIL) и предупреждение.
    /// </summary>
    [Theory]
    [InlineData(RoutePriority.Normal, true)]
    [InlineData(RoutePriority.High, false)]
    public async Task DirectDomainUnderCidrTunnelRule_FollowsPriority(RoutePriority cidrPriority, bool accepted)
    {
        var bank = Ipv4.Parse("104.16.10.20");
        SaveSettings(Settings() with
        {
            Rules = [new UserRuleSetting { Cidr = "104.16.0.0/12", Target = RouteTarget.Tunnel(_profile.Id), Priority = cidrPriority }],
            DomainRules = [new DomainRuleSetting { Suffix = "bank.ru", Target = RouteTarget.Direct }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var pin = ObservePin(coordinator, "bank.ru", RouteTarget.Direct, bank);
        await coordinator.DrainAsync();

        Assert.Equal(accepted, await pin);
        Assert.Equal(accepted ? Decision.Direct : Decision.Vpn, coordinator.Facts.Policy!.Classify(bank).Decision);
        Assert.Equal(accepted ? FilterAction.Permit : FilterAction.Block, RoutingAction(bank, FakeWorld.WiFiLuid));
        Assert.Equal(!accepted, coordinator.BuildStatus().Warnings.Any(w => w.Code == "domain-pin-rejected" && w.Text.Contains("bank.ru", StringComparison.Ordinal)));
    }

    /// <summary>
    /// П.1, п.8: политика стала строже уже принятого закрепления (CIDR-правилу поднят приоритет). Сборка снимает отклонённое
    /// закрепление из реестра: следующий ответ получает отказ, предупреждение называет правило, а адрес больше не держит
    /// конфликт - другой домен закрепляет его за туннелем.
    /// </summary>
    [Fact]
    public async Task PinRejectedAfterRuleChange_IsDroppedFromRegistry()
    {
        var shared = Ipv4.Parse("151.101.4.71");
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var settings = Settings() with
        {
            Rules = [new UserRuleSetting { Cidr = "151.101.0.0/16", Target = vpn }],
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "direct.example", Target = RouteTarget.Direct },
                new DomainRuleSetting { Suffix = "vpn.example", Target = vpn },
            ],
        };
        SaveSettings(settings);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var first = ObservePin(coordinator, "direct.example", RouteTarget.Direct, shared);
        await coordinator.DrainAsync();
        Assert.True(await first);
        Assert.Equal(RouteTarget.Direct, coordinator.Facts.Pinned[shared].Target);

        var stricter = settings with { Rules = [new UserRuleSetting { Cidr = "151.101.0.0/16", Target = vpn, Priority = RoutePriority.High }] };
        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(stricter), CancellationToken.None)).Ok);
        await TickAsync(coordinator);

        Assert.DoesNotContain(shared, coordinator.Facts.Pinned.Keys);
        Assert.Equal(Decision.Vpn, coordinator.Facts.Policy!.Classify(shared).Decision);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "domain-pin-rejected" && w.Text.Contains("direct.example", StringComparison.Ordinal));
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("direct.example", StringComparison.Ordinal) && e.Text.Contains("не закреплён", StringComparison.Ordinal));

        Assert.False(await ObservePin(coordinator, "direct.example", RouteTarget.Direct, shared));
        var other = ObservePin(coordinator, "vpn.example", vpn, shared);
        await coordinator.DrainAsync();
        Assert.True(await other);
        Assert.Equal(vpn, coordinator.Facts.Policy!.PinTarget(shared));
    }

    /// <summary>
    /// П.1: закрепление в туннель поверх запрета пользователя отклоняется: адрес не отдаётся программе, предупреждение
    /// ограничено и снимается, когда правило для домена исчезает.
    /// </summary>
    [Fact]
    public async Task PinOverUserBlock_IsRefusedWithBoundedWarning()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var settings = Settings() with
        {
            Rules = [new UserRuleSetting { Cidr = "45.10.0.0/16", Target = RouteTarget.Blocked }],
            DomainRules = [new DomainRuleSetting { Suffix = "blocked.example", Target = vpn }],
        };
        SaveSettings(settings);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        for (var i = 0; i < Coordinator.MaxRejectedPinWarnings + 5; i++)
        {
            Assert.False(await ObservePin(coordinator, "blocked.example", vpn, Ipv4.Parse("45.10.0.1") + (uint)i));
        }

        var warning = Assert.Single(coordinator.BuildStatus().Warnings, w => w.Code == "domain-pin-rejected");
        Assert.Contains("запрещён правилом пользователя", warning.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("45.10.0.1", warning.Text, StringComparison.Ordinal);

        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(settings with { DomainRules = [] }), CancellationToken.None)).Ok);
        await TickAsync(coordinator);
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "domain-pin-rejected");
    }

    /// <summary>П.4: текст предупреждения о публичной сети адаптера.</summary>
    [Fact]
    public void PublicOnLinkText_GivesSafeAdvice()
    {
        var prefix = Ipv4Cidr.Parse("95.31.18.0/24");
        var primary = Coordinator.PublicOnLinkText("Ethernet", prefix, overlay: false, primary: true);
        Assert.Contains("провайдера, офиса или учебного заведения", primary, StringComparison.Ordinal);
        Assert.Contains("95.31.18.0/24 → «Напрямую»", primary, StringComparison.Ordinal);
        Assert.Contains("не добавляйте", primary, StringComparison.Ordinal);
        Assert.DoesNotContain("Доверенные адаптеры", primary, StringComparison.Ordinal);

        var secondary = Coordinator.PublicOnLinkText("Ethernet 2", prefix, overlay: false, primary: false);
        Assert.DoesNotContain("Доверенные адаптеры", secondary, StringComparison.Ordinal);
        Assert.DoesNotContain("Напрямую", secondary, StringComparison.Ordinal);

        var overlay = Coordinator.PublicOnLinkText("ZeroTier", prefix, overlay: true, primary: false);
        Assert.Contains("Доверенные адаптеры", overlay, StringComparison.Ordinal);
        Assert.DoesNotContain("Напрямую", overlay, StringComparison.Ordinal);
    }

    /// <summary>
    /// П.5: распознанная виртуальная сеть (ZeroTier) с публичной сетью вне диапазонов поставщика: сеть не локальна,
    /// разрешение адаптера её не включает, предупреждение советует отметить адаптер в «Доверенных адаптерах».
    /// </summary>
    [Fact]
    public async Task OverlayWithForeignPublicNetwork_IsNotLocal()
    {
        _world.Inventory.RadminDescription = "ZeroTier Virtual Port";
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.False(coordinator.Facts.Policy!.LocalRanges.Contains(RadminPeer));
        var trusted = Assert.Single(coordinator.Facts.AppliedFilters[FilterGroup.Runtime].Specs, f => f.Name == "Доверенный адаптер «Radmin VPN»");
        Assert.Contains(trusted.Conditions, c => c is RemoteRangesV4 r && !r.Contains(RadminPeer) && r.Contains(Ipv4.Parse("10.1.1.1")));
        var warning = Assert.Single(coordinator.BuildStatus().Warnings, w => w.Code == "public-onlink");
        Assert.Contains("Доверенные адаптеры", warning.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// П.6: маршруты доверенного адаптера (подсеть за Tailscale, управляемый маршрут ZeroTier) и его сети IPv6 - в его
    /// разрешении; у распознанной виртуальной сети - только частные маршруты и без IPv6.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TrustedAdapterRoutes_AreLocalOnlyForExplicitTrust(bool explicitTrust)
    {
        var radmin = Guid.NewGuid();
        var managed = Ipv4.Parse("91.108.4.10");
        var subnet = Ipv4.Parse("192.168.50.7");
        _world.Inventory.RadminGuid = radmin;
        _world.Inventory.RadminDescription = "Famatech Radmin VPN Ethernet Adapter";
        _world.Inventory.RadminPrefixesV6 = [IPNetwork.Parse("2001:db8:5::/64")];
        _world.Inventory.ExtraRoutes.Add(new RouteEntry(Ipv4Cidr.Parse("91.108.4.0/22"), 0, FakeWorld.RadminLuid, 19, 1, 3));
        _world.Inventory.ExtraRoutes.Add(new RouteEntry(Ipv4Cidr.Parse("192.168.50.0/24"), 0, FakeWorld.RadminLuid, 19, 1, 3));
        _world.Inventory.ExtraRoutes.Add(new RouteEntry(Ipv4Cidr.Parse("0.0.0.0/1"), 0, FakeWorld.RadminLuid, 19, 1, 3));
        SaveSettings(Settings() with { TrustedAdapters = explicitTrust ? [radmin] : [] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var specs = coordinator.Facts.AppliedFilters[FilterGroup.Runtime].Specs;
        var trusted = Assert.Single(specs, f => f.Name == "Доверенный адаптер «Radmin VPN»");
        var ranges = Assert.Single(trusted.Conditions.OfType<RemoteRangesV4>());
        Assert.True(ranges.Contains(RadminPeer));
        Assert.True(ranges.Contains(subnet));
        Assert.Equal(explicitTrust, ranges.Contains(managed));
        Assert.False(ranges.Contains(Ipv4.Parse("1.1.1.1")));
        Assert.Equal(explicitTrust, coordinator.Facts.Policy!.LocalRanges.Contains(managed));
        Assert.Equal(explicitTrust, specs.Any(f => f.Conditions.Any(c => c is RemotePrefixV6 p && p.Network == IPNetwork.Parse("2001:db8:5::/64"))));
    }

    /// <summary>
    /// П.7: широкое ручное правило (10.0.0.0/8 → «Напрямую») при «Ручные правила важнее сетей шлюза» не отбирает DNS шлюза:
    /// split DNS работает через него, предупреждения «gateway-dns-rule» нет.
    /// </summary>
    [Fact]
    public async Task AnyConnect_BroadUserRule_KeepsGatewayDns()
    {
        var coordinator = await StartWithAnyConnectAsync(Settings() with
        {
            Profiles = [_profile, _anyConnect],
            Rules = [new UserRuleSetting { Cidr = "10.0.0.0/8", Target = RouteTarget.Direct }],
        });
        await EstablishSessionAsync(coordinator, GatewaySession());

        Assert.Equal([GatewayDns], coordinator.Facts.Tunnels[_anyConnect.Id].VpnDns);
        Assert.Equal(DecisionSource.TunnelInfrastructure, coordinator.Facts.Policy!.Classify(GatewayDns).Source);
        Assert.Equal(_anyConnect.Id, coordinator.Facts.Policy.Classify(GatewayDns).Tunnel);
        var office = Assert.Single(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "office.example.org");
        Assert.Equal([GatewayDns], office.Route!.Servers.Select(s => Ipv4.ToUInt(s.Address)));
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "gateway-dns-rule");
    }

    /// <summary>
    /// П.7: DNS шлюза убран правилом ровно на его адрес - имена split DNS и правила для домена в AnyConnect не уходят к
    /// публичным резолверам: они не разрешаются (правило «недоступно», SERVFAIL), на главной - предупреждение.
    /// </summary>
    [Fact]
    public async Task AnyConnect_NoGatewayDnsLeft_NamesFailInsteadOfPublicResolvers()
    {
        var coordinator = await StartWithAnyConnectAsync(Settings() with
        {
            Profiles = [_profile, _anyConnect],
            Rules = [new UserRuleSetting { Cidr = "10.0.16.21/32", Target = RouteTarget.Direct }],
            DomainRules = [new DomainRuleSetting { Suffix = "corp.example", Target = RouteTarget.Tunnel(_anyConnect.Id) }],
        });
        await EstablishSessionAsync(coordinator, GatewaySession());

        Assert.Empty(coordinator.Facts.Tunnels[_anyConnect.Id].VpnDns);
        var office = Assert.Single(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "office.example.org");
        Assert.True(office.Unavailable);
        Assert.Null(office.Route);
        var corp = Assert.Single(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "corp.example");
        Assert.True(corp.Unavailable);
        Assert.Null(corp.Route);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "gateway-dns-rule");
    }

    /// <summary>
    /// П.10: узел шлюза в публичной сети недоверенного основного адаптера (публичная /16 университета) принимается как
    /// любой публичный адрес; узел в частной сети адаптера и сам маршрутизатор - нет.
    /// </summary>
    [Fact]
    public void GatewayNode_InUntrustedPublicOnLinkNetwork_IsAccepted()
    {
        var primary = new AdapterCandidate
        {
            InterfaceGuid = Guid.NewGuid(), Name = "Ethernet", DefaultGateway = Ipv4.Parse("141.20.0.1"), IsUp = true,
            OnLinkPrefixes = [Ipv4Cidr.Parse("141.20.0.0/16")], Addresses = [Ipv4.Parse("141.20.5.9")],
        };
        var local = RangeSet.From(PolicyCompiler.SelectOnLinkPrefixes([primary], _ => AdapterTrust.None).Local);

        Assert.Null(Coordinator.GatewayNodeAddressProblem(Ipv4.Parse("141.20.200.10"), primary, local, [], []));
        Assert.Equal("маршрутизатор локальной сети", Coordinator.GatewayNodeAddressProblem(Ipv4.Parse("141.20.0.1"), primary, local, [], []));
        Assert.Equal("локальная сеть", Coordinator.GatewayNodeAddressProblem(Ipv4.Parse("141.20.5.9"), primary, local, [], []));
        Assert.Equal("локальная сеть", Coordinator.GatewayNodeAddressProblem(Ipv4.Parse("192.168.1.5"), primary,
            RangeSet.From([Ipv4Cidr.Parse("192.168.1.0/24")]), [], []));
    }
}
