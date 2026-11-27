using System.Net;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>
/// Итерация 13: исправления по состязательной проверке итерации 12 - закрепления по домену поверх локальных сетей и
/// ручных правил, маршрутизатор недоверенного адаптера, доверие к виртуальным сетям, маршруты доверенного адаптера,
/// зарезервированные диапазоны.
/// </summary>
public partial class FilterPlanTests
{
    private static readonly uint CorpHost = Ipv4.Parse("10.20.30.40");

    /// <summary>
    /// П.1: «corp.example → туннель» с именами в 10.x. Закрепление в туннель поверх локальной сети принимается: адрес идёт
    /// только в свой туннель, а пока туннель лежит - блокируется (не уходит в сеть гостиницы по «Локальному доступу»,
    /// в другой VPN или по маршруту по умолчанию).
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TunnelPin_OnPrivateAddress_IsAcceptedAndBlockedWhileTunnelDown(bool secondUp)
    {
        var inputs = Inputs(Tunnel, secondUp ? SecondTunnel : null, [new PinnedHost(CorpHost, RouteTarget.Tunnel(TunnelB))]);
        var filters = All(inputs);

        Assert.Equal(new PinnedHost(CorpHost, RouteTarget.Tunnel(TunnelB)), Assert.Single(inputs.Policy.Pins));
        Assert.Empty(inputs.Policy.RejectedPins);
        Assert.Equal(TunnelB, inputs.Policy.Classify(CorpHost).Tunnel);
        Assert.Equal(DecisionSource.DomainRule, inputs.Policy.Classify(CorpHost).Source);
        Assert.Equal(secondUp ? FilterAction.Permit : FilterAction.Block, Evaluate(filters, Tcp(CorpHost, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(CorpHost, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(CorpHost, 443, Tunnel)));
    }

    /// <summary>П.1: закрепление в группу поверх локальной сети тоже принимается и раскрывается в участника.</summary>
    [Fact]
    public void GroupPin_OnPrivateAddress_IsAccepted()
    {
        var inputs = Inputs(Tunnel, SecondTunnel, [new PinnedHost(CorpHost, RouteTarget.Group(GroupAb))], group: [TunnelB]);

        Assert.Equal(RouteTarget.Tunnel(TunnelB), Assert.Single(inputs.Policy.Pins).Target);
        Assert.Equal(FilterAction.Permit, Evaluate(All(inputs), Tcp(CorpHost, 443, SecondTunnel)));
    }

    /// <summary>
    /// П.1: «ru → Напрямую» и evil.ru → 10.20.30.40 (подмена в духе DNS rebinding). Прямое закрепление на частный адрес
    /// не ставится (маршрут через маршрутизатор открыл бы адрес в обход «Локального доступа»): молчаливый отказ, адрес
    /// остаётся локальным, как и без программы. Если частную сеть правило ведёт в туннель - отказ с причиной.
    /// </summary>
    [Fact]
    public void DirectPin_OnPrivateAddress_IsNotPinned()
    {
        var local = Inputs(Tunnel, SecondTunnel, [new PinnedHost(CorpHost, RouteTarget.Direct)]);
        Assert.Empty(local.Policy.Pins);
        Assert.Empty(local.Policy.RejectedPins);
        Assert.Equal([CorpHost], local.Policy.IgnoredPins);
        Assert.Equal(Decision.Local, local.Policy.Classify(CorpHost).Decision);
        Assert.Equal((false, (string?)null), local.Policy.EvaluatePin(new PinnedHost(CorpHost, RouteTarget.Direct)));

        var ruled = Inputs(Tunnel, SecondTunnel, [new PinnedHost(RemoteLan, RouteTarget.Direct, RoutePriority.High)]);
        Assert.Empty(ruled.Policy.Pins);
        Assert.Contains("частный адрес", Assert.Single(ruled.Policy.RejectedPins).Reason, StringComparison.Ordinal);
        Assert.Equal(FilterAction.Block, Evaluate(All(ruled), Tcp(RemoteLan, 3389, WiFi)));
    }

    /// <summary>
    /// П.3: точка доступа назвала маршрутизатором ценный публичный адрес (DC Telegram). Правило 149.154.160.0/20 → туннель
    /// и закрепление по домену важнее: адрес идёт в туннель, мимо него не выпускается.
    /// </summary>
    [Fact]
    public void PublicGateway_OfUntrustedAdapter_YieldsToUserRuleAndPin()
    {
        var telegram = Ipv4.Parse("149.154.167.51");
        var hotspot = Adapter("Wi-Fi", "149.154.160.0/20", gateway: "149.154.167.51", luid: WiFi);
        var selection = PolicyCompiler.SelectOnLinkPrefixes([hotspot], _ => AdapterTrust.None);
        Assert.Empty(selection.Local);
        Assert.Equal([new AdapterGateway(telegram, WiFi)], selection.Gateways);

        ProtectionInputs Build(IReadOnlyList<UserRule> rules, IReadOnlyList<PinnedHost> pins)
        {
            var policy = PolicyCompiler.Compile(new PolicyInput
            {
                DefaultTarget = RouteTarget.Direct,
                Rules = rules,
                ServerAddresses = [Server],
                OnLinePrefixes = selection.Local,
                AdapterGateways = [.. selection.Gateways.Select(g => g.Address)],
                PinnedHosts = pins,
            });
            return new ProtectionInputs
            {
                Policy = policy,
                PrimaryLuid = WiFi,
                Tunnels = [new TunnelInput { Id = TunnelA, Name = "Основной", Luid = Tunnel, ServerAddresses = [Server] }],
                ServiceExecutablePath = ServiceExe,
                OnLinkPrefixes = selection.Local,
                AdapterGateways = selection.Gateways,
            };
        }

        // Без правила маршрутизатор локален и доступен только через свой адаптер.
        var plain = Build([], []);
        Assert.Equal(Decision.Local, plain.Policy.Classify(telegram).Decision);
        Assert.Equal(FilterAction.Permit, Evaluate(All(plain), Tcp(telegram, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(All(plain), Tcp(telegram, 443, Radmin)));

        // Правило пользователя важнее: адрес в туннеле, мимо туннеля - блок.
        var ruled = Build([new UserRule(Ipv4Cidr.Parse("149.154.160.0/20"), RouteTarget.Tunnel(TunnelA))], []);
        Assert.Equal(Decision.Vpn, ruled.Policy.Classify(telegram).Decision);
        Assert.DoesNotContain(FilterPlanBuilder.BuildRuntime(ruled), f => f.Name.StartsWith("Маршрутизатор", StringComparison.Ordinal));
        Assert.Equal(FilterAction.Block, Evaluate(All(ruled), Tcp(telegram, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(All(ruled), Tcp(telegram, 443, Tunnel)));

        // Закрепление по домену в туннель тоже важнее и принимается.
        var pinned = Build([], [new PinnedHost(telegram, RouteTarget.Tunnel(TunnelA))]);
        Assert.Single(pinned.Policy.Pins);
        Assert.Equal(FilterAction.Block, Evaluate(All(pinned), Tcp(telegram, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(All(pinned), Tcp(telegram, 443, Tunnel)));
    }

    /// <summary>П.3: маршрутизатор с частным адресом в публичной сети адаптера остаётся локальным, как прежде.</summary>
    [Fact]
    public void PrivateGateway_InPublicPrefix_StaysOnLinkLocal()
    {
        var odd = Adapter("Ethernet", "100.0.0.0/8", gateway: "100.64.0.1", luid: WiFi);
        var selection = PolicyCompiler.SelectOnLinkPrefixes([odd], _ => AdapterTrust.None);

        Assert.Equal([Ipv4Cidr.Parse("100.64.0.1/32")], selection.Local);
        Assert.Empty(selection.Gateways);
    }

    /// <summary>
    /// П.5: распознанная виртуальная сеть доверена только в частных диапазонах и диапазонах поставщика. Контроллер ZeroTier,
    /// назначивший 149.154.160.0/20, этот кусок интернета локальным не делает; явное доверие (GUID) - делает.
    /// </summary>
    [Fact]
    public void OverlayTrust_CoversOnlyPrivateAndVendorRanges()
    {
        var radmin = Adapter("Radmin VPN", "26.0.0.0/8", description: "Famatech Radmin VPN Ethernet Adapter");
        var hamachi = Adapter("Hamachi", "25.0.0.0/8", description: "LogMeIn Hamachi Virtual Ethernet Adapter");
        var zeroTier = Adapter("ZeroTier", "149.154.160.0/20", description: "ZeroTier Virtual Port");
        var zeroTierLan = Adapter("ZeroTier LAN", "10.147.17.0/24", description: "ZeroTier Virtual Port");

        var overlay = PolicyCompiler.SelectOnLinkPrefixes([radmin, hamachi, zeroTier, zeroTierLan], _ => AdapterTrust.Overlay);
        Assert.Equal([Ipv4Cidr.Parse("26.0.0.0/8"), Ipv4Cidr.Parse("25.0.0.0/8"), Ipv4Cidr.Parse("10.147.17.0/24")], overlay.Local);
        Assert.Equal([Ipv4Cidr.Parse("149.154.160.0/20")], overlay.Untrusted.Select(u => u.Prefix));

        // Radmin с чужим публичным диапазоном (не 26.0.0.0/8) тоже не локален.
        var odd = Adapter("Radmin VPN", "91.108.4.0/22", description: "Famatech Radmin VPN Ethernet Adapter");
        Assert.Empty(PolicyCompiler.SelectOnLinkPrefixes([odd], _ => AdapterTrust.Overlay).Local);

        var explicitTrust = PolicyCompiler.SelectOnLinkPrefixes([zeroTier], _ => AdapterTrust.Explicit);
        Assert.Equal([Ipv4Cidr.Parse("149.154.160.0/20")], explicitTrust.Local);
        Assert.Empty(explicitTrust.Untrusted);
    }

    /// <summary>
    /// П.6: маршруты доверенного адаптера (подсеть за Tailscale, управляемый маршрут ZeroTier) - его сети; маршрут по
    /// умолчанию и пара /1 - никогда. У распознанной виртуальной сети - только частные и диапазоны поставщика.
    /// </summary>
    [Fact]
    public void TrustedNetworks_IncludeAdapterRoutes()
    {
        var zeroTier = Adapter("ZeroTier", "10.147.17.0/24", description: "ZeroTier Virtual Port");
        Ipv4Cidr[] routes =
        [
            Ipv4Cidr.Parse("0.0.0.0/0"), Ipv4Cidr.Parse("0.0.0.0/1"), Ipv4Cidr.Parse("128.0.0.0/1"), Ipv4Cidr.Parse("4.0.0.0/6"),
            Ipv4Cidr.Parse("192.168.50.0/24"), Ipv4Cidr.Parse("91.108.4.0/22"),
        ];

        Assert.Equal(
            [Ipv4Cidr.Parse("10.147.17.0/24"), Ipv4Cidr.Parse("192.168.50.0/24"), Ipv4Cidr.Parse("91.108.4.0/22")],
            PolicyCompiler.TrustedNetworks(zeroTier, AdapterTrust.Explicit, routes));
        Assert.Equal(
            [Ipv4Cidr.Parse("10.147.17.0/24"), Ipv4Cidr.Parse("192.168.50.0/24")],
            PolicyCompiler.TrustedNetworks(zeroTier, AdapterTrust.Overlay, routes));
        Assert.Equal([Ipv4Cidr.Parse("10.147.17.0/24")], PolicyCompiler.TrustedNetworks(zeroTier, AdapterTrust.None, routes));

        // Маршруты входят и в локальные сети выбора: явное доверие делает публичный управляемый маршрут локальным.
        var selection = PolicyCompiler.SelectOnLinkPrefixes([zeroTier], _ => AdapterTrust.Explicit, _ => routes);
        Assert.Contains(Ipv4Cidr.Parse("91.108.4.0/22"), selection.Local);
        Assert.DoesNotContain(Ipv4Cidr.Parse("0.0.0.0/1"), selection.Local);
    }

    /// <summary>П.6: разрешение доверенного адаптера включает его маршруты и сети IPv6, но не весь интернет.</summary>
    [Fact]
    public void TrustedAdapterPermit_CoversRoutesAndIpv6Prefixes()
    {
        var adapter = new TrustedAdapterInput(Radmin, "ZeroTier")
        {
            Prefixes = [Ipv4Cidr.Parse("10.147.17.0/24"), Ipv4Cidr.Parse("91.108.4.0/22")],
            PrefixesV6 = [IPNetwork.Parse("2001:db8:5::/64")],
        };
        var filters = All(Inputs(tunnel: null) with { OutageMode = OutageMode.BlockAllPublic, LocalAccess = false, TrustedAdapters = [adapter] });

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("91.108.4.10"), 443, Radmin)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("10.147.17.5"), 443, Radmin)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 443, Radmin)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Packet.V6("2001:db8:5::10", 6, 443, Radmin)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.V6("2a00:1450:4001::1", 6, 443, Radmin)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.V6("2001:db8:5::10", 6, 443, WiFi)));
    }

    /// <summary>
    /// П.9: DS-Lite (192.0.0.0/29) и адаптеры TUN с fake-IP (198.18.0.0/15) - частные в сети адаптера, предупреждения нет;
    /// документационные сети тоже без предупреждения.
    /// </summary>
    [Theory]
    [InlineData("192.0.0.0/29", true, false)]
    [InlineData("198.18.0.0/16", true, false)]
    [InlineData("198.18.0.0/15", true, false)]
    [InlineData("192.0.2.0/24", false, false)]
    [InlineData("203.0.113.0/24", false, false)]
    [InlineData("192.0.0.0/24", false, false)]
    [InlineData("95.31.18.0/24", false, true)]
    [InlineData("192.168.1.0/24", true, false)]
    public void ReservedOnLink_IsPrivateOrNotWarned(string prefix, bool privateOnLink, bool warned)
    {
        var cidr = Ipv4Cidr.Parse(prefix);
        Assert.Equal(privateOnLink, PolicyCompiler.IsPrivateOnLink(cidr));
        Assert.Equal(warned, PolicyCompiler.IsPublicOnLink(cidr));
        Assert.Equal(warned, PrimaryAdapterSelector.PublicOnLinkConflicts([Adapter("Clash", prefix)]).Any());
        Assert.Equal(privateOnLink, PolicyCompiler.SelectOnLinkPrefixes([Adapter("Clash", prefix)], _ => AdapterTrust.None).Local.Contains(cidr));
    }

    /// <summary>П.9: адреса fake-IP (198.18.0.0/15) закрепляются по домену с любой целью; документационные - нет.</summary>
    [Theory]
    [InlineData("198.18.0.5", true, true)]
    [InlineData("198.19.255.1", false, true)]
    [InlineData("198.51.100.7", true, false)]
    [InlineData("192.0.2.7", false, false)]
    public void FakeIpPool_IsPinnable(string address, bool direct, bool accepted)
    {
        var host = Ipv4.Parse(address);
        var target = direct ? RouteTarget.Direct : RouteTarget.Tunnel(TunnelB);
        var inputs = Inputs(Tunnel, SecondTunnel, [new PinnedHost(host, target)]);

        Assert.Equal(accepted, inputs.Policy.Pins.Count == 1);
        if (accepted)
        {
            Assert.Equal(direct ? Decision.Direct : Decision.Vpn, inputs.Policy.Classify(host).Decision);
        }
        else
        {
            Assert.Contains("зарезервированного", Assert.Single(inputs.Policy.RejectedPins).Reason, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Закрепление, которое не меняет решения (сеть шлюза AnyConnect той же цели), принимается: имя корпоративного домена
    /// за своим шлюзом не получает отказа, а при лежащем шлюзе адрес блокируется.
    /// </summary>
    [Fact]
    public void Pin_SameTargetAsGatewayNetwork_IsAccepted()
    {
        var host = Ipv4.Parse("10.20.0.5");
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(TunnelA),
            ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(AnyConnectTunnel), [Ipv4Cidr.Parse("10.20.0.0/16")])],
            PinnedHosts = [new PinnedHost(host, RouteTarget.Tunnel(AnyConnectTunnel))],
        });

        Assert.Single(policy.Pins);
        Assert.Empty(policy.RejectedPins);
        Assert.Equal(AnyConnectTunnel, policy.Classify(host).Tunnel);
    }

    /// <summary>Отказ по запрету пользователя и сети шлюза другой цели остаётся (с причиной для предупреждения).</summary>
    [Fact]
    public void EvaluatePin_MatchesCompiledDecision()
    {
        var inputs = Inputs(Tunnel, SecondTunnel);
        Assert.Equal((true, (string?)null), inputs.Policy.EvaluatePin(new PinnedHost(CorpHost, RouteTarget.Tunnel(TunnelB))));
        Assert.Equal((true, (string?)null), inputs.Policy.EvaluatePin(new PinnedHost(SecondNetwork, RouteTarget.Direct)));
        Assert.False(inputs.Policy.EvaluatePin(new PinnedHost(SecondNetwork, RouteTarget.Direct, RoutePriority.Low)).Allowed);
        Assert.Contains("запрещён", inputs.Policy.EvaluatePin(new PinnedHost(BlockedByRule, RouteTarget.Tunnel(TunnelA))).Reason, StringComparison.Ordinal);
        Assert.Equal((false, (string?)null), inputs.Policy.EvaluatePin(new PinnedHost(Server, RouteTarget.Direct)));
    }
}
