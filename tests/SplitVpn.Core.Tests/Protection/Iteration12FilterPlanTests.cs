using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>
/// Итерация 12: решения ядра политики - какие закрепления по домену принимаются, какие сети адаптеров локальны,
/// метки DNS сети и DNS шлюза, IPv6 в туннеле AnyConnect.
/// </summary>
public partial class FilterPlanTests
{
    private static readonly Guid AnyConnectTunnel = new("eeeeeeee-0000-0000-0000-000000000005");

    [Theory]
    [InlineData("169.254.10.1", null)]
    [InlineData("203.0.113.77", "зарезервированного")]
    [InlineData("192.0.0.9", "зарезервированного")]
    [InlineData("45.10.0.1", "запрещён правилом")]
    public void Pin_DoesNotOverrideStrongerAddressDecision(string address, string? reason)
    {
        var host = Ipv4.Parse(address);
        var inputs = Inputs(Tunnel, SecondTunnel, [new PinnedHost(host, RouteTarget.Tunnel(TunnelB))]);

        Assert.Empty(inputs.Policy.Pins);
        if (reason is null)
        {
            Assert.Empty(inputs.Policy.RejectedPins);
        }
        else
        {
            Assert.Contains(reason, Assert.Single(inputs.Policy.RejectedPins).Reason, StringComparison.Ordinal);
        }

        // Адрес остаётся при адресном решении: не уходит в туннель правила для домена.
        Assert.NotEqual(TunnelB, inputs.Policy.Classify(host).Tunnel);
        Assert.NotEqual(DecisionSource.DomainRule, inputs.Policy.Classify(host).Source);
    }

    [Fact]
    public void Pin_DoesNotOverrideGatewayNetwork()
    {
        var host = Ipv4.Parse("10.20.0.5");
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(TunnelA),
            ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(AnyConnectTunnel), [Ipv4Cidr.Parse("10.20.0.0/16")])],
            PinnedHosts = [new PinnedHost(host, RouteTarget.Tunnel(TunnelB))],
        });

        Assert.Empty(policy.Pins);
        Assert.Contains("шлюза", Assert.Single(policy.RejectedPins).Reason, StringComparison.Ordinal);
        Assert.Equal(AnyConnectTunnel, policy.Classify(host).Tunnel);
    }

    /// <summary>Закрепление в туннель поверх правила «напрямую» или правила в другой туннель допустимо: трафик остаётся в VPN.</summary>
    [Fact]
    public void TunnelPin_OverUserDirectOrOtherTunnelRule_IsAccepted()
    {
        var directRule = Ipv4.Parse("8.8.4.4");
        var inputs = Inputs(Tunnel, SecondTunnel,
            [new PinnedHost(directRule, RouteTarget.Tunnel(TunnelB)), new PinnedHost(SecondNetwork, RouteTarget.Tunnel(TunnelA))],
            extraRules: [new UserRule(Ipv4Cidr.Parse("8.8.4.0/24"), RouteTarget.Direct)]);

        Assert.Equal(2, inputs.Policy.Pins.Count);
        Assert.Empty(inputs.Policy.RejectedPins);
        Assert.Equal(FilterAction.Permit, Evaluate(All(inputs), Tcp(directRule, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(All(inputs), Tcp(directRule, 443, WiFi)));
    }

    [Fact]
    public void OnLinkSelection_PublicPrefixIsLocalOnlyForTrustedAdapter()
    {
        var hotspot = Adapter("Wi-Fi", "149.154.160.0/20", gateway: "149.154.160.1", luid: WiFi);
        var lan = Adapter("Ethernet", "192.168.1.0/24", gateway: "192.168.1.1");
        var cgnat = Adapter("Tailscale", "100.100.0.0/16");
        var radmin = Adapter("Radmin VPN", "26.0.0.0/8");

        var selection = PolicyCompiler.SelectOnLinkPrefixes([hotspot, lan, cgnat, radmin], a => a == radmin ? AdapterTrust.Explicit : AdapterTrust.None);

        // Публичный маршрутизатор точки доступа - не в локальных сетях (они выше правил), а отдельно: ниже правил и закреплений.
        Assert.Equal([Ipv4Cidr.Parse("192.168.1.0/24"), Ipv4Cidr.Parse("100.100.0.0/16"), Ipv4Cidr.Parse("26.0.0.0/8")], selection.Local);
        Assert.Equal([Ipv4Cidr.Parse("149.154.160.0/20")], selection.Untrusted.Select(u => u.Prefix));
        Assert.Equal([new AdapterGateway(Ipv4.Parse("149.154.160.1"), WiFi)], selection.Gateways);

        var trusted = PolicyCompiler.SelectOnLinkPrefixes([hotspot], _ => AdapterTrust.Explicit);
        Assert.Equal([Ipv4Cidr.Parse("149.154.160.0/20")], trusted.Local);
        Assert.Empty(trusted.Untrusted);
        Assert.Empty(trusted.Gateways);
    }

    /// <summary>
    /// Чужая точка доступа с публичной сетью: сеть больше не открыта мимо VPN (защита её блокирует - Windows отдаёт её
    /// интерфейсу Wi-Fi, а политика - туннелю), а маршрутизатор, транспорт VPN, DNS службы и DHCP работают.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PublicOnLinkOfUntrustedAdapter_IsGuardedButGatewayVpnDnsAndDhcpWork(bool connected)
    {
        // Обычная схема провайдера: единственный адаптер с публичным адресом в публичной /24, DNS провайдера в той же сети.
        var isp = Adapter("Ethernet", "95.31.18.0/24", gateway: "95.31.18.1", luid: WiFi);
        var ispDns = Ipv4.Parse("95.31.18.2");
        var server = Ipv4.Parse("5.129.236.106");
        var neighbour = Ipv4.Parse("95.31.18.50");
        var selection = PolicyCompiler.SelectOnLinkPrefixes([isp], _ => AdapterTrust.None);
        var onLink = selection.Local;
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(TunnelA),
            ServerAddresses = [server],
            ServiceDnsAddresses = [ispDns],
            OnLinePrefixes = onLink,
            AdapterGateways = [.. selection.Gateways.Select(g => g.Address)],
        });
        var filters = All(new ProtectionInputs
        {
            Policy = policy,
            PrimaryLuid = WiFi,
            Tunnels = [new TunnelInput { Id = TunnelA, Name = "Основной", Luid = connected ? Tunnel : null, ServerAddresses = [server], ServesDefault = true }],
            ServiceDnsAddresses = [ispDns],
            ServiceExecutablePath = ServiceExe,
            OnLinkPrefixes = onLink,
            AdapterGateways = selection.Gateways,
        });

        Assert.Equal(Decision.Local, policy.Classify(Ipv4.Parse("95.31.18.1")).Decision);
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("95.31.18.1"), 80, WiFi)));
        // Разрешение маршрутизатора привязано к его адаптеру.
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Ipv4.Parse("95.31.18.1"), 80, Radmin)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(server, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Udp(ispDns, 53, WiFi, ServiceExe, system: true)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Packet.Dhcp(WiFi) with { RemoteV4 = Ipv4.Parse("95.31.18.3") }));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Packet.Dhcp(WiFi) with { RemoteV4 = uint.MaxValue }));

        Assert.Equal(Decision.Vpn, policy.Classify(neighbour).Decision);
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(neighbour, 445, WiFi)));
        Assert.Equal(connected ? FilterAction.Permit : FilterAction.Block, Evaluate(filters, Tcp(neighbour, 445, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(ispDns, 53, WiFi)));
    }

    /// <summary>
    /// DNS сети (DHCP) не перекрывает правила пользователя: программы идут по правилу, а служба разрешает имена и под
    /// запретом, и пока туннель правила лежит (её разрешение весит больше блока «Туннель недоступен»).
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ServiceDns_KeepsUserRuleForAppsButServiceStillResolves(bool blocked)
    {
        var dns = blocked ? BlockedByRule : SecondNetwork;
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(TunnelA),
            Rules = [new UserRule(Ipv4Cidr.Parse("45.10.0.0/16"), RouteTarget.Blocked), new UserRule(Ipv4Cidr.Parse("13.107.0.0/16"), RouteTarget.Tunnel(TunnelB))],
            ServerAddresses = [Server],
            ServiceDnsAddresses = [dns],
            PinnedHosts = [new PinnedHost(dns, RouteTarget.Tunnel(TunnelA))],
        });
        var filters = All(new ProtectionInputs
        {
            Policy = policy,
            PrimaryLuid = WiFi,
            Tunnels =
            [
                new TunnelInput { Id = TunnelA, Name = "Основной", Luid = Tunnel, ServerAddresses = [Server], ServesDefault = true },
                new TunnelInput { Id = TunnelB, Name = "Второй", Luid = null, ServerAddresses = [SecondServer] },
            ],
            ServiceDnsAddresses = [dns],
            ServiceExecutablePath = ServiceExe,
        });

        Assert.Equal(DecisionSource.UserRule, policy.Classify(dns).Source);
        Assert.Empty(policy.Pins);
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Udp(dns, 53, WiFi, ServiceExe, system: true)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(dns, 53, Radmin, ServiceExe, system: true)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(dns, 53, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(dns, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(dns, 443, Tunnel)));
    }

    /// <summary>
    /// DNS шлюза при «Ручные правила важнее сетей шлюза» уступает только правилу ровно на свой адрес (/32): широкое
    /// правило (8.8.4.0/24 → «Напрямую») его не забирает, иначе split DNS шлюза пропал бы.
    /// </summary>
    [Theory]
    [InlineData(true, "8.8.4.4/32", true)]
    [InlineData(false, "8.8.4.4/32", false)]
    [InlineData(true, "8.8.4.0/24", false)]
    [InlineData(false, "8.8.4.0/24", false)]
    public void TunnelDns_KeepsOnlyExactUserRuleWhenUserRulesWin(bool userRulesWin, string rule, bool ruleWins)
    {
        var dns = Ipv4.Parse("8.8.4.4");
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(TunnelA),
            Rules = [new UserRule(Ipv4Cidr.Parse(rule), RouteTarget.Direct)],
            TunnelHosts = [new TunnelHost(AnyConnectTunnel, dns, userRulesWin)],
        });

        var label = policy.Classify(dns);
        Assert.Equal(ruleWins ? Decision.Direct : Decision.Vpn, label.Decision);
        Assert.Equal(ruleWins ? DecisionSource.UserRule : DecisionSource.TunnelInfrastructure, label.Source);
    }

    /// <summary>Туннель AnyConnect пропускает только IPv4: IPv6 от шлюза (если отключить его не удалось) блокируется.</summary>
    [Fact]
    public void AnyConnectTunnel_PermitsOnlyIpv4()
    {
        var baseline = Inputs(Tunnel);
        var inputs = baseline with { Tunnels = [.. baseline.Tunnels.Select(t => t.ServesDefault ? t with { Protocol = VpnProtocol.AnyConnect } : t)] };
        var filters = All(inputs);

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.V6("2a00:1450:4001::1", 6, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.V6("fd00::1", 6, 443, Tunnel)));

        // Другие протоколы не меняются.
        Assert.Contains(FilterPlanBuilder.BuildRuntime(baseline), f => f.Name == "Туннель «Основной»" && f.Family == FilterFamily.Both);
    }

    private static AdapterCandidate Adapter(string name, string prefix, string? gateway = null, ulong luid = 0, string description = "") => new()
    {
        InterfaceGuid = Guid.NewGuid(),
        Luid = luid,
        Name = name,
        Description = description,
        IsUp = true,
        OnLinkPrefixes = [Ipv4Cidr.Parse(prefix)],
        DefaultGateway = gateway is null ? null : Ipv4.Parse(gateway),
    };
}
