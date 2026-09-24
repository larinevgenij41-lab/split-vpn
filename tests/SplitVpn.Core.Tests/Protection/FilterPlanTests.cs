using System.Net;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>
/// Проверка схемы весов на модели арбитража WFP внутри одного sublayer: срабатывает совпавший фильтр
/// с наибольшим весом, при равенстве Block сильнее Permit.
/// </summary>
public class FilterPlanTests
{
    private const ulong WiFi = 8;
    private const ulong Radmin = 19;
    private const ulong Tunnel = 77;
    private const ulong SecondTunnel = 78;
    private const string ServiceExe = @"C:\Program Files\SplitVpn\SplitVpn.Service.exe";

    private static readonly uint Server = Ipv4.Parse("203.0.113.20");
    private static readonly uint RouterDns = Ipv4.Parse("192.168.1.1");
    private static readonly uint Yandex = Ipv4.Parse("77.88.55.242");
    private static readonly uint Cloudflare = Ipv4.Parse("1.1.1.1");
    private static readonly uint BlockedByRule = Ipv4.Parse("45.10.0.1");
    private static readonly uint SecondServer = Ipv4.Parse("203.0.113.200");
    private static readonly uint SecondNetwork = Ipv4.Parse("13.107.1.1");
    private static readonly uint RemoteLan = Ipv4.Parse("192.168.100.209");

    [Theory]
    [InlineData(VpnProtocol.L2tpIpsec, 17, 500, true)]
    [InlineData(VpnProtocol.L2tpIpsec, 17, 4500, true)]
    [InlineData(VpnProtocol.L2tpIpsec, 17, 1701, true)]
    [InlineData(VpnProtocol.Ikev2, 17, 1701, false)]
    [InlineData(VpnProtocol.Ikev2, 50, 0, true)]
    [InlineData(VpnProtocol.Ikev2, 6, 443, false)]
    [InlineData(VpnProtocol.Pptp, 6, 1723, true)]
    [InlineData(VpnProtocol.Pptp, 47, 0, true)]
    [InlineData(VpnProtocol.Pptp, 17, 4500, false)]
    [InlineData(VpnProtocol.AnyConnect, 6, 443, true)]
    [InlineData(VpnProtocol.AnyConnect, 17, 443, true)]
    [InlineData(VpnProtocol.AnyConnect, 17, 500, false)]
    [InlineData(VpnProtocol.AnyConnect, 50, 0, false)]
    public void TransportExceptionsAreLimitedToServerAndPrimary(VpnProtocol protocol, byte ipProtocol, ushort port, bool allowed)
    {
        var baseline = Inputs(tunnel: null);
        var filters = All(baseline with { Tunnels = [.. baseline.Tunnels.Select(t => t.ServesDefault ? t with { Protocol = protocol } : t)] });
        Assert.Equal(allowed ? FilterAction.Permit : FilterAction.Block, Evaluate(filters, Packet.V4(Server, ipProtocol, port, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.V4(Server, ipProtocol, port, Radmin)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.V4(Cloudflare, ipProtocol, port, WiFi)));
    }

    [Fact]
    public void Connected_SplitsTrafficWithoutLeaks()
    {
        var filters = All(Inputs(tunnel: Tunnel));

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Yandex, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(Yandex, 53, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Udp(Cloudflare, 53, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(BlockedByRule, 443, Tunnel)));
    }

    [Fact]
    public void LocalNetworks_FollowLocalAccessSetting()
    {
        var on = All(Inputs(tunnel: Tunnel));
        var off = All(Inputs(tunnel: Tunnel) with { LocalAccess = false });

        Assert.Equal(FilterAction.Permit, Evaluate(on, Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(on, Tcp(Ipv4.Parse("26.1.2.3"), 80, Radmin)));
        Assert.Equal(FilterAction.Block, Evaluate(off, Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(off, Tcp(Ipv4.Parse("26.1.2.3"), 80, Radmin)));
        Assert.Equal(FilterAction.Permit, Evaluate(off, Packet.Dhcp(WiFi)));
    }

    [Fact]
    public void OtherInterfaceWithDefaultRoute_CannotCarryDirectOrVpnTraffic()
    {
        var filters = All(Inputs(tunnel: null));

        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Yandex, 443, Radmin)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 443, Radmin)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Server, 443, Radmin)));
    }

    [Fact]
    public void Outage_BlockVpnTraffic_KeepsRussiaAndServerTransport()
    {
        var filters = All(Inputs(tunnel: null));

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Yandex, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Server, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Udp(RouterDns, 53, WiFi, ServiceExe, system: true)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(RouterDns, 53, WiFi, @"C:\Windows\explorer.exe", system: false)));
    }

    [Fact]
    public void Outage_BlockAllPublic_BlocksRussiaButNotLocalOrServer()
    {
        var filters = All(Inputs(tunnel: null) with { OutageMode = OutageMode.BlockAllPublic });

        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Yandex, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Server, 443, WiFi)));
    }

    [Fact]
    public void Outage_AllowAll_OpensTrafficButKeepsDnsGuard_AndNotForManualDisconnect()
    {
        var outage = All(Inputs(tunnel: null) with { OutageMode = OutageMode.AllowAll });
        var manual = All(Inputs(tunnel: null) with { OutageMode = OutageMode.AllowAll, Intent = Intent.Protected });

        Assert.Equal(FilterAction.Permit, Evaluate(outage, Tcp(Cloudflare, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(outage, Udp(Yandex, 53, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(manual, Tcp(Cloudflare, 443, WiFi)));
    }

    [Fact]
    public void Ipv6_PublicBlocked_LinkLocalAndNdAllowed()
    {
        var filters = All(Inputs(tunnel: Tunnel));

        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.V6("2a00:1450:4001::1", 6, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Packet.V6("fe80::1", 6, 445, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Packet.V6("ff02::1", FilterPlanBuilder.ProtocolIcmpV6, 0, WiFi, localPort: 135)));
    }

    [Fact]
    public void AfterReboot_OnlyBaseRemains_AndIsStricter()
    {
        var filters = FilterPlanBuilder.BuildBase(Inputs(tunnel: null));

        Assert.All(filters, f => Assert.Equal(FilterGroup.Base, f.Group));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Yandex, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Server, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Packet.Loopback()));
    }

    [Fact]
    public void Groups_AreSeparatedByLifetime()
    {
        var inputs = Inputs(tunnel: Tunnel);

        Assert.DoesNotContain(FilterPlanBuilder.BuildBase(inputs), f => f.Conditions.OfType<LocalInterfaceCondition>().Any());
        Assert.All(FilterPlanBuilder.BuildDirect(inputs), f => Assert.Equal(FilterPlanBuilder.WeightDirect, f.Weight));
        Assert.Contains(FilterPlanBuilder.BuildRuntime(inputs), f => f.Weight == FilterPlanBuilder.WeightTunnel);
    }

    private static readonly Guid TunnelA = new("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid TunnelB = new("bbbbbbbb-0000-0000-0000-000000000002");
    private static readonly Guid GroupAb = new("cccccccc-0000-0000-0000-000000000003");

    private static ProtectionInputs Inputs(ulong? tunnel) => Inputs(tunnel, null);

    /// <summary>Основной туннель несёт «остальной интернет»; второй, если задан, — сеть 13.107.0.0/16.</summary>
    private static ProtectionInputs Inputs(
        ulong? tunnel,
        ulong? second,
        IReadOnlyList<PinnedHost>? pins = null,
        IReadOnlyList<Guid>? group = null)
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            PinnedHosts = pins ?? [],
            Groups = group is null ? [] : [new TunnelGroup(GroupAb, group)],
            DefaultTarget = RouteTarget.Tunnel(TunnelA),
            Geo = RangeSet.From(new[] { Ipv4Cidr.Parse("77.88.0.0/18") }),
            Rules =
            [
                new UserRule(Ipv4Cidr.Parse("45.10.0.0/16"), RouteTarget.Blocked),
                new UserRule(Ipv4Cidr.Parse("13.107.0.0/16"), RouteTarget.Tunnel(TunnelB)),
                new UserRule(Ipv4Cidr.Parse("192.168.100.0/24"), RouteTarget.Tunnel(TunnelB)),
            ],
            ServerAddresses = [Server],
            ServiceDnsAddresses = [RouterDns],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24"), Ipv4Cidr.Parse("26.0.0.0/8")],
        });
        return new ProtectionInputs
        {
            Policy = policy,
            PrimaryLuid = WiFi,
            Tunnels =
            [
                new TunnelInput { Id = TunnelA, Name = "Основной", Luid = tunnel, ServerAddresses = [Server], ServesDefault = true },
                new TunnelInput { Id = TunnelB, Name = "Второй", Luid = second, ServerAddresses = [SecondServer] },
            ],
            ServiceDnsAddresses = [RouterDns],
            ServiceExecutablePath = ServiceExe,
            OnLinkPrefixes = [Ipv4Cidr.Parse("192.168.1.0/24"), Ipv4Cidr.Parse("26.0.0.0/8")],
        };
    }

    [Fact]
    public void SecondTunnel_Up_CarriesOnlyItsOwnNetworks()
    {
        var filters = All(Inputs(Tunnel, SecondTunnel));

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(SecondNetwork, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, Tunnel)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(SecondServer, 443, WiFi)));
    }

    [Fact]
    public void SecondTunnel_Down_BlocksItsNetworks_InsteadOfLeakingIntoMainTunnel()
    {
        var filters = All(Inputs(Tunnel, second: null));

        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, Tunnel)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(SecondServer, 443, WiFi)));
    }

    [Fact]
    public void PrivateNetworkRule_GoesOnlyThroughItsTunnel()
    {
        var up = All(Inputs(Tunnel, SecondTunnel));
        Assert.Equal(FilterAction.Permit, Evaluate(up, Tcp(RemoteLan, 3389, SecondTunnel)));

        // Туннель сети лежит: «Локальный доступ» не должен выпустить её адреса ни в Wi-Fi, ни в основной туннель.
        var down = All(Inputs(Tunnel, second: null));
        Assert.Equal(FilterAction.Block, Evaluate(down, Tcp(RemoteLan, 3389, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(down, Tcp(RemoteLan, 3389, Tunnel)));
        Assert.Equal(FilterAction.Permit, Evaluate(down, Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
    }

    [Fact]
    public void DomainRules_PinDirectHostsAndBlockOthers()
    {
        var inputs = Inputs(Tunnel, SecondTunnel, pins:
        [
            new PinnedHost(Cloudflare, RouteTarget.Direct),
            new PinnedHost(Ipv4.Parse("203.0.113.5"), RouteTarget.Blocked),
        ]);
        var filters = All(inputs);

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Ipv4.Parse("203.0.113.5"), 443, Tunnel)));
        Assert.All(FilterPlanBuilder.BuildDynamic(inputs), f => Assert.Equal(FilterGroup.Dynamic, f.Group));
    }

    [Fact]
    public void DomainRule_IntoUnavailableTunnel_BlocksInsteadOfLeakingDirectly()
    {
        var host = Ipv4.Parse("203.0.113.77");
        var filters = All(Inputs(Tunnel, second: null, pins: [new PinnedHost(host, RouteTarget.Tunnel(TunnelB))]));

        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(host, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(host, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(host, 443, Radmin)));
    }

    [Fact]
    public void DomainRule_IntoAvailableTunnel_LeavesOnlyThroughThatTunnel()
    {
        var host = Ipv4.Parse("203.0.113.77");
        var filters = All(Inputs(Tunnel, SecondTunnel, pins: [new PinnedHost(host, RouteTarget.Tunnel(TunnelB))]));

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(host, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(host, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(host, 443, Tunnel)));
    }

    [Fact]
    public void DomainRule_IntoGroup_FollowsItsLiveMember_AndBlocksWhenGroupIsDown()
    {
        var host = Ipv4.Parse("203.0.113.77");
        var live = Inputs(Tunnel, SecondTunnel, pins: [new PinnedHost(host, RouteTarget.Group(GroupAb))], group: [TunnelB]);
        var down = Inputs(Tunnel, second: null, pins: [new PinnedHost(host, RouteTarget.Group(GroupAb))], group: []);

        Assert.Equal(RouteTarget.Tunnel(TunnelB), Assert.Single(live.Policy.Pins).Target);
        Assert.Equal(FilterAction.Permit, Evaluate(All(live), Tcp(host, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(All(live), Tcp(host, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(All(down), Tcp(host, 443, WiFi)));
    }

    [Fact]
    public void DomainRule_DoesNotPinServerOrServiceDnsAddresses()
    {
        var inputs = Inputs(Tunnel, SecondTunnel, pins:
        [
            new PinnedHost(Server, RouteTarget.Tunnel(TunnelB)),
            new PinnedHost(RouterDns, RouteTarget.Tunnel(TunnelB)),
        ]);

        Assert.Empty(inputs.Policy.Pins);
        Assert.Equal(FilterAction.Permit, Evaluate(All(inputs), Tcp(Server, 443, WiFi)));
    }

    [Fact]
    public void Outage_IsDrivenByTunnelThatCarriesTheRestOfInternet()
    {
        Assert.True(FilterPlanBuilder.IsOutage(Inputs(tunnel: null, second: SecondTunnel)));
        Assert.False(FilterPlanBuilder.IsOutage(Inputs(tunnel: Tunnel, second: null)));
    }

    private static List<FilterSpec> All(ProtectionInputs inputs) =>
        [
            .. FilterPlanBuilder.BuildBase(inputs),
            .. FilterPlanBuilder.BuildRuntime(inputs),
            .. FilterPlanBuilder.BuildDynamic(inputs),
            .. FilterPlanBuilder.BuildDirect(inputs),
        ];

    private static Packet Tcp(uint remote, ushort port, ulong luid) => Packet.V4(remote, FilterPlanBuilder.ProtocolTcp, port, luid);

    private static Packet Udp(uint remote, ushort port, ulong luid, string app = @"C:\app.exe", bool system = false) =>
        Packet.V4(remote, FilterPlanBuilder.ProtocolUdp, port, luid) with { AppPath = app, IsSystem = system };

    private static FilterAction Evaluate(IEnumerable<FilterSpec> filters, Packet packet)
    {
        var matched = filters
            .Where(f => FamilyMatches(f.Family, packet.IsV6) && f.Conditions.All(c => Matches(c, packet)))
            .OrderByDescending(f => f.Weight)
            .ThenByDescending(f => f.Action == FilterAction.Block)
            .FirstOrDefault();
        return matched?.Action ?? FilterAction.Permit;
    }

    private static bool FamilyMatches(FilterFamily family, bool isV6) =>
        family == FilterFamily.Both || (family == FilterFamily.V6) == isV6;

    private static bool Matches(FilterCondition condition, Packet packet) => condition switch
    {
        LoopbackCondition => packet.IsLoopback,
        RemoteRangeV4 r => !packet.IsV6 && packet.RemoteV4 >= r.Start && packet.RemoteV4 <= r.End,
        RemotePrefixV6 p => packet.IsV6 && p.Network.Contains(packet.RemoteV6!),
        RemotePortCondition p => packet.RemotePort == p.Port,
        LocalPortRange p => packet.LocalPort >= p.Low && packet.LocalPort <= p.High,
        ProtocolCondition p => packet.Protocol == p.Protocol,
        LocalInterfaceCondition i => i.NotEqual ? packet.Luid != i.Luid : packet.Luid == i.Luid,
        AppIdCondition a => string.Equals(a.ExecutablePath, packet.AppPath, StringComparison.OrdinalIgnoreCase),
        LocalSystemUserCondition => packet.IsSystem,
        _ => throw new NotSupportedException(condition.GetType().Name),
    };

    private sealed record Packet(bool IsV6, uint RemoteV4, IPAddress? RemoteV6, byte Protocol, ushort RemotePort, ushort LocalPort, ulong Luid)
    {
        public bool IsLoopback { get; init; }

        public string AppPath { get; init; } = @"C:\app.exe";

        public bool IsSystem { get; init; }

        public static Packet V4(uint remote, byte protocol, ushort port, ulong luid) => new(false, remote, null, protocol, port, 50000, luid);

        public static Packet V6(string remote, byte protocol, ushort port, ulong luid, ushort localPort = 50000) =>
            new(true, 0, IPAddress.Parse(remote), protocol, port, localPort, luid);

        public static Packet Dhcp(ulong luid) => new(false, Ipv4.Parse("192.168.1.1"), null, FilterPlanBuilder.ProtocolUdp, 67, 68, luid);

        public static Packet Loopback() => new(false, Ipv4.Parse("127.0.0.1"), null, FilterPlanBuilder.ProtocolTcp, 53, 50000, 1) { IsLoopback = true };
    }
}
