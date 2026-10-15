using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

public sealed class ServerNetworksPolicyTests
{
    private static readonly Guid Sstp = new("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid Gateway = new("dddddddd-0000-0000-0000-000000000004");
    private static readonly uint SstpServer = Ipv4.Parse("203.0.113.10");
    private static readonly uint SstpDnsInPrivateRange = Ipv4.Parse("10.8.0.1");
    private static readonly uint GatewayDns = Ipv4.Parse("10.0.16.21");

    private static PolicyInput Input(params string[] networks) => Input(true, networks);

    private static PolicyInput Input(bool userRulesWin, params string[] networks) => new()
    {
        DefaultTarget = RouteTarget.Tunnel(Sstp),
        ServerAddresses = [SstpServer],
        ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(Gateway), networks.Select(Ipv4Cidr.Parse).ToList(), userRulesWin)],
    };

    [Fact]
    public void WithoutServerNetworks_PrivateRangeStaysLocal()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput { DefaultTarget = RouteTarget.Tunnel(Sstp) });

        Assert.Equal(Decision.Local, policy.Classify(Ipv4.Parse("10.1.2.3")).Decision);
    }

    [Fact]
    public void ServerNetworks_OverridePrivateRangeAndGoToGatewayTunnel()
    {
        var policy = PolicyCompiler.Compile(Input("10.0.0.0/8", "213.180.193.247/32"));

        var privateHost = policy.Classify(Ipv4.Parse("10.1.2.3"));
        Assert.Equal(Decision.Vpn, privateHost.Decision);
        Assert.Equal(Gateway, privateHost.Tunnel);
        Assert.Equal(DecisionSource.ServerNetwork, privateHost.Source);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("213.180.193.247")).Tunnel);
        Assert.Equal(Sstp, policy.Classify(Ipv4.Parse("213.180.193.248")).Tunnel);
        Assert.Contains(Ipv4Cidr.Parse("10.0.0.0/8"), policy.RouteCidrsFor(Gateway));
    }

    [Fact]
    public void UserRulesFlagOff_ServerNetworksOverrideUserRulesButNotOnLinkLoopbackOrServers()
    {
        var input = Input(false, "10.0.0.0/8", "192.168.0.0/16", "203.0.113.10/32") with
        {
            Rules = [new UserRule(Ipv4Cidr.Parse("10.5.0.0/16"), RouteTarget.Direct)],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
        };

        var policy = PolicyCompiler.Compile(input);

        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("10.5.1.1")).Tunnel);
        Assert.Equal(DecisionSource.OnLink, policy.Classify(Ipv4.Parse("192.168.1.10")).Source);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("192.168.2.10")).Tunnel);
        Assert.Equal(DecisionSource.Server, policy.Classify(SstpServer).Source);
        Assert.Equal(Decision.Local, policy.Classify(Ipv4.Parse("127.0.0.1")).Decision);
    }

    [Fact]
    public void UserRules_WinOverServerNetworksButNotOverOnLinkLoopbackOrServers()
    {
        var input = Input("10.0.0.0/8", "192.168.0.0/16", "203.0.113.10/32") with
        {
            Rules =
            [
                new UserRule(Ipv4Cidr.Parse("10.100.5.0/24"), RouteTarget.Tunnel(Sstp)),
                new UserRule(Ipv4Cidr.Parse("192.168.0.0/16"), RouteTarget.Direct),
            ],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
        };

        var policy = PolicyCompiler.Compile(input);

        var manual = policy.Classify(Ipv4.Parse("10.100.5.11"));
        Assert.Equal(Sstp, manual.Tunnel);
        Assert.Equal(DecisionSource.UserRule, manual.Source);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("10.100.6.1")).Tunnel);
        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("192.168.2.10")).Decision);
        Assert.Equal(DecisionSource.OnLink, policy.Classify(Ipv4.Parse("192.168.1.10")).Source);
        Assert.Equal(DecisionSource.Server, policy.Classify(SstpServer).Source);
        Assert.Equal(Decision.Local, policy.Classify(Ipv4.Parse("127.0.0.1")).Decision);
        Assert.DoesNotContain(policy.RouteCidrsFor(Gateway), c => c.Contains(Ipv4.Parse("10.100.5.11")));
    }

    /// <summary>Широкое ручное правило сильнее и более узкой сети шлюза внутри него: длина префикса не важна.</summary>
    [Fact]
    public void WideUserRule_WinsOverNarrowerServerNetwork()
    {
        var input = Input("10.100.5.0/26") with
        {
            Rules = [new UserRule(Ipv4Cidr.Parse("10.100.0.0/16"), RouteTarget.Tunnel(Sstp))],
        };

        var policy = PolicyCompiler.Compile(input);

        Assert.Equal(Sstp, policy.Classify(Ipv4.Parse("10.100.5.11")).Tunnel);
        Assert.Empty(policy.RouteCidrsFor(Gateway));
    }

    [Fact]
    public void UserRules_DoNotWinOverTunnelHosts()
    {
        var input = Input("10.0.0.0/8") with
        {
            Rules = [new UserRule(Ipv4Cidr.Parse("10.0.16.0/24"), RouteTarget.Direct)],
            TunnelHosts = [new TunnelHost(Gateway, GatewayDns)],
        };

        var policy = PolicyCompiler.Compile(input);

        Assert.Equal(DecisionSource.TunnelInfrastructure, policy.Classify(GatewayDns).Source);
        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("10.0.16.22")).Decision);
    }

    [Fact]
    public void TunnelHosts_KeepOtherTunnelDnsOutOfGatewayNetworks()
    {
        var input = Input("10.0.0.0/8") with
        {
            TunnelHosts = [new TunnelHost(Sstp, SstpDnsInPrivateRange), new TunnelHost(Gateway, GatewayDns)],
        };

        var policy = PolicyCompiler.Compile(input);

        var sstpDns = policy.Classify(SstpDnsInPrivateRange);
        Assert.Equal(Sstp, sstpDns.Tunnel);
        Assert.Equal(DecisionSource.TunnelInfrastructure, sstpDns.Source);
        Assert.Equal(Gateway, policy.Classify(GatewayDns).Tunnel);
    }

    [Fact]
    public void ServerNetworks_MovedToDirect_GoDirect()
    {
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(Sstp),
            ServerNetworks = [new ServerNetworks(RouteTarget.Direct, [Ipv4Cidr.Parse("10.0.0.0/8")])],
        };

        Assert.Equal(Decision.Direct, PolicyCompiler.Compile(input).Classify(Ipv4.Parse("10.1.1.1")).Decision);
    }

    [Fact]
    public void NarrowerServerNetworkWinsOverWiderOne()
    {
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Direct,
            ServerNetworks =
            [
                new ServerNetworks(RouteTarget.Direct, [Ipv4Cidr.Parse("10.10.0.0/16")]),
                new ServerNetworks(RouteTarget.Tunnel(Gateway), [Ipv4Cidr.Parse("10.0.0.0/8")]),
            ],
        };

        var policy = PolicyCompiler.Compile(input);

        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("10.10.1.1")).Decision);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("10.11.1.1")).Tunnel);
    }
}
