using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

/// <summary>
/// Сети, присланные шлюзом AnyConnect, — недоверенные данные: слишком широкая сеть забрала бы интернет
/// в корпоративный туннель, а запрет пользователя перекрывать нельзя.
/// </summary>
public sealed class GatewayNetworkLimitsTests
{
    private static readonly Guid Sstp = new("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid Gateway = new("dddddddd-0000-0000-0000-000000000004");

    private static PolicyInput Input(params string[] networks) => new()
    {
        DefaultTarget = RouteTarget.Tunnel(Sstp),
        ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(Gateway), networks.Select(Ipv4Cidr.Parse).ToList())],
    };

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("0.0.0.0/1")]
    [InlineData("128.0.0.0/1")]
    [InlineData("2.0.0.0/7")]
    public void Session_DropsNetworksWiderThanEight(string cidr)
    {
        var session = new SessionInfo { SplitIncludes = [cidr, "10.0.0.0/8"] };

        Assert.Equal([Ipv4Cidr.Parse("10.0.0.0/8")], session.IncludeCidrs());
        Assert.Equal([Ipv4Cidr.Parse(cidr)], session.TooWideIncludes());
    }

    [Fact]
    public void Session_KeepsEightAndNarrower()
    {
        var session = new SessionInfo { SplitIncludes = ["10.0.0.0/255.0.0.0", "162.159.0.0/16", "213.180.193.247"] };

        Assert.Equal(
            [Ipv4Cidr.Parse("10.0.0.0/8"), Ipv4Cidr.Parse("162.159.0.0/16"), Ipv4Cidr.Parse("213.180.193.247/32")],
            session.IncludeCidrs());
        Assert.Empty(session.TooWideIncludes());
    }

    [Fact]
    public void Compiler_IgnoresNetworksWiderThanEight()
    {
        var policy = PolicyCompiler.Compile(Input("0.0.0.0/1", "10.0.0.0/8"));

        Assert.Equal(Sstp, policy.Classify(Ipv4.Parse("8.8.8.8")).Tunnel);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("10.1.2.3")).Tunnel);
    }

    [Fact]
    public void Compiler_KeepsUserBlockUnderGatewayNetwork()
    {
        // Шлюз присылает публичную сеть (живой случай: 162.159.0.0/16 Cloudflare), часть которой
        // пользователь запретил: запрет остаётся запретом.
        var input = Input("162.159.0.0/16") with
        {
            Rules = [new UserRule(Ipv4Cidr.Parse("162.159.5.0/24"), RouteTarget.Blocked)],
        };

        var policy = PolicyCompiler.Compile(input);

        var blocked = policy.Classify(Ipv4.Parse("162.159.5.1"));
        Assert.Equal(Decision.Block, blocked.Decision);
        Assert.Equal(DecisionSource.UserRule, blocked.Source);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("162.159.6.1")).Tunnel);
        Assert.DoesNotContain(Ipv4Cidr.Parse("162.159.5.0/24"), policy.RouteCidrsFor(Gateway));
    }

    [Fact]
    public void Compiler_StillOverridesOtherUserRules()
    {
        var input = Input("162.159.0.0/16", "10.0.0.0/8") with
        {
            Rules =
            [
                new UserRule(Ipv4Cidr.Parse("162.159.5.0/24"), RouteTarget.Direct),
                new UserRule(Ipv4Cidr.Parse("162.159.7.0/24"), RouteTarget.Tunnel(Sstp)),
                new UserRule(Ipv4Cidr.Parse("10.5.0.0/16"), RouteTarget.Direct),
            ],
        };

        var policy = PolicyCompiler.Compile(input);

        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("162.159.5.1")).Tunnel);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("162.159.7.1")).Tunnel);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("10.5.1.1")).Tunnel);
    }

    /// <summary>
    /// Внутри диапазонов локальных сетей правило пользователя не действует и без шлюза (слой «Локальные
    /// сети» красится поверх правил, валидатор об этом предупреждает), поэтому и запрет там не сохраняется.
    /// </summary>
    [Fact]
    public void Compiler_DoesNotResurrectUserBlockInsideLocalRanges()
    {
        var input = Input("10.0.0.0/8") with
        {
            Rules = [new UserRule(Ipv4Cidr.Parse("10.5.0.0/16"), RouteTarget.Blocked)],
        };

        Assert.Equal(Gateway, PolicyCompiler.Compile(input).Classify(Ipv4.Parse("10.5.1.1")).Tunnel);
    }
}
