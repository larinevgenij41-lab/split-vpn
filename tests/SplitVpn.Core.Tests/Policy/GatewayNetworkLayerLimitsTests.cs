using System.Diagnostics;
using System.Globalization;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

/// <summary>
/// Слой сетей шлюза проверяется целиком: поштучный предел /8 не мешает прислать сотни /8 или десятки
/// тысяч /32. Слой сверх пределов отбрасывается с предупреждением, годный красится одним проходом.
/// </summary>
public sealed class GatewayNetworkLayerLimitsTests
{
    private static readonly Guid Sstp = new("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid Gateway = new("dddddddd-0000-0000-0000-000000000004");

    private static IEnumerable<string> AllPublicEights() => Enumerable.Range(1, 223)
        .Select(i => string.Create(CultureInfo.InvariantCulture, $"{i}.0.0.0/8"));

    [Fact]
    public void Compiler_RejectsLayerCoveringPublicInternet()
    {
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(Sstp),
            ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(Gateway), AllPublicEights().Select(Ipv4Cidr.Parse).ToList())],
        };

        var policy = PolicyCompiler.Compile(input);

        var label = policy.Classify(Ipv4.Parse("8.8.8.8"));
        Assert.NotEqual(DecisionSource.ServerNetwork, label.Source);
        Assert.Equal(Sstp, label.Tunnel);
        Assert.Single(policy.Warnings);
        Assert.Empty(policy.RangesFor(Gateway));
    }

    [Fact]
    public void Compiler_RejectsOnlyOffendingGateway()
    {
        var other = new Guid("eeeeeeee-0000-0000-0000-000000000005");
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(Sstp),
            ServerNetworks =
            [
                new ServerNetworks(RouteTarget.Tunnel(Gateway), AllPublicEights().Select(Ipv4Cidr.Parse).ToList()),
                new ServerNetworks(RouteTarget.Tunnel(other), [Ipv4Cidr.Parse("10.0.0.0/8")]),
            ],
        };

        var policy = PolicyCompiler.Compile(input);

        Assert.Equal(other, policy.Classify(Ipv4.Parse("10.1.2.3")).Tunnel);
        Assert.Equal(Sstp, policy.Classify(Ipv4.Parse("8.8.8.8")).Tunnel);
    }

    [Fact]
    public void Session_RejectsWholeLayerAndExplains()
    {
        var session = new SessionInfo { SplitIncludes = [.. AllPublicEights()] };

        Assert.Empty(session.IncludeCidrs());
        Assert.NotNull(session.RejectedIncludes());
    }

    [Fact]
    public void Session_RejectsTooManyRoutes()
    {
        // Несмежные /32: после свёртки маршрутов столько же, сколько сетей.
        var session = new SessionInfo
        {
            SplitIncludes = [.. Enumerable.Range(0, GatewayNetworkLimits.MaxRoutes + 1).Select(i => Ipv4.Format(0x0B000000u + ((uint)i * 2)))],
        };

        Assert.Empty(session.IncludeCidrs());
        Assert.NotNull(session.RejectedIncludes());
    }

    [Fact]
    public void Session_KeepsOrdinaryLayer()
    {
        var session = new SessionInfo { SplitIncludes = ["10.0.0.0/8", "172.16.0.0/12", "162.159.0.0/16"] };

        Assert.Equal(3, session.IncludeCidrs().Count);
        Assert.Null(session.RejectedIncludes());
    }

    /// <summary>Сеть шире /8 отбрасывается поштучно и не делает «отброшенным целиком» остальной слой.</summary>
    [Fact]
    public void Session_TooWideNetworkDroppedAlone_LayerNotReportedRejected()
    {
        var session = new SessionInfo { SplitIncludes = ["0.0.0.0/1", "10.0.0.0/8"] };

        Assert.Equal([Ipv4Cidr.Parse("10.0.0.0/8")], session.IncludeCidrs());
        Assert.Null(session.RejectedIncludes());
        Assert.Single(session.TooWideIncludes());
    }

    [Fact]
    public void Compiler_ManyHostRoutesOverLargeGeo_BuildsQuickly()
    {
        // RU-база из 20 тыс. несмежных диапазонов /24 в 5.0.0.0–...; 50 тыс. /32 шлюза — смежные (свёртка в
        // несколько блоков) и проходят пределы; покраска одним проходом укладывается в доли секунды.
        var geo = RangeSet.From(Enumerable.Range(0, 20_000).Select(i => new Ipv4Range(0x05000000u + ((uint)i << 9), 0x05000000u + ((uint)i << 9) + 255)));
        var hosts = Enumerable.Range(0, 50_000).Select(i => new Ipv4Cidr(0x05000000u + (uint)i, 32)).ToList();
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(Sstp),
            GeoTarget = RouteTarget.Direct,
            Geo = geo,
            ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(Gateway), hosts, UserRulesWin: true)],
        };

        var watch = Stopwatch.StartNew();
        var policy = PolicyCompiler.Compile(input);
        watch.Stop();

        Assert.Empty(policy.Warnings);
        Assert.Equal(Gateway, policy.Classify(0x05000000u + 49_999).Tunnel);
        Assert.Equal(Decision.Direct, policy.Classify(0x05000000u + 0x100000).Decision);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"сборка заняла {watch.Elapsed}");
    }

    [Fact]
    public void Compiler_ManyScatteredHostRoutesOverLargeGeo_RejectedQuickly()
    {
        var geo = RangeSet.From(Enumerable.Range(0, 20_000).Select(i => new Ipv4Range(0x05000000u + ((uint)i << 9), 0x05000000u + ((uint)i << 9) + 255)));
        var hosts = Enumerable.Range(0, 50_000).Select(i => new Ipv4Cidr(0x30000000u + ((uint)i * 3), 32)).ToList();
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(Sstp),
            Geo = geo,
            ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(Gateway), hosts)],
        };

        var watch = Stopwatch.StartNew();
        var policy = PolicyCompiler.Compile(input);
        watch.Stop();

        Assert.Single(policy.Warnings);
        Assert.NotEqual(DecisionSource.ServerNetwork, policy.Classify(0x30000000u).Source);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"сборка заняла {watch.Elapsed}");
    }

    /// <summary>Покраска множествами сохраняет прежний порядок: узкая сеть другого шлюза важнее широкой.</summary>
    [Fact]
    public void Compiler_NarrowerNetworkOfAnotherGatewayWins()
    {
        var other = new Guid("eeeeeeee-0000-0000-0000-000000000005");
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(Sstp),
            ServerNetworks =
            [
                new ServerNetworks(RouteTarget.Tunnel(Gateway), [Ipv4Cidr.Parse("10.1.0.0/16"), Ipv4Cidr.Parse("10.3.0.0/16")]),
                new ServerNetworks(RouteTarget.Tunnel(other), [Ipv4Cidr.Parse("10.0.0.0/8"), Ipv4Cidr.Parse("10.3.3.0/24")]),
            ],
            Rules = [new UserRule(Ipv4Cidr.Parse("10.1.5.0/24"), RouteTarget.Blocked)],
        };

        var policy = PolicyCompiler.Compile(input);

        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("10.1.2.3")).Tunnel);
        Assert.Equal(Decision.Block, policy.Classify(Ipv4.Parse("10.1.5.1")).Decision);
        Assert.Equal(other, policy.Classify(Ipv4.Parse("10.2.2.3")).Tunnel);
        Assert.Equal(other, policy.Classify(Ipv4.Parse("10.3.3.3")).Tunnel);
        Assert.Equal(Gateway, policy.Classify(Ipv4.Parse("10.3.4.3")).Tunnel);
    }
}
