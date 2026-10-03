using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

public class PolicyCompilerTests
{
    private static readonly uint Server = Ipv4.Parse("203.0.113.20");
    private static readonly Guid TunnelA = new("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid TunnelB = new("bbbbbbbb-0000-0000-0000-000000000002");
    private static readonly Guid GroupId = new("cccccccc-0000-0000-0000-000000000003");
    private static readonly RouteTarget ToA = RouteTarget.Tunnel(TunnelA);
    private static readonly RouteTarget ToB = RouteTarget.Tunnel(TunnelB);

    [Fact]
    public void GeoAddress_GoesDirect_OtherPublic_GoesVpn()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput { DefaultTarget = ToA, Geo = Set("77.88.0.0/18") });

        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("77.88.8.8")).Decision);
        Assert.Equal(DecisionSource.Geo, policy.Classify(Ipv4.Parse("77.88.8.8")).Source);
        Assert.Equal(Decision.Vpn, policy.Classify(Ipv4.Parse("8.8.8.8")).Decision);
        Assert.Equal(TunnelA, policy.Classify(Ipv4.Parse("8.8.8.8")).Tunnel);
        Assert.Equal(DecisionSource.Default, policy.Classify(Ipv4.Parse("8.8.8.8")).Source);
    }

    [Fact]
    public void BroadVpnRule_RemovesNestedGeoNetworks_AndNestedDirectRuleWins()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            Geo = Set("77.88.0.0/18"),
            Rules =
            [
                new UserRule(Ipv4Cidr.Parse("77.0.0.0/8"), ToA),
                new UserRule(Ipv4Cidr.Parse("77.88.8.0/24"), RouteTarget.Direct),
            ],
        });

        Assert.Equal(Decision.Vpn, policy.Classify(Ipv4.Parse("77.88.1.1")).Decision);
        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("77.88.8.8")).Decision);
        Assert.Equal(RangeSet.From(new[] { Ipv4Cidr.Parse("77.88.8.0/24") }).ToArray(), policy.DirectRanges.ToArray());
    }

    [Fact]
    public void AllViaVpn_IgnoresGeo_ButKeepsManualDirect()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            GeoTarget = ToA,
            Geo = Set("77.88.0.0/18"),
            Rules = [new UserRule(Ipv4Cidr.Parse("5.255.255.0/24"), RouteTarget.Direct)],
        });

        Assert.Equal(Decision.Vpn, policy.Classify(Ipv4.Parse("77.88.8.8")).Decision);
        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("5.255.255.5")).Decision);
    }

    [Fact]
    public void SecondTunnel_GetsOnlyItsOwnNetworks()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            Rules = [new UserRule(Ipv4Cidr.Parse("13.107.0.0/16"), ToB)],
        });

        Assert.Equal(TunnelB, policy.Classify(Ipv4.Parse("13.107.1.1")).Tunnel);
        Assert.Equal(TunnelA, policy.Classify(Ipv4.Parse("8.8.8.8")).Tunnel);
        Assert.Equal(RangeSet.From(new[] { Ipv4Cidr.Parse("13.107.0.0/16") }).ToArray(), policy.RangesFor(TunnelB).ToArray());
        Assert.Equal([Ipv4Cidr.Parse("13.107.0.0/16")], policy.RouteCidrsFor(TunnelB));
        Assert.Equal([TunnelA, TunnelB], policy.Tunnels.Order().ToArray());
    }

    [Fact]
    public void Group_SplitsAddressSpaceBetweenMembers()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Group(GroupId),
            Groups = [new TunnelGroup(GroupId, [TunnelA, TunnelB])],
        });

        // Блок /8 достаётся участнику по остатку от деления номера блока.
        Assert.Equal(TunnelA, policy.Classify(Ipv4.Parse("8.8.8.8")).Tunnel);
        Assert.Equal(TunnelB, policy.Classify(Ipv4.Parse("9.9.9.9")).Tunnel);
        Assert.Equal(TunnelA, policy.Classify(Ipv4.Parse("104.1.1.1")).Tunnel);
        Assert.Equal(TunnelB, policy.Classify(Ipv4.Parse("13.107.1.1")).Tunnel);
        Assert.NotEmpty(policy.RangesFor(TunnelA));
        Assert.NotEmpty(policy.RangesFor(TunnelB));
        Assert.Empty(policy.RangesFor(GroupId));
    }

    [Fact]
    public void Group_WithSingleAvailableMember_GivesItEverything()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Group(GroupId),
            Groups = [new TunnelGroup(GroupId, [TunnelB])],
        });

        Assert.Equal(TunnelB, policy.Classify(Ipv4.Parse("8.8.8.8")).Tunnel);
        Assert.Equal(TunnelB, policy.Classify(Ipv4.Parse("9.9.9.9")).Tunnel);
        Assert.Empty(policy.RangesFor(TunnelA));
    }

    [Fact]
    public void Group_WithoutAvailableMembers_KeepsGroupId()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            Rules = [new UserRule(Ipv4Cidr.Parse("13.107.0.0/16"), RouteTarget.Group(GroupId))],
            Groups = [new TunnelGroup(GroupId, [])],
        });

        Assert.Equal(GroupId, policy.Classify(Ipv4.Parse("13.107.1.1")).Tunnel);
        Assert.Equal(RangeSet.From(new[] { Ipv4Cidr.Parse("13.107.0.0/16") }).ToArray(), policy.RangesFor(GroupId).ToArray());
    }

    [Fact]
    public void ServerAndAdapterNetwork_OverrideUserBlock()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            Rules =
            [
                new UserRule(Ipv4Cidr.Parse("89.0.0.0/8"), RouteTarget.Blocked),
                new UserRule(Ipv4Cidr.Parse("192.168.0.0/16"), RouteTarget.Blocked),
            ],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
            ServerAddresses = [Server],
        });

        Assert.Equal(Decision.Server, policy.Classify(Server).Decision);
        Assert.Equal(new Classification(Decision.Local, DecisionSource.OnLink, null), policy.Classify(Ipv4.Parse("192.168.1.1")));
        Assert.Equal(Decision.Block, policy.Classify(Ipv4.Parse("192.168.5.5")).Decision);
        Assert.False(policy.BlockRanges.Contains(Server));
        Assert.False(policy.BlockRanges.Contains(Ipv4.Parse("192.168.1.1")));
        Assert.True(policy.BlockRanges.Contains(Ipv4.Parse("89.1.1.1")));
    }

    [Fact]
    public void PrivateNetworkRule_SendsRemoteLanIntoItsTunnel()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            Rules = [new UserRule(Ipv4Cidr.Parse("192.168.100.0/24"), ToB)],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
        });

        var remote = policy.Classify(Ipv4.Parse("192.168.100.209"));
        Assert.Equal((Decision.Vpn, DecisionSource.UserRule, TunnelB), (remote.Decision, remote.Source, remote.Tunnel));
        Assert.Equal([Ipv4Cidr.Parse("192.168.100.0/24")], policy.RouteCidrsFor(TunnelB));
        Assert.Equal(DecisionSource.OnLink, policy.Classify(Ipv4.Parse("192.168.1.5")).Source);
        Assert.Equal(DecisionSource.LocalNetwork, policy.Classify(Ipv4.Parse("192.168.2.1")).Source);
        Assert.Equal(DecisionSource.LocalNetwork, policy.Classify(Ipv4.Parse("10.1.2.3")).Source);
    }

    [Fact]
    public void PrivateNetworkRule_DoesNotTakeAdapterNetwork()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            Rules = [new UserRule(Ipv4Cidr.Parse("192.168.0.0/16"), ToB)],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
        });

        Assert.Equal(DecisionSource.OnLink, policy.Classify(Ipv4.Parse("192.168.1.5")).Source);
        Assert.Equal(TunnelB, policy.Classify(Ipv4.Parse("192.168.2.1")).Tunnel);
        Assert.False(policy.RangesFor(TunnelB).Overlaps(Ipv4Cidr.Parse("192.168.1.0/24").ToRange()));
    }

    [Fact]
    public void PrivateNetworkRule_Direct_GetsDirectRoute()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            Rules = [new UserRule(Ipv4Cidr.Parse("10.20.0.0/16"), RouteTarget.Direct)],
        });

        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("10.20.1.1")).Decision);
        Assert.Equal([Ipv4Cidr.Parse("10.20.0.0/16")], policy.DirectRouteCidrs);
    }

    [Theory]
    [InlineData("169.254.0.0/16", "169.254.1.1")]
    [InlineData("224.0.0.0/8", "224.0.0.251")]
    public void LinkScopeAddresses_IgnoreUserRules(string rule, string address)
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            Rules = [new UserRule(Ipv4Cidr.Parse(rule), ToB)],
        });

        Assert.Equal(new Classification(Decision.Local, DecisionSource.LocalNetwork, null), policy.Classify(Ipv4.Parse(address)));
        Assert.Empty(policy.RangesFor(TunnelB));
    }

    [Fact]
    public void SpecialRanges_AreNotClassifiedByCountry()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput { DefaultTarget = ToA, Geo = Set("10.0.0.0/8", "203.0.113.0/24", "127.0.0.0/8") });

        Assert.Equal(Decision.Local, policy.Classify(Ipv4.Parse("10.1.2.3")).Decision);
        Assert.Equal(DecisionSource.Reserved, policy.Classify(Ipv4.Parse("203.0.113.10")).Source);
        Assert.Equal(DecisionSource.Loopback, policy.Classify(Ipv4.Parse("127.0.0.1")).Source);
        Assert.Empty(policy.DirectRanges);
    }

    [Fact]
    public void ReservedRanges_AreBlocked_WhenRestOfInternetGoesDirect()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput { DefaultTarget = RouteTarget.Direct });

        Assert.Equal(Decision.Block, policy.Classify(Ipv4.Parse("203.0.113.10")).Decision);
        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("8.8.8.8")).Decision);
    }

    [Fact]
    public void OnLinkPrefixes_ShorterThanSlash8_AreIgnored()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToA,
            OnLinePrefixes = [Ipv4Cidr.Parse("26.0.0.0/8"), Ipv4Cidr.Parse("0.0.0.0/1")],
        });

        Assert.Equal(DecisionSource.OnLink, policy.Classify(Ipv4.Parse("26.1.2.3")).Source);
        Assert.Equal(Decision.Vpn, policy.Classify(Ipv4.Parse("45.1.2.3")).Decision);
    }

    [Theory]
    [InlineData(101)]
    [InlineData(202)]
    [InlineData(303)]
    [InlineData(404)]
    public void Compiler_MatchesNaiveClassification(int seed)
    {
        var random = new Random(seed);
        for (var iteration = 0; iteration < 150; iteration++)
        {
            var input = RandomInput(random);
            var policy = PolicyCompiler.Compile(input);

            foreach (var address in SampleAddresses(input, random))
            {
                var expected = Naive(input, address);
                var actual = policy.Classify(address);
                Assert.True(
                    expected.Decision == actual.Decision && expected.Source == actual.Source && expected.Tunnel == actual.Tunnel,
                    $"{Ipv4.Format(address)}: ожидалось {expected.Decision}/{expected.Source}/{expected.Tunnel}, получено {actual.Decision}/{actual.Source}/{actual.Tunnel}");
                Assert.Equal(expected.Decision == Decision.Direct, policy.DirectRanges.Contains(address));
                Assert.Equal(expected.Decision == Decision.Block, policy.BlockRanges.Contains(address));
                Assert.Equal(expected.Decision == Decision.Vpn, policy.RangesFor(expected.Tunnel).Contains(address));
            }

            AssertInvariants(input, policy);
        }
    }

    [Fact]
    public void FullSizeGeo_CompilesQuickly()
    {
        var random = new Random(7);
        var cidrs = Enumerable.Range(0, 13_000)
            .Select(_ => new Ipv4Cidr((uint)random.NextInt64(0x01000000, 0xDF000000) & Ipv4Cidr.MaskOf(24), 24))
            .ToList();
        var input = new PolicyInput
        {
            DefaultTarget = ToA,
            Geo = RangeSet.From(cidrs),
            Rules = Enumerable.Range(0, 200).Select(i => new UserRule(new Ipv4Cidr((uint)(0x2D000000 + (i << 16)), 16), ToA)).ToList(),
            ServerAddresses = [Server],
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var policy = PolicyCompiler.Compile(input);
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3), $"Компиляция заняла {stopwatch.Elapsed}");
        Assert.Equal(policy.DirectRanges.TotalAddresses, policy.DirectRouteCidrs.Aggregate(0UL, (s, c) => s + c.ToRange().Size));
    }

    [Fact]
    public void FullSizeGeo_WithBalancedGroup_CompilesQuickly()
    {
        var random = new Random(11);
        var cidrs = Enumerable.Range(0, 13_000)
            .Select(_ => new Ipv4Cidr((uint)random.NextInt64(0x01000000, 0xDF000000) & Ipv4Cidr.MaskOf(24), 24))
            .ToList();
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Group(GroupId),
            Geo = RangeSet.From(cidrs),
            Groups = [new TunnelGroup(GroupId, [TunnelA, TunnelB])],
            ServerAddresses = [Server],
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var policy = PolicyCompiler.Compile(input);
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3), $"Компиляция заняла {stopwatch.Elapsed}");
        Assert.Empty(policy.RangesFor(TunnelA).Intersect(policy.RangesFor(TunnelB)));
        Assert.True(policy.RangesFor(TunnelA).TotalAddresses > 0 && policy.RangesFor(TunnelB).TotalAddresses > 0);
    }

    private static void AssertInvariants(PolicyInput input, CompiledPolicy policy)
    {
        var service = RangeSet.From(input.ServerAddresses.Concat(input.ServiceDnsAddresses).Select(Ipv4Range.Host))
            .Union(SpecialRanges.Loopback)
            .Union(SpecialRanges.LinkScope)
            .Union(PolicyCompiler.OnLinkSet(input.OnLinePrefixes));
        Assert.Empty(policy.BlockRanges.Intersect(service));
        Assert.Empty(policy.DirectRanges.Intersect(service));
        Assert.Equal(policy.DirectRanges.ToArray(), RangeSet.From(policy.DirectRouteCidrs).ToArray());
        foreach (var tunnel in policy.Tunnels)
        {
            Assert.Empty(policy.RangesFor(tunnel).Intersect(policy.DirectRanges));
            Assert.Empty(policy.RangesFor(tunnel).Intersect(service));
        }
    }

    private static Classification Naive(PolicyInput input, uint address)
    {
        var label = NaiveTarget(input, address);
        return ExpandGroup(input, label, address);
    }

    private static Classification NaiveTarget(PolicyInput input, uint address)
    {
        if (input.ServerAddresses.Contains(address))
        {
            return new Classification(Decision.Server, DecisionSource.Server, null);
        }

        if (input.ServiceDnsAddresses.Contains(address))
        {
            return new Classification(Decision.Server, DecisionSource.ServiceDns, null);
        }

        var special = NaiveSpecial(input, address);
        if (special is not null)
        {
            return special.Value;
        }

        var rule = input.Rules.Where(r => r.Cidr.Contains(address)).OrderBy(r => r.Cidr.PrefixLength).LastOrDefault();
        if (rule is not null)
        {
            return PolicyCompiler.Label(rule.Target, DecisionSource.UserRule, rule);
        }

        if (SpecialRanges.Private.Contains(address))
        {
            return new Classification(Decision.Local, DecisionSource.LocalNetwork, null);
        }

        return input.GeoTarget != input.DefaultTarget && input.Geo.Contains(address)
            ? PolicyCompiler.Label(input.GeoTarget, DecisionSource.Geo)
            : PolicyCompiler.Label(input.DefaultTarget, DecisionSource.Default);
    }

    private static Classification? NaiveSpecial(PolicyInput input, uint address)
    {
        if (SpecialRanges.Loopback.Contains(address))
        {
            return new Classification(Decision.Local, DecisionSource.Loopback, null);
        }

        if (input.OnLinePrefixes.Any(p => p.PrefixLength >= PolicyCompiler.MinOnLinkPrefix && p.Contains(address)))
        {
            return new Classification(Decision.Local, DecisionSource.OnLink, null);
        }

        if (SpecialRanges.LinkScope.Contains(address))
        {
            return new Classification(Decision.Local, DecisionSource.LocalNetwork, null);
        }

        if (!SpecialRanges.Reserved.Contains(address))
        {
            return null;
        }

        return input.DefaultTarget.IsVpn
            ? PolicyCompiler.Label(input.DefaultTarget, DecisionSource.Reserved)
            : new Classification(Decision.Block, DecisionSource.Reserved, null);
    }

    private static Classification ExpandGroup(PolicyInput input, Classification label, uint address)
    {
        if (label.Decision != Decision.Vpn)
        {
            return label;
        }

        var group = input.Groups.FirstOrDefault(g => g.Id == label.Tunnel);
        if (group is null || group.Members.Count == 0)
        {
            return label;
        }

        var block = address >> 24;
        return label with { Tunnel = group.Members[(int)(block % (uint)group.Members.Count)] };
    }

    private static PolicyInput RandomInput(Random random)
    {
        // Основная зона — 45.0.0.0/8 и соседние сети, чтобы правила и база пересекались.
        var geo = Enumerable.Range(0, random.Next(0, 40)).Select(_ => RandomCidr(random, 12, 28)).ToList();
        geo.Add(Ipv4Cidr.Parse("192.168.0.0/20"));
        var targets = new[] { RouteTarget.Direct, ToA, ToB, RouteTarget.Blocked, RouteTarget.Group(GroupId) };
        var rules = Enumerable.Range(0, random.Next(0, 12))
            .Select(_ => new UserRule(RandomCidr(random, 9, 30), targets[random.Next(targets.Length)]))
            .GroupBy(r => r.Cidr)
            .Select(g => g.First())
            .ToList();
        var members = random.Next(0, 4) switch
        {
            0 => new List<Guid>(),
            1 => [TunnelB],
            _ => [TunnelA, TunnelB],
        };
        return new PolicyInput
        {
            DefaultTarget = targets[random.Next(targets.Length - 1)],
            GeoTarget = random.Next(0, 4) == 0 ? ToA : RouteTarget.Direct,
            Geo = RangeSet.From(geo),
            Rules = rules,
            Groups = [new TunnelGroup(GroupId, members)],
            OnLinePrefixes = [RandomCidr(random, 6, 24)],
            ServerAddresses = [RandomAddress(random)],
            ServiceDnsAddresses = random.Next(0, 2) == 0 ? [RandomAddress(random)] : [],
        };
    }

    private static IEnumerable<uint> SampleAddresses(PolicyInput input, Random random)
    {
        var edges = input.Rules.Select(r => r.Cidr.ToRange())
            .Concat(input.Geo)
            .Concat(input.OnLinePrefixes.Select(p => p.ToRange()))
            .SelectMany(r => new[] { r.Start, r.End, r.Start - 1, r.End + 1 });
        return edges
            .Concat(input.ServerAddresses)
            .Concat(input.ServiceDnsAddresses)
            .Concat(Enumerable.Range(0, 50).Select(_ => RandomAddress(random)))
            .Concat([0u, uint.MaxValue, Ipv4.Parse("127.0.0.1"), Ipv4.Parse("203.0.113.1")])
            .Distinct();
    }

    private static Ipv4Cidr RandomCidr(Random random, int minPrefix, int maxPrefix)
    {
        var prefix = random.Next(minPrefix, maxPrefix + 1);
        return new Ipv4Cidr(RandomAddress(random) & Ipv4Cidr.MaskOf(prefix), prefix);
    }

    private static uint RandomAddress(Random random)
    {
        var zones = new[] { 0x2D000000u, 0x2E000000u, 0xC0A80000u, 0xCB007100u, 0xA9FE0000u };
        var zone = zones[random.Next(zones.Length)];
        return zone | (uint)random.Next(0, 1 << 20);
    }

    private static RangeSet Set(params string[] cidrs) => RangeSet.From(cidrs.Select(Ipv4Cidr.Parse));
}
