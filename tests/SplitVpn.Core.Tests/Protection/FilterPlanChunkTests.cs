using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>
/// Группа Direct складывает тысячи диапазонов в несколько фильтров с условием «любой из». Решение для любого
/// адреса и интерфейса должно остаться тем же, что при фильтре на каждый диапазон.
/// </summary>
public partial class FilterPlanTests
{
    [Fact]
    public void Direct_PacksRangesIntoFewFilters_WithSameDecisions()
    {
        var tunnelId = new Guid("aaaaaaaa-0000-0000-0000-0000000000a1");
        var random = new Random(11);
        var bypass = RangeSet.From(Enumerable.Range(0, 6000).Select(_ => Ipv4Range.Host((uint)random.Next(0x01000000, 0x7F000000))));
        var inputs = new ProtectionInputs
        {
            Policy = PolicyCompiler.Compile(new PolicyInput
            {
                DefaultTarget = RouteTarget.Direct,
                BypassTarget = RouteTarget.Tunnel(tunnelId),
                Bypass = bypass,
            }),
            PrimaryLuid = WiFi,
            Tunnels = [new TunnelInput { Id = tunnelId, Name = "Тест", Luid = Tunnel }],
        };

        var packed = FilterPlanBuilder.BuildDirect(inputs);
        var unpacked = packed.SelectMany(Unpack).ToList();

        Assert.True(unpacked.Count > 15_000, $"ожидались тысячи диапазонов, получено {unpacked.Count}");
        Assert.True(packed.Count < 200, $"фильтров {packed.Count}");
        Assert.All(packed.SelectMany(f => f.Conditions).OfType<RemoteRangesV4>(), c => Assert.InRange(c.Ranges.Count, 1, FilterPlanBuilder.MaxRangesPerFilter));
        // Разностная замена группы сравнивает фильтры по имени: имена не повторяются.
        Assert.Equal(packed.Count, packed.Select(f => f.Name).Distinct(StringComparer.Ordinal).Count());

        var samples = bypass.Take(300).Select(r => r.Start)
            .Concat(Enumerable.Range(0, 300).Select(_ => (uint)random.Next(0x01000000, 0x7F000000)));
        foreach (var address in samples)
        {
            foreach (var luid in new[] { WiFi, Tunnel })
            {
                Assert.Equal(Evaluate(unpacked, Tcp(address, 443, luid)), Evaluate(packed, Tcp(address, 443, luid)));
            }
        }

        // Адрес списка не уходит мимо туннеля, прочий интернет не уходит в туннель.
        var listed = bypass[0].Start;
        Assert.Equal(FilterAction.Block, Evaluate(packed, Tcp(listed, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(packed, Tcp(listed, 443, Tunnel)));
    }

    [Fact]
    public void Direct_ChangeInOnePart_KeepsOtherFilterNames()
    {
        var before = FilterPlanBuilder.Chunks(RangeSet.From([Ipv4Cidr.Parse("8.8.8.0/24"), Ipv4Cidr.Parse("100.1.0.0/16")])).ToList();
        var after = FilterPlanBuilder.Chunks(RangeSet.From([Ipv4Cidr.Parse("8.8.8.0/24"), Ipv4Cidr.Parse("100.2.0.0/16")])).ToList();

        Assert.Equal(before[0].Label, after[0].Label);
        Assert.NotEqual(before[1].Label, after[1].Label);
    }

    [Fact]
    public void RemoteRangesV4_RejectsEmptySet() =>
        Assert.Throws<ArgumentException>(() => new RemoteRangesV4([]));

    /// <summary>Тот же фильтр по одному на каждый диапазон: прежняя схема группы Direct.</summary>
    private static IEnumerable<FilterSpec> Unpack(FilterSpec spec)
    {
        var set = spec.Conditions.OfType<RemoteRangesV4>().SingleOrDefault();
        if (set is null)
        {
            yield return spec;
            yield break;
        }

        foreach (var range in set.Ranges)
        {
            yield return spec with { Conditions = [.. spec.Conditions.Select(c => c == set ? new RemoteRangeV4(range.Start, range.End) : c)] };
        }
    }
}
