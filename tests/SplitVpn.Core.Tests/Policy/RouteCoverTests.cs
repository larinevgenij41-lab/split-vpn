using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

/// <summary>
/// Маршруты с исключениями: самый длинный подходящий префикс обязан вести каждый адрес туда же, куда точное
/// CIDR-покрытие каждой цели, а записей должно быть не больше.
/// </summary>
public class RouteCoverTests
{
    private static RangeSet Set(params string[] cidrs) => RangeSet.From(cidrs.Select(Ipv4Cidr.Parse));

    [Fact]
    public void RussianSubnetWithHole_BecomesSupernetAndException()
    {
        // /21 без одной /24: точно это три маршрута (/23, /24, /22), с исключением — два.
        var direct = Set("77.88.0.0/23", "77.88.2.0/24", "77.88.4.0/22");

        var cover = RouteCover.Build([(direct, 1)], [true, true], RangeSet.Empty);

        Assert.Equal(3, direct.ToCidrs().Count);
        Assert.Equal(2, cover.Count);
        Assert.Contains(new CoverRoute(Ipv4Cidr.Parse("77.88.0.0/21"), 1), cover);
        Assert.Contains(new CoverRoute(Ipv4Cidr.Parse("77.88.3.0/24"), 0), cover);
    }

    [Fact]
    public void NoPathForDefault_KeepsExactCover()
    {
        var direct = Set("77.88.0.0/23", "77.88.2.0/24", "77.88.4.0/22");

        var cover = RouteCover.Build([(direct, 1)], [false, true], RangeSet.Empty);

        Assert.Equal(direct.ToCidrs().Count, cover.Count);
        Assert.All(cover, r => Assert.Equal(1, r.Target));
    }

    [Fact]
    public void LocalNetworks_AreNeverCovered()
    {
        var direct = Set("10.0.0.0/9", "10.128.0.0/10", "10.193.0.0/16");
        var local = Set("10.192.0.0/16");

        var cover = RouteCover.Build([(direct, 1)], [true, true], local);

        Assert.All(cover, r => Assert.False(local.Overlaps(r.Cidr.ToRange())));
        AssertSameDecisions([(direct, 1)], cover, local, Probe(direct.Union(local)));
    }

    [Fact]
    public void Cover_MatchesExactRoutes_OnRandomMaps()
    {
        var random = new Random(5);
        for (var round = 0; round < 150; round++)
        {
            var targets = random.Next(2, 5);
            var layers = new List<(RangeSet Ranges, int Target)>();
            var used = RangeSet.Empty;
            for (var target = 1; target < targets; target++)
            {
                var ranges = RangeSet.From(Enumerable.Range(0, random.Next(1, 60))
                    .Select(_ => Masked(0x4D000000u | ((uint)random.Next(0, 1 << 16) << 8), random.Next(20, 25)))).Subtract(used);
                used = used.Union(ranges);
                layers.Add((ranges, target));
            }

            var local = RangeSet.From(Enumerable.Range(0, random.Next(0, 4)).Select(_ => new Ipv4Cidr(0x4D000000u | ((uint)random.Next(0, 1 << 12) << 12), 20))).Subtract(used);
            var emittable = Enumerable.Range(0, targets).Select(t => t != 0 || random.Next(2) == 0).ToList();

            var cover = RouteCover.Build(layers, emittable, local);

            var exact = layers.Sum(l => l.Ranges.ToCidrs().Count);
            Assert.True(cover.Count <= exact, $"раунд {round}: {cover.Count} > {exact}");
            Assert.All(cover, r => Assert.True(r.Cidr.PrefixLength >= RouteCover.MinPrefix));
            Assert.All(cover, r => Assert.True(emittable[r.Target]));
            Assert.All(cover, r => Assert.False(local.Overlaps(r.Cidr.ToRange())));
            AssertSameDecisions(layers, cover, local, Probe(used.Union(local)).Concat(Enumerable.Range(0, 300).Select(_ => 0x4D000000u | (uint)random.Next(0, 1 << 24))));
        }
    }

    [Fact]
    public void OnLinkRoute_LastAddressBelongsToItsTarget()
    {
        // Сеть туннеля без последнего адреса, который идёт напрямую: широкий маршрут туннеля с исключением
        // дал бы два маршрута, но Windows поставил бы /32 последнего адреса в туннель поверх исключения.
        var tunnel = Set("13.107.0.0/16").Subtract(Set("13.107.255.255/32"));
        var direct = Set("13.107.255.255/32");
        CoverTarget[] targets = [new(true, OnLink: true), new(true, OnLink: true), new(true)];

        var cover = RouteCover.Build([(tunnel, 1), (direct, 2)], targets, RangeSet.Empty);

        Assert.DoesNotContain(cover, r => r.Target == 1 && r.Cidr.ToRange().Contains(Ipv4.Parse("13.107.255.255")) && r.Cidr.PrefixLength <= RouteCover.MaxBroadcastPrefix);
        AssertSameDecisions([(tunnel, 1), (direct, 2)], cover, RangeSet.Empty, Probe(tunnel.Union(direct)), targets);
    }

    [Fact]
    public void DefaultTunnelAddresses_StayOutOfOtherTunnelRoutes()
    {
        // Дыра в сети второго туннеля принадлежит туннелю «остального интернета». Исключение внутри маршрута
        // второго туннеля при обрыве основного снялось бы, и адреса ушли бы во второй туннель.
        var second = Set("8.8.0.0/16").Subtract(Set("8.8.128.0/24"));

        var free = RouteCover.Build([(second, 1)], [new CoverTarget(true, OnLink: true), new CoverTarget(true, OnLink: true)], RangeSet.Empty);
        var held = RouteCover.Build([(second, 1)], [new CoverTarget(true, OnLink: true), new CoverTarget(true, OnLink: true, HoldsDefault: false)], RangeSet.Empty);

        Assert.Contains(free, r => r.Target == 1 && r.Cidr.ToRange().Contains(Ipv4.Parse("8.8.128.1")));
        Assert.DoesNotContain(held, r => r.Target == 1 && r.Cidr.ToRange().Contains(Ipv4.Parse("8.8.128.1")));
        AssertSameDecisions([(second, 1)], held, RangeSet.Empty, Probe(Set("8.8.0.0/16")));
    }

    [Fact]
    public void Cover_WithTargetRules_MatchesExactRoutes_OnRandomMaps()
    {
        var random = new Random(11);
        for (var round = 0; round < 150; round++)
        {
            var count = random.Next(2, 5);
            var layers = new List<(RangeSet Ranges, int Target)>();
            var used = RangeSet.Empty;
            for (var target = 1; target < count; target++)
            {
                var ranges = RangeSet.From(Enumerable.Range(0, random.Next(1, 60))
                    .Select(_ => Masked(0x4D000000u | ((uint)random.Next(0, 1 << 16) << 8), random.Next(18, 33)))).Subtract(used);
                used = used.Union(ranges);
                layers.Add((ranges, target));
            }

            var targets = Enumerable.Range(0, count)
                .Select(t => new CoverTarget(t != 0 || random.Next(3) > 0, OnLink: random.Next(2) == 0, HoldsDefault: t == 0 || random.Next(2) == 0))
                .ToList();

            var cover = RouteCover.Build(layers, targets, RangeSet.Empty);

            Assert.All(cover, r => Assert.True(targets[r.Target].Emittable));
            foreach (var route in cover.Where(r => targets[r.Target].OnLink && r.Cidr.PrefixLength <= RouteCover.MaxBroadcastPrefix))
            {
                var last = route.Cidr.ToRange().End;
                Assert.True(TargetOf(layers, last) == route.Target, $"раунд {round}: последний адрес {route.Cidr} не своей цели");
            }

            var probes = Probe(used).Concat(Enumerable.Range(0, 300).Select(_ => 0x4D000000u | (uint)random.Next(0, 1 << 24))).ToList();

            // Когда маршруты цели 0 сняты (обрыв её туннеля), адрес цели 0 попадает под ближайший маршрут другой
            // цели: это не должна быть цель, которой нельзя накрывать цель 0.
            foreach (var address in probes.Where(a => TargetOf(layers, a) == 0))
            {
                var fallback = cover.Where(r => r.Target != 0 && r.Cidr.ToRange().Contains(address)).OrderByDescending(r => r.Cidr.PrefixLength).FirstOrDefault();
                Assert.True(fallback == default || targets[fallback.Target].HoldsDefault, $"раунд {round}: {Ipv4.Format(address)} уйдёт в {fallback.Cidr}");
            }

            AssertSameDecisions(layers, cover, RangeSet.Empty, probes, targets);
        }
    }

    private static int TargetOf(IReadOnlyList<(RangeSet Ranges, int Target)> layers, uint address) =>
        layers.FirstOrDefault(l => l.Ranges.Contains(address)).Target;

    private static Ipv4Cidr Masked(uint address, int length) => new(address & (uint.MaxValue << (32 - length)), length);

    /// <summary>Края каждого диапазона и соседние адреса: там покрытие ошибается первым.</summary>
    private static IEnumerable<uint> Probe(RangeSet set) =>
        set.SelectMany(r => new[] { r.Start, r.End, r.Start - 1, r.End + 1, r.Start + ((r.End - r.Start) / 2) });

    /// <summary>
    /// Выбор Windows: самый длинный подходящий префикс. С целями без шлюза к каждому их маршруту шире /31 Windows
    /// добавляет /32 последнего адреса в тот же интерфейс, и при равной длине выигрывает он (метрика меньше).
    /// </summary>
    private static void AssertSameDecisions(IReadOnlyList<(RangeSet Ranges, int Target)> layers, List<CoverRoute> cover, RangeSet local, IEnumerable<uint> addresses,
        IReadOnlyList<CoverTarget>? targets = null)
    {
        var table = cover.Select(r => (r.Cidr, r.Target, System: false)).ToList();
        if (targets is not null)
        {
            table.AddRange(cover.Where(r => targets[r.Target].OnLink && r.Cidr.PrefixLength <= RouteCover.MaxBroadcastPrefix)
                .Select(r => (new Ipv4Cidr(r.Cidr.ToRange().End, 32), r.Target, System: true)));
        }

        foreach (var address in addresses)
        {
            var expected = layers.FirstOrDefault(l => l.Ranges.Contains(address)).Target;
            var match = table.Where(r => r.Cidr.ToRange().Contains(address)).OrderByDescending(r => r.Cidr.PrefixLength).ThenByDescending(r => r.System)
                .Select(r => (int?)r.Target).FirstOrDefault();
            var actual = match ?? 0;
            Assert.True(expected == actual, $"{Ipv4.Format(address)}: ожидалась цель {expected}, маршрут ведёт в {actual}");
            if (local.Contains(address))
            {
                Assert.Null(match);
            }
        }
    }
}
