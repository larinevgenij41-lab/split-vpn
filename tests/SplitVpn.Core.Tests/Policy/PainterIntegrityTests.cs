using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

public class PainterIntegrityTests
{
    private static readonly Classification Direct = new(Decision.Direct, DecisionSource.Default, null);
    private static readonly Classification Local = new(Decision.Local, DecisionSource.LocalNetwork, null);

    [Theory]
    [InlineData(0u, 0u)]
    [InlineData(uint.MaxValue, uint.MaxValue)]
    [InlineData(0u, uint.MaxValue)]
    [InlineData(20u, 95u)]
    [InlineData(30u, 49u)]
    public void SingleRangeLayer_ChangesOnlyCoveredAddresses(uint start, uint end)
    {
        var background = RangeSet.From(new[] { new Ipv4Range(10, 29), new Ipv4Range(50, 69), new Ipv4Range(90, 109) });
        var painter = new IntervalPainter(Direct, background, Local);
        var blocked = new Classification(Decision.Block, DecisionSource.UserRule, null);

        painter.Paint(RangeSet.From([new Ipv4Range(start, end)]), blocked);

        Assert.Null(painter.FindViolation());
        foreach (var address in Enumerable.Range(0, 121).Select(i => (uint)i).Concat([uint.MaxValue - 1, uint.MaxValue]))
        {
            var expected = address >= start && address <= end ? blocked : background.Contains(address) ? Local : Direct;
            Assert.Equal(expected, painter.Classify(address));
        }
    }

    [Fact]
    public void PaintedLayers_KeepIntegrity()
    {
        var painter = new IntervalPainter(Direct, RangeSet.From([Ipv4Cidr.Parse("77.88.0.0/18")]), Local);
        painter.Paint(Ipv4Cidr.Parse("0.0.0.0/8").ToRange(), Local);
        painter.Paint(Ipv4Cidr.Parse("255.255.255.255/32").ToRange(), Local);
        painter.PaintKeeping(Ipv4Cidr.Parse("77.88.8.0/24").ToRange(), Direct, _ => false);

        Assert.Null(painter.FindViolation());
    }

    /// <summary>Слой за один проход размечает адреса так же, как покраска по одному диапазону.</summary>
    [Fact]
    public void LayerPaint_MatchesRangeByRange()
    {
        var labels = new[] { Direct, Local, new Classification(Decision.Block, DecisionSource.UserRule, null) };
        for (var seed = 0; seed < 3000; seed++)
        {
            var rng = new Random(seed);
            var background = RandomSet(rng);
            var layered = new IntervalPainter(Direct, background, Local);
            var single = new IntervalPainter(Direct, background, Local);
            for (var step = 0; step < 4; step++)
            {
                var set = RandomSet(rng);
                var label = labels[rng.Next(labels.Length)];
                layered.Paint(set, label);
                foreach (var range in set)
                {
                    single.Paint(range, label);
                }
            }

            Assert.Null(layered.FindViolation());
            foreach (var point in single.Segments.Concat(layered.Segments).SelectMany(s => new[] { s.Start, s.End }))
            {
                Assert.True(single.Classify(point) == layered.Classify(point), $"seed {seed}, адрес {Ipv4.Format(point)}");
            }
        }
    }

    private static RangeSet RandomSet(Random rng)
    {
        // Границы собираются у 0, у конца пространства и в узком окне, чтобы диапазоны часто соприкасались.
        uint Pick() => rng.Next(3) switch
        {
            0 => (uint)rng.Next(0, 40),
            1 => uint.MaxValue - (uint)rng.Next(0, 40),
            _ => 1000 + (uint)rng.Next(0, 40),
        };

        return RangeSet.From(Enumerable.Range(0, rng.Next(0, 6)).Select(_ =>
        {
            var a = Pick();
            var b = Pick();
            return new Ipv4Range(Math.Min(a, b), Math.Max(a, b));
        }));
    }

    [Fact]
    public void InvertedSegment_IsReported()
    {
        var painter = new IntervalPainter(Direct);
        var segments = (List<IntervalPainter.Segment>)painter.Segments;
        segments[0] = segments[0] with { End = 10 };
        segments.Add(new IntervalPainter.Segment(11, 5, Local));
        segments.Add(new IntervalPainter.Segment(6, uint.MaxValue, Direct));

        var violation = painter.FindViolation();

        Assert.NotNull(violation);
        Assert.Contains("участок №1 из 3: конец меньше начала", violation, StringComparison.Ordinal);
        Assert.Contains("0.0.0.11–0.0.0.5", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void GapBetweenSegments_IsReported()
    {
        var painter = new IntervalPainter(Direct);
        var segments = (List<IntervalPainter.Segment>)painter.Segments;
        segments[0] = segments[0] with { End = 10 };
        segments.Add(new IntervalPainter.Segment(20, uint.MaxValue, Local));

        Assert.Contains("ожидалось начало 0.0.0.11", painter.FindViolation(), StringComparison.Ordinal);
    }

    [Fact]
    public void ShortCoverage_IsReported()
    {
        var painter = new IntervalPainter(Direct);
        var segments = (List<IntervalPainter.Segment>)painter.Segments;
        segments[0] = segments[0] with { End = 10 };

        Assert.Contains("не доходит до конца", painter.FindViolation(), StringComparison.Ordinal);
    }

    [Fact]
    public void InputDescription_ListsVolatileInputs()
    {
        var tunnel = new Guid("aaaaaaaa-0000-0000-0000-000000000001");
        var description = PolicyCompiler.DescribeInput(new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(tunnel),
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
            ServerAddresses = [Ipv4.Parse("203.0.113.20")],
            ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(tunnel), [Ipv4Cidr.Parse("10.163.0.0/16")])],
            TunnelHosts = [new TunnelHost(tunnel, Ipv4.Parse("10.163.7.1"))],
        });

        Assert.Contains("сеть адаптера: 192.168.1.0/24", description, StringComparison.Ordinal);
        Assert.Contains("серверы: 203.0.113.20", description, StringComparison.Ordinal);
        Assert.Contains("10.163.0.0/16", description, StringComparison.Ordinal);
        Assert.Contains($"{tunnel}:10.163.7.1", description, StringComparison.Ordinal);
    }
}
