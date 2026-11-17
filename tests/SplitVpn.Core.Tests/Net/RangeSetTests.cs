using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Net;

public class RangeSetTests
{
    [Fact]
    public void From_MergesOverlappingAndAdjacentRanges()
    {
        var set = RangeSet.From(new[] { new Ipv4Range(10, 20), new Ipv4Range(21, 30), new Ipv4Range(25, 40), new Ipv4Range(50, 60) });

        Assert.Equal(new[] { new Ipv4Range(10, 40), new Ipv4Range(50, 60) }, set.ToArray());
        Assert.Equal(42UL, set.TotalAddresses);
    }

    [Fact]
    public void From_HandlesWholeAddressSpace()
    {
        var set = RangeSet.From(new[] { new Ipv4Range(0, uint.MaxValue), new Ipv4Range(5, 6) });

        Assert.Single(set);
        Assert.Equal(1UL << 32, set.TotalAddresses);
        Assert.Equal("0.0.0.0/0", Assert.Single(set.ToCidrs()).ToString());
    }

    [Fact]
    public void Subtract_SplitsRanges()
    {
        var set = RangeSet.From(new[] { new Ipv4Range(0, 100) });
        var cut = RangeSet.From(new[] { new Ipv4Range(10, 20), new Ipv4Range(90, 200) });

        Assert.Equal(new[] { new Ipv4Range(0, 9), new Ipv4Range(21, 89) }, set.Subtract(cut).ToArray());
    }

    [Fact]
    public void Subtract_AtAddressSpaceEdges()
    {
        var set = RangeSet.From(new[] { new Ipv4Range(0, uint.MaxValue) });
        var cut = RangeSet.From(new[] { new Ipv4Range(0, 0), new Ipv4Range(uint.MaxValue, uint.MaxValue) });

        Assert.Equal(new[] { new Ipv4Range(1, uint.MaxValue - 1) }, set.Subtract(cut).ToArray());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void SetOperations_MatchBitmapModel(int seed)
    {
        const int universe = 2048;
        var random = new Random(seed);
        for (var iteration = 0; iteration < 200; iteration++)
        {
            var (a, bitsA) = RandomSet(random, universe);
            var (b, bitsB) = RandomSet(random, universe);

            AssertMatches(a.Union(b), i => bitsA[i] || bitsB[i], universe);
            AssertMatches(a.Subtract(b), i => bitsA[i] && !bitsB[i], universe);
            AssertMatches(a.Intersect(b), i => bitsA[i] && bitsB[i], universe);
            AssertCanonical(a.Union(b));
        }
    }

    [Theory]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    public void ToCidrs_IsExactCover(int seed)
    {
        var random = new Random(seed);
        for (var iteration = 0; iteration < 500; iteration++)
        {
            var start = (uint)random.NextInt64(0, uint.MaxValue);
            var end = (uint)Math.Min(uint.MaxValue, start + (ulong)random.NextInt64(0, 1L << random.Next(1, 33)));
            var range = new Ipv4Range(start, end);

            var cidrs = CidrCover.Cover(range);

            Assert.Equal(range.Size, cidrs.Aggregate(0UL, (sum, c) => sum + c.ToRange().Size));
            Assert.All(cidrs, c => Assert.True(c.Network >= range.Start && c.Last <= range.End));
            Assert.Equal(range, RangeSet.From(cidrs).Single());
        }
    }

    [Fact]
    public void Contains_UsesBinarySearch()
    {
        var set = RangeSet.From(Enumerable.Range(0, 1000).Select(i => new Ipv4Range((uint)(i * 10), (uint)(i * 10) + 4)));

        Assert.True(set.Contains(9994));
        Assert.False(set.Contains(9995));
        Assert.True(set.Overlaps(new Ipv4Range(5, 10)));
        Assert.False(set.Overlaps(new Ipv4Range(5, 9)));
    }

    private static (RangeSet Set, bool[] Bits) RandomSet(Random random, int universe)
    {
        var bits = new bool[universe];
        var ranges = new List<Ipv4Range>();
        for (var i = random.Next(0, 8); i > 0; i--)
        {
            var start = random.Next(0, universe);
            var end = Math.Min(universe - 1, start + random.Next(0, 300));
            ranges.Add(new Ipv4Range((uint)start, (uint)end));
            for (var k = start; k <= end; k++)
            {
                bits[k] = true;
            }
        }

        return (RangeSet.From(ranges), bits);
    }

    private static void AssertMatches(RangeSet set, Func<int, bool> expected, int universe)
    {
        for (var i = 0; i < universe; i++)
        {
            Assert.Equal(expected(i), set.Contains((uint)i));
        }
    }

    private static void AssertCanonical(RangeSet set)
    {
        for (var i = 1; i < set.Count; i++)
        {
            Assert.True(set[i].Start > set[i - 1].End + 1, "Диапазоны должны быть отсортированы, не пересекаться и не соприкасаться.");
        }
    }
}
