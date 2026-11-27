using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Net;

/// <summary>
/// Минимальное точное покрытие диапазона блоками CIDR. Свойства: блоки по возрастанию, без пробелов и перекрытий,
/// ровно от начала до конца, каждый выровнен, соседние блоки нельзя слить в один, блоков не больше 62.
/// </summary>
public sealed class CidrCoverTests
{
    private static ulong Size(Ipv4Cidr cidr) => 1UL << (32 - cidr.PrefixLength);

    private static void AssertExactMinimalCover(Ipv4Range range, IReadOnlyList<Ipv4Cidr> cover)
    {
        Assert.NotEmpty(cover);
        Assert.True(cover.Count <= 62, $"{range}: {cover.Count} блоков");
        var next = (ulong)range.Start;
        for (var i = 0; i < cover.Count; i++)
        {
            var block = cover[i];
            Assert.Equal(next, (ulong)block.Network);
            Assert.Equal(0UL, block.Network % Size(block));
            next += Size(block);
            if (i > 0)
            {
                // Два одинаковых соседних блока, первый из которых выровнен по удвоенному размеру, - это один блок.
                var previous = cover[i - 1];
                Assert.False(previous.PrefixLength == block.PrefixLength && previous.Network % (Size(block) * 2) == 0,
                    $"{range}: {previous.Network}/{previous.PrefixLength} и {block.Network}/{block.PrefixLength} сливаются");
            }
        }

        Assert.Equal((ulong)range.End + 1, next);
    }

    [Theory]
    [InlineData(0u, uint.MaxValue, 1)]
    [InlineData(0u, 0u, 1)]
    [InlineData(uint.MaxValue, uint.MaxValue, 1)]
    [InlineData(0u, uint.MaxValue - 1, 32)]
    [InlineData(1u, uint.MaxValue, 32)]
    [InlineData(1u, uint.MaxValue - 1, 62)]
    [InlineData(0x80000000u, uint.MaxValue, 1)]
    [InlineData(0x7FFFFFFFu, 0x80000000u, 2)]
    [InlineData(0x0A000000u, 0x0AFFFFFFu, 1)]
    public void Extremes(uint start, uint end, int expectedBlocks)
    {
        var range = new Ipv4Range(start, end);

        var cover = CidrCover.Cover(range);

        Assert.Equal(expectedBlocks, cover.Count);
        AssertExactMinimalCover(range, cover);
    }

    [Fact]
    public void FullSpace_IsSingleSlashZero()
    {
        var block = Assert.Single(CidrCover.Cover(new Ipv4Range(0, uint.MaxValue)));

        Assert.Equal(0u, block.Network);
        Assert.Equal(0, block.PrefixLength);
    }

    [Fact]
    public void LastAddress_DoesNotWrapAround()
    {
        var cover = CidrCover.Cover(new Ipv4Range(uint.MaxValue - 2, uint.MaxValue));

        Assert.Equal([(uint.MaxValue - 2, 32), (uint.MaxValue - 1, 31)], cover.Select(c => (c.Network, c.PrefixLength)));
    }

    [Fact]
    public void RandomRanges_AreCoveredExactlyAndMinimally()
    {
        var random = new Random(20261127);
        for (var i = 0; i < 2000; i++)
        {
            var a = (uint)random.NextInt64(0, 1L << 32);
            var b = i % 3 == 0 ? a + (uint)random.Next(0, 4096) : (uint)random.NextInt64(0, 1L << 32);
            if (b < a)
            {
                (a, b) = (b, a);
            }

            var range = new Ipv4Range(a, b);
            AssertExactMinimalCover(range, CidrCover.Cover(range));
        }
    }

    [Fact]
    public void AppendCover_AppendsWithoutClearingExisting()
    {
        var result = new List<Ipv4Cidr> { new(0x01000000u, 8) };

        CidrCover.AppendCover(new Ipv4Range(0x0A000000u, 0x0A000001u), result);

        Assert.Equal([(0x01000000u, 8), (0x0A000000u, 31)], result.Select(c => (c.Network, c.PrefixLength)));
    }

    [Fact]
    public void InvertedRange_IsRejectedByRange()
    {
        Assert.Throws<ArgumentException>(() => new Ipv4Range(2, 1));
    }
}
