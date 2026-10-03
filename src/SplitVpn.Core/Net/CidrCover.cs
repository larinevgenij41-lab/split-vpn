using System.Numerics;

namespace SplitVpn.Core.Net;

/// <summary>Минимальное точное покрытие диапазона IPv4 блоками CIDR.</summary>
public static class CidrCover
{
    public static IReadOnlyList<Ipv4Cidr> Cover(Ipv4Range range)
    {
        var result = new List<Ipv4Cidr>();
        AppendCover(range, result);
        return result;
    }

    internal static void AppendCover(Ipv4Range range, List<Ipv4Cidr> result)
    {
        var start = (ulong)range.Start;
        var end = (ulong)range.End;
        while (start <= end)
        {
            // Самый большой блок, выровненный по start и не выходящий за end.
            var alignment = start == 0 ? 32 : BitOperations.TrailingZeroCount(start);
            var fit = 63 - BitOperations.LeadingZeroCount(end - start + 1);
            var hostBits = Math.Min(Math.Min(alignment, fit), 32);
            result.Add(new Ipv4Cidr((uint)start, 32 - hostBits));
            start += 1UL << hostBits;
        }
    }
}
