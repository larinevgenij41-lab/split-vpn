using System.Collections;

namespace SplitVpn.Core.Net;

/// <summary>
/// Неизменяемое множество IPv4-адресов: отсортированные непересекающиеся и несмежные диапазоны.
/// Смежные диапазоны объединяются — это точное преобразование, множество адресов не расширяется.
/// </summary>
public sealed class RangeSet : IReadOnlyList<Ipv4Range>
{
    private readonly Ipv4Range[] _ranges;

    private RangeSet(Ipv4Range[] normalized)
    {
        _ranges = normalized;
    }

    public static RangeSet Empty { get; } = new([]);

    public int Count => _ranges.Length;

    public Ipv4Range this[int index] => _ranges[index];

    public ulong TotalAddresses
    {
        get
        {
            ulong total = 0;
            foreach (var range in _ranges)
            {
                total += range.Size;
            }

            return total;
        }
    }

    public static RangeSet From(IEnumerable<Ipv4Range> ranges)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        var sorted = ranges.OrderBy(r => r.Start).ToList();
        if (sorted.Count == 0)
        {
            return Empty;
        }

        var result = new List<Ipv4Range>(sorted.Count);
        var current = sorted[0];
        for (var i = 1; i < sorted.Count; i++)
        {
            var next = sorted[i];
            if (TouchesOrOverlaps(current, next))
            {
                current = new Ipv4Range(current.Start, Math.Max(current.End, next.End));
                continue;
            }

            result.Add(current);
            current = next;
        }

        result.Add(current);
        return new RangeSet([.. result]);
    }

    public static RangeSet From(IEnumerable<Ipv4Cidr> cidrs)
    {
        ArgumentNullException.ThrowIfNull(cidrs);
        return From(cidrs.Select(c => c.ToRange()));
    }

    public bool Contains(uint address)
    {
        var lo = 0;
        var hi = _ranges.Length - 1;
        while (lo <= hi)
        {
            var mid = lo + ((hi - lo) / 2);
            var range = _ranges[mid];
            if (address < range.Start)
            {
                hi = mid - 1;
            }
            else if (address > range.End)
            {
                lo = mid + 1;
            }
            else
            {
                return true;
            }
        }

        return false;
    }

    public bool Overlaps(Ipv4Range range)
    {
        var index = FirstEndingAtOrAfter(range.Start);
        return index < _ranges.Length && _ranges[index].Start <= range.End;
    }

    public RangeSet Union(RangeSet other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return From(_ranges.Concat(other._ranges));
    }

    public RangeSet Subtract(RangeSet other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (other.Count == 0 || Count == 0)
        {
            return this;
        }

        var result = new List<Ipv4Range>(_ranges.Length);
        var j = 0;
        foreach (var range in _ranges)
        {
            while (j < other._ranges.Length && other._ranges[j].End < range.Start)
            {
                j++;
            }

            SubtractFrom(range, other._ranges, j, result);
        }

        return new RangeSet([.. result]);
    }

    public RangeSet Intersect(RangeSet other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return Subtract(Subtract(other));
    }

    /// <summary>Точное покрытие множества CIDR-блоками (для маршрутов).</summary>
    public IReadOnlyList<Ipv4Cidr> ToCidrs()
    {
        var result = new List<Ipv4Cidr>();
        foreach (var range in _ranges)
        {
            CidrCover.AppendCover(range, result);
        }

        return result;
    }

    public IEnumerator<Ipv4Range> GetEnumerator() => ((IEnumerable<Ipv4Range>)_ranges).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => _ranges.GetEnumerator();

    private static bool TouchesOrOverlaps(Ipv4Range current, Ipv4Range next)
    {
        return current.End == uint.MaxValue || next.Start <= current.End + 1;
    }

    private static void SubtractFrom(Ipv4Range range, Ipv4Range[] cuts, int startIndex, List<Ipv4Range> result)
    {
        var cursor = (ulong)range.Start;
        for (var k = startIndex; k < cuts.Length && cuts[k].Start <= range.End; k++)
        {
            if (cuts[k].Start > cursor)
            {
                result.Add(new Ipv4Range((uint)cursor, cuts[k].Start - 1));
            }

            cursor = Math.Max(cursor, (ulong)cuts[k].End + 1);
            if (cursor > range.End)
            {
                return;
            }
        }

        result.Add(new Ipv4Range((uint)cursor, range.End));
    }

    private int FirstEndingAtOrAfter(uint address)
    {
        var lo = 0;
        var hi = _ranges.Length;
        while (lo < hi)
        {
            var mid = lo + ((hi - lo) / 2);
            if (_ranges[mid].End < address)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid;
            }
        }

        return lo;
    }
}
