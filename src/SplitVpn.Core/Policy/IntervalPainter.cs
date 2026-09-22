using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>
/// Разметка всего пространства IPv4 на сегменты с метками. Каждая покраска перекрывает предыдущие,
/// поэтому слои красятся от низшего приоритета к высшему.
/// </summary>
internal sealed class IntervalPainter
{
    /// <summary>
    /// Размер блока, которым распределяется нагрузка между туннелями группы: адресное пространство
    /// делится на блоки /8, блок достаётся участнику по остатку от деления. Таблица маршрутов умеет
    /// только префиксы, поэтому распределение идёт по назначению, а не по соединениям.
    /// </summary>
    public const int BalanceBlockBits = 24;

    private readonly List<Segment> _segments;

    public IntervalPainter(Classification initial)
    {
        _segments = [new Segment(0, uint.MaxValue, initial)];
    }

    /// <summary>Фон и один слой без поразрядных вставок: линейно, для больших наборов вроде RU-базы.</summary>
    public IntervalPainter(Classification background, RangeSet layer, Classification label)
    {
        ArgumentNullException.ThrowIfNull(layer);
        _segments = new List<Segment>((layer.Count * 2) + 1);
        ulong cursor = 0;
        foreach (var range in layer)
        {
            if (range.Start > cursor)
            {
                _segments.Add(new Segment((uint)cursor, range.Start - 1, background));
            }

            _segments.Add(new Segment(range.Start, range.End, label));
            cursor = (ulong)range.End + 1;
        }

        if (cursor <= uint.MaxValue)
        {
            _segments.Add(new Segment((uint)cursor, uint.MaxValue, background));
        }
    }

    public IReadOnlyList<Segment> Segments => _segments;

    public void Paint(RangeSet ranges, Classification label)
    {
        foreach (var range in ranges)
        {
            Paint(range, label);
        }
    }

    public void Paint(Ipv4Range range, Classification label)
    {
        var first = IndexOf(range.Start);
        var last = IndexOf(range.End);
        var head = _segments[first];
        var tail = _segments[last];

        var replacement = new List<Segment>(3);
        if (head.Start < range.Start)
        {
            replacement.Add(head with { End = range.Start - 1 });
        }

        replacement.Add(new Segment(range.Start, range.End, label));
        if (tail.End > range.End)
        {
            replacement.Add(tail with { Start = range.End + 1 });
        }

        _segments.RemoveRange(first, last - first + 1);
        _segments.InsertRange(first, replacement);
    }

    /// <summary>
    /// Покраска, которая не трогает уже размеченные участки, защищённые условием: слой ложится поверх
    /// остальных, но сохраняет то, что решил пользователь (например, «Блокировать» своим правилом).
    /// </summary>
    public void PaintKeeping(Ipv4Range range, Classification label, Func<Classification, bool> keep)
    {
        ArgumentNullException.ThrowIfNull(keep);
        var first = IndexOf(range.Start);
        var last = IndexOf(range.End);
        var head = _segments[first];
        var tail = _segments[last];

        var replacement = new List<Segment>(last - first + 3);
        if (head.Start < range.Start)
        {
            replacement.Add(head with { End = range.Start - 1 });
        }

        for (var i = first; i <= last; i++)
        {
            var segment = _segments[i];
            var start = Math.Max(segment.Start, range.Start);
            var end = Math.Min(segment.End, range.End);
            Append(replacement, new Segment(start, end, keep(segment.Label) ? segment.Label : label));
        }

        if (tail.End > range.End)
        {
            Append(replacement, tail with { Start = range.End + 1 });
        }

        _segments.RemoveRange(first, last - first + 1);
        _segments.InsertRange(first, replacement);
    }

    public Classification Classify(uint address) => _segments[IndexOf(address)].Label;

    /// <summary>Множество адресов, у которых решение совпадает с заданным.</summary>
    public RangeSet Collect(Decision decision)
    {
        return RangeSet.From(_segments.Where(s => s.Label.Decision == decision).Select(s => new Ipv4Range(s.Start, s.End)));
    }

    /// <summary>Множества адресов по туннелям: один проход вместо прохода на каждый туннель.</summary>
    public Dictionary<Guid, RangeSet> CollectTunnels()
    {
        var byTunnel = new Dictionary<Guid, List<Ipv4Range>>();
        foreach (var segment in _segments.Where(s => s.Label.Decision == Decision.Vpn))
        {
            if (!byTunnel.TryGetValue(segment.Label.Tunnel, out var ranges))
            {
                ranges = [];
                byTunnel[segment.Label.Tunnel] = ranges;
            }

            ranges.Add(new Ipv4Range(segment.Start, segment.End));
        }

        return byTunnel.ToDictionary(p => p.Key, p => RangeSet.From(p.Value));
    }

    /// <summary>
    /// Раскрывает группы: сегмент, помеченный идентификатором группы, делится по блокам /8 между её
    /// участниками. Группа без годных участников остаётся помеченной своим идентификатором — служба
    /// считает её недоступным туннелем и блокирует назначенные ей адреса.
    /// </summary>
    public void ExpandGroups(IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> groups)
    {
        ArgumentNullException.ThrowIfNull(groups);
        if (groups.Count == 0 || !_segments.Any(s => IsGroup(s.Label, groups)))
        {
            return;
        }

        var result = new List<Segment>(_segments.Count + (1 << (32 - BalanceBlockBits)));
        foreach (var segment in _segments)
        {
            if (segment.Label.Decision == Decision.Vpn && groups.TryGetValue(segment.Label.Tunnel, out var members) && members.Count > 0)
            {
                AppendSplit(result, segment, members);
            }
            else
            {
                Append(result, segment);
            }
        }

        _segments.Clear();
        _segments.AddRange(result);
    }

    private static bool IsGroup(Classification label, IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> groups) =>
        label.Decision == Decision.Vpn && groups.TryGetValue(label.Tunnel, out var members) && members.Count > 0;

    private static void AppendSplit(List<Segment> result, Segment segment, IReadOnlyList<Guid> members)
    {
        var start = segment.Start;
        while (true)
        {
            var block = start >> BalanceBlockBits;
            var blockEnd = (block << BalanceBlockBits) | ((1u << BalanceBlockBits) - 1);
            var end = Math.Min(blockEnd, segment.End);
            var label = segment.Label with { Tunnel = members[(int)(block % (uint)members.Count)] };
            Append(result, new Segment(start, end, label));
            if (end == segment.End)
            {
                return;
            }

            start = end + 1;
        }
    }

    /// <summary>Добавляет сегмент, склеивая его с предыдущим при совпадении метки.</summary>
    private static void Append(List<Segment> result, Segment segment)
    {
        if (result.Count > 0 && (ulong)result[^1].End + 1 == segment.Start && result[^1].Label == segment.Label)
        {
            result[^1] = result[^1] with { End = segment.End };
            return;
        }

        result.Add(segment);
    }

    private int IndexOf(uint address)
    {
        var lo = 0;
        var hi = _segments.Count - 1;
        while (lo < hi)
        {
            var mid = lo + ((hi - lo + 1) / 2);
            if (_segments[mid].Start <= address)
            {
                lo = mid;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return lo;
    }

    internal readonly record struct Segment(uint Start, uint End, Classification Label);
}
