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

    /// <summary>
    /// Слой целиком за один проход. Покраска по одному диапазону сдвигает хвост списка на каждой вставке:
    /// список обхода поверх RU-базы (по 10–20 тыс. диапазонов) собирался так 300 мс вместо 10.
    /// </summary>
    public void Paint(RangeSet ranges, Classification label)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        if (ranges.Count == 0)
        {
            return;
        }

        var result = new List<Segment>(_segments.Count + (ranges.Count * 2));
        var next = 0;
        foreach (var segment in _segments)
        {
            next = PaintSegment(segment, ranges, next, label, result);
        }

        _segments.Clear();
        _segments.AddRange(result);
    }

    /// <summary>
    /// Раскладывает сегмент по диапазонам слоя, начиная с диапазона next. Возвращает первый диапазон,
    /// который может задеть следующий сегмент: диапазон, выходящий за конец сегмента, остаётся текущим.
    /// </summary>
    private static int PaintSegment(Segment segment, RangeSet ranges, int next, Classification label, List<Segment> result)
    {
        var cursor = (ulong)segment.Start;
        while (next < ranges.Count && ranges[next].Start <= segment.End)
        {
            var range = ranges[next];
            if (range.Start > cursor)
            {
                result.Add(segment with { Start = (uint)cursor, End = range.Start - 1 });
            }

            var end = Math.Min(range.End, segment.End);
            Append(result, new Segment((uint)Math.Max(cursor, range.Start), end, label));
            cursor = (ulong)end + 1;
            if (range.End > segment.End)
            {
                return next;
            }

            next++;
        }

        if (cursor <= segment.End)
        {
            result.Add(segment with { Start = (uint)cursor });
        }

        return next;
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

    /// <summary>
    /// Первое нарушение разметки: участки обязаны идти подряд от 0.0.0.0 до 255.255.255.255 без разрывов
    /// и наложений, у каждого начало не больше конца. Null — разметка цела.
    /// </summary>
    public string? FindViolation()
    {
        if (_segments.Count == 0)
        {
            return "разметка пуста";
        }

        for (var i = 0; i < _segments.Count; i++)
        {
            var expectedStart = i == 0 ? 0 : (ulong)_segments[i - 1].End + 1;
            if (_segments[i].End < _segments[i].Start)
            {
                return DescribeViolation(i, "конец меньше начала");
            }

            if (_segments[i].Start != expectedStart)
            {
                return DescribeViolation(i, $"ожидалось начало {Ipv4.Format((uint)expectedStart)}");
            }
        }

        return _segments[^1].End == uint.MaxValue ? null : DescribeViolation(_segments.Count - 1, "разметка не доходит до конца пространства");
    }

    private string DescribeViolation(int index, string problem)
    {
        var neighbours = Enumerable.Range(index - 1, 3)
            .Where(i => i >= 0 && i < _segments.Count)
            .Select(i => $"№{i} {Ipv4.Format(_segments[i].Start)}–{Ipv4.Format(_segments[i].End)} {_segments[i].Label.Decision}/{_segments[i].Label.Source}");
        return $"участок №{index} из {_segments.Count}: {problem} ({string.Join("; ", neighbours)})";
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
