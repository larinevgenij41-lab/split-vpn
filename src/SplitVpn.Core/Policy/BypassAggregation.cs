using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>
/// Свёртка списка обхода блокировок в подсети. В списке ReFilter десятки тысяч одиночных адресов, и каждый
/// даёт отдельный маршрут и фильтры WFP: таблица маршрутов и сверка фильтров нагружают службы Windows.
/// Подсеть заданной длины, где есть хотя бы один адрес списка, может уйти туда же, куда список, целиком.
/// Адреса RU-базы, которых нет в самом списке, свёртка не забирает: они остаются при своём решении.
/// Из всех наборов между списком и этим пределом выбирается тот, что покрывается наименьшим числом CIDR
/// (маршрутов): лишний адрес берётся, только если он сокращает число маршрутов.
/// </summary>
public static class BypassAggregation
{
    /// <summary>Длина префикса по умолчанию: подсеть /18.</summary>
    public const int DefaultPrefix = 18;

    /// <summary>Самая широкая допустимая подсеть свёртки.</summary>
    public const int MinPrefix = 16;

    /// <summary>Префикс /32 — свёртка выключена.</summary>
    public const int Off = 32;

    /// <param name="bypass">Список обхода как есть.</param>
    /// <param name="keep">Адреса, которые свёртка не должна забирать (RU-база).</param>
    /// <param name="prefix">Длина префикса самой широкой подсети; 32 — без свёртки.</param>
    public static RangeSet Aggregate(RangeSet bypass, RangeSet keep, int prefix)
    {
        ArgumentNullException.ThrowIfNull(bypass);
        ArgumentNullException.ThrowIfNull(keep);
        ArgumentOutOfRangeException.ThrowIfLessThan(prefix, MinPrefix);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(prefix, Off);
        if (prefix == Off || bypass.Count == 0)
        {
            return bypass;
        }

        var mask = uint.MaxValue << (32 - prefix);
        var widened = RangeSet.From(bypass.Select(r => new Ipv4Range(r.Start & mask, r.End | ~mask)));
        // Предел: подсети с адресами списка без адресов RU-базы, которых нет в самом списке.
        var allowed = widened.Subtract(keep.Subtract(bypass));
        return RangeSet.From(MinimalCover(bypass.ToArray(), allowed.ToArray()));
    }

    /// <summary>
    /// Наименьший набор CIDR, который покрывает весь <paramref name="required"/> и не выходит за <paramref name="allowed"/>
    /// (required ⊆ allowed). Обход дерева префиксов сверху: подсеть без адресов списка пропускается, подсеть
    /// целиком внутри предела берётся одним маршрутом, остальные делятся пополам. Такой выбор оптимален:
    /// любое покрытие подсети с адресом списка тратит на неё хотя бы один маршрут.
    /// </summary>
    internal static List<Ipv4Cidr> MinimalCover(Ipv4Range[] required, Ipv4Range[] allowed)
    {
        var result = new List<Ipv4Cidr>();
        var stack = new Stack<(uint Network, int Length)>();
        stack.Push((0, 0));
        while (stack.Count > 0)
        {
            var (network, length) = stack.Pop();
            // Сдвиг uint берёт только 5 бит счётчика: /0 и /32 считаются отдельно.
            var last = length switch
            {
                0 => uint.MaxValue,
                32 => network,
                _ => network | (uint.MaxValue >> length),
            };
            if (!Overlaps(required, network, last))
            {
                continue;
            }

            if (Covers(allowed, network, last))
            {
                // Одного маршрута хватает; берётся самая узкая подсеть вокруг адресов списка внутри этой:
                // она тоже в пределе, а лишних адресов в ней меньше.
                result.Add(Enclosing(FirstRequired(required, network), LastRequired(required, last)));
                continue;
            }

            // required ⊆ allowed, поэтому /32 с адресом списка всегда целиком в пределе и сюда не доходит.
            var half = 1u << (31 - length);
            stack.Push((network | half, length + 1));
            stack.Push((network, length + 1));
        }

        return result;
    }

    /// <summary>Индекс последнего диапазона, который начинается не позже <paramref name="address"/>; -1, если такого нет.</summary>
    private static int LastStartingAtOrBefore(Ipv4Range[] ranges, uint address)
    {
        int low = 0, high = ranges.Length - 1, found = -1;
        while (low <= high)
        {
            var middle = low + ((high - low) / 2);
            if (ranges[middle].Start <= address)
            {
                found = middle;
                low = middle + 1;
            }
            else
            {
                high = middle - 1;
            }
        }

        return found;
    }

    /// <summary>Первый адрес списка не раньше <paramref name="first"/> (вызывается, когда он есть в подсети).</summary>
    private static uint FirstRequired(Ipv4Range[] ranges, uint first)
    {
        var index = LastStartingAtOrBefore(ranges, first);
        return index >= 0 && ranges[index].End >= first ? first : ranges[index + 1].Start;
    }

    /// <summary>Последний адрес списка не позже <paramref name="last"/> (вызывается, когда он есть в подсети).</summary>
    private static uint LastRequired(Ipv4Range[] ranges, uint last)
    {
        var range = ranges[LastStartingAtOrBefore(ranges, last)];
        return Math.Min(range.End, last);
    }

    /// <summary>Наименьшая подсеть, содержащая оба адреса.</summary>
    private static Ipv4Cidr Enclosing(uint first, uint last)
    {
        var length = System.Numerics.BitOperations.LeadingZeroCount(first ^ last);
        var network = length == 0 ? 0 : first & (uint.MaxValue << (32 - length));
        return new Ipv4Cidr(network, length);
    }

    private static bool Overlaps(Ipv4Range[] ranges, uint first, uint last)
    {
        var index = LastStartingAtOrBefore(ranges, last);
        return index >= 0 && ranges[index].End >= first;
    }

    /// <summary>Диапазоны объединены и не соприкасаются, поэтому целиком покрыть отрезок может только один из них.</summary>
    private static bool Covers(Ipv4Range[] ranges, uint first, uint last)
    {
        var index = LastStartingAtOrBefore(ranges, first);
        return index >= 0 && ranges[index].End >= last;
    }
}
