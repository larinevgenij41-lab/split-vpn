using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>
/// Свёртка списка обхода блокировок в подсети. В списке ReFilter десятки тысяч одиночных адресов, и каждый
/// даёт отдельный маршрут и фильтры WFP: таблица маршрутов и сверка фильтров нагружают службы Windows.
/// Подсеть заданной длины, где есть хотя бы один адрес списка, целиком уходит туда же, куда список.
/// Адреса RU-базы, которых нет в самом списке, свёртка не забирает: они остаются при своём решении.
/// </summary>
public static class BypassAggregation
{
    /// <summary>Длина префикса по умолчанию: подсеть /24.</summary>
    public const int DefaultPrefix = 24;

    /// <summary>Самая широкая допустимая подсеть свёртки.</summary>
    public const int MinPrefix = 20;

    /// <summary>Префикс /32 — свёртка выключена.</summary>
    public const int Off = 32;

    /// <param name="bypass">Список обхода как есть.</param>
    /// <param name="keep">Адреса, которые свёртка не должна забирать (RU-база).</param>
    /// <param name="prefix">Длина префикса подсети; 32 — без свёртки.</param>
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
        // Из расширения убираются только адреса RU-базы, добавленные свёрткой; адреса самого списка остаются.
        return widened.Subtract(keep.Subtract(bypass));
    }
}
