using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>Диапазоны, которые не классифицируются по стране (PLAN §4 «Специальные диапазоны»).</summary>
public static class SpecialRanges
{
    /// <summary>
    /// Частные сети: локальные, пока на них нет ручного правила. Правило их перекрывает — так в туннель
    /// направляется удалённая частная сеть за VPN (офис, склад). Сеть самого адаптера правило не перекрывает.
    /// </summary>
    public static RangeSet Private { get; } = FromCidrs(
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16");

    /// <summary>Адреса канального уровня, multicast и широковещание: только локально, правила на них не действуют.</summary>
    public static RangeSet LinkScope { get; } = FromCidrs(
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32");

    /// <summary>Локальные сети: доступ по настройке «Локальный доступ».</summary>
    public static RangeSet Local { get; } = Private.Union(LinkScope);

    public static RangeSet Loopback { get; } = FromCidrs("127.0.0.0/8");

    /// <summary>Зарезервированные и документационные диапазоны: не маршрутизируются в интернете.</summary>
    public static RangeSet Reserved { get; } = FromCidrs(
        "0.0.0.0/8",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4").Subtract(Local);

    /// <summary>Всё, что нельзя встретить в корректной RU-базе.</summary>
    public static RangeSet AllNonPublic { get; } = Local.Union(Loopback).Union(Reserved);

    private static RangeSet FromCidrs(params string[] cidrs) => RangeSet.From(cidrs.Select(Ipv4Cidr.Parse));
}
