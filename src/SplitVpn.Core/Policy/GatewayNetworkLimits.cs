using System.Globalization;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>
/// Пределы слоя сетей, присланных шлюзом AnyConnect. Сети шлюза — недоверенные данные: поштучный предел
/// (не шире /8) не мешает прислать 223 сети /8 и забрать весь публичный IPv4 в чужой туннель или десятки
/// тысяч /32 и подвесить сборку политики. Поэтому слой одного шлюза проверяется целиком, после свёртки:
/// превышен предел — слой отбрасывается весь, с предупреждением (частичное применение было бы произвольным).
/// IPv6 сети шлюза в политику не попадают (разбираются только IPv4-маршруты), отдельного предела им не нужно.
/// </summary>
public static class GatewayNetworkLimits
{
    /// <summary>Суммарное покрытие слоя: 1/16 пространства IPv4, как предел RU-базы (GeoValidationOptions.MaxV4Addresses).</summary>
    public const ulong MaxAddresses = 1UL << 28;

    /// <summary>Число маршрутов (CIDR-блоков) после свёртки слоя.</summary>
    public const int MaxRoutes = 1024;

    /// <summary>Годные сети слоя (не шире /8) одним множеством.</summary>
    public static RangeSet Union(IEnumerable<Ipv4Cidr> cidrs)
    {
        ArgumentNullException.ThrowIfNull(cidrs);
        return RangeSet.From(cidrs.Where(c => c.PrefixLength >= PolicyCompiler.MinServerNetworkPrefix));
    }

    /// <summary>Причина отказа слою сетей шлюза или null, если слой в пределах.</summary>
    public static string? Violation(RangeSet layer)
    {
        ArgumentNullException.ThrowIfNull(layer);
        if (layer.TotalAddresses > MaxAddresses)
        {
            return string.Create(CultureInfo.InvariantCulture,
                $"сети шлюза покрывают {layer.TotalAddresses} адресов при пределе {MaxAddresses} (1/16 IPv4)");
        }

        // Число CIDR-блоков не меньше числа диапазонов: при большом числе диапазонов свёртку не считаем.
        if (layer.Count > MaxRoutes)
        {
            return string.Create(CultureInfo.InvariantCulture,
                $"сетей шлюза после свёртки больше {MaxRoutes} (диапазонов {layer.Count})");
        }

        var routes = layer.ToCidrs().Count;
        return routes > MaxRoutes
            ? string.Create(CultureInfo.InvariantCulture, $"сетей шлюза после свёртки {routes} при пределе {MaxRoutes}")
            : null;
    }
}
