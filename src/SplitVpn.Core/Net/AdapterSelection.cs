namespace SplitVpn.Core.Net;

/// <summary>Сведения об интерфейсе, нужные для выбора основного адаптера и детектора конфликтов.</summary>
public sealed record AdapterCandidate
{
    public required Guid InterfaceGuid { get; init; }

    public ulong Luid { get; init; }

    public uint InterfaceIndex { get; init; }

    public required string Name { get; init; }

    public string Description { get; init; } = "";

    /// <summary>Тип интерфейса IANA (6 — Ethernet, 71 — Wi-Fi, 23 — PPP).</summary>
    public uint IfType { get; init; }

    public bool IsHardware { get; init; }

    /// <summary>
    /// Интерфейс PPPoE-подключения к провайдеру. Windows не считает его аппаратным (это PPP, как у VPN), но
    /// это и есть выход в интернет, когда компьютер подключается к провайдеру сам, без роутера.
    /// </summary>
    public bool IsBroadbandDialUp { get; init; }

    public bool IsUp { get; init; }

    /// <summary>Шлюз маршрута 0.0.0.0/0 через этот интерфейс, если есть.</summary>
    public uint? DefaultGateway { get; init; }

    /// <summary>Метрика маршрута по умолчанию с учётом метрики интерфейса.</summary>
    public uint? DefaultRouteMetric { get; init; }

    public IReadOnlyList<Ipv4Cidr> OnLinkPrefixes { get; init; } = [];

    public IReadOnlyList<uint> Addresses { get; init; } = [];

    public IReadOnlyList<uint> DnsServers { get; init; } = [];

    /// <summary>Адаптер виртуальной сети вроде Radmin VPN: узнаётся по описанию драйвера.</summary>
    public bool IsOverlay => OverlayAdapters.IsKnown(Description);

    public string TypeName => IfType switch
    {
        6 => "Ethernet",
        71 => "Wi-Fi",
        23 => "PPP",
        131 => "Туннель",
        _ => IsHardware ? "Сетевой адаптер" : "Виртуальный адаптер",
    };
}

/// <summary>
/// Виртуальные сети поверх интернета (Radmin VPN, Hamachi, ZeroTier, Tailscale). Их адаптер не бывает
/// основным, а при включённом доверии его трафик пропускается защитой независимо от «Локального доступа».
/// </summary>
public static class OverlayAdapters
{
    public static IReadOnlyList<string> KnownDescriptions { get; } = ["Radmin VPN", "Hamachi", "ZeroTier", "Tailscale"];

    public static bool IsKnown(string? description) =>
        !string.IsNullOrEmpty(description)
        && KnownDescriptions.Any(known => description.Contains(known, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Действующая метрика маршрута: метрика маршрута плюс метрика интерфейса.</summary>
public static class RouteMetric
{
    /// <summary>
    /// Сумма без переполнения: огромная метрика интерфейса не должна «перескочить» через ноль и сделать
    /// адаптер самым дешёвым. Сумма больше uint.MaxValue считается uint.MaxValue.
    /// </summary>
    public static uint Effective(uint routeMetric, uint interfaceMetric) =>
        (uint)Math.Min((ulong)routeMetric + interfaceMetric, uint.MaxValue);
}

public enum PrimaryAdapterStatus
{
    Selected,
    PinnedMissing,
    FallbackFromPinned,
    NoneAvailable,

    /// <summary>Закреплённого GUID в системе нет, найден единственный адаптер с тем же описанием драйвера.</summary>
    PinnedRebound,
}

public sealed record PrimaryAdapterResult(AdapterCandidate? Adapter, PrimaryAdapterStatus Status);

public static class PrimaryAdapterSelector
{
    /// <summary>
    /// Может ли интерфейс быть основным: аппаратный адаптер или PPPoE-подключение провайдера, не виртуальная сеть,
    /// включён и с маршрутом по умолчанию.
    /// </summary>
    public static bool CanBePrimary(AdapterCandidate adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        return (adapter.IsHardware || adapter.IsBroadbandDialUp) && !adapter.IsOverlay && adapter.IsUp && adapter.DefaultGateway is not null;
    }

    /// <summary>
    /// Auto — пригодный интерфейс (<see cref="CanBePrimary"/>) с минимальной метрикой маршрута по умолчанию.
    /// Pinned — закреплённый по GUID; при его отсутствии переход разрешён только флагом.
    /// Если GUID исчез из системы совсем (сброс сети Windows выдаёт адаптеру новый), а <paramref name="pinnedDescription"/>
    /// совпадает ровно с одним пригодным адаптером, закрепление переносится на него: это тот же адаптер.
    /// </summary>
    public static PrimaryAdapterResult Select(IReadOnlyList<AdapterCandidate> adapters, Guid? pinned, bool allowFallback, string? pinnedDescription = null)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        var usable = adapters
            .Where(CanBePrimary)
            .OrderBy(a => a.DefaultRouteMetric ?? uint.MaxValue)
            .ThenBy(a => a.InterfaceIndex)
            .ToList();

        if (pinned is null)
        {
            return usable.Count > 0 ? new(usable[0], PrimaryAdapterStatus.Selected) : new(null, PrimaryAdapterStatus.NoneAvailable);
        }

        var pinnedAdapter = usable.FirstOrDefault(a => a.InterfaceGuid == pinned);
        if (pinnedAdapter is not null)
        {
            return new(pinnedAdapter, PrimaryAdapterStatus.Selected);
        }

        // Адаптер с прежним GUID есть, но выключен или без шлюза: это не смена GUID, ждём его.
        if (!string.IsNullOrWhiteSpace(pinnedDescription) && adapters.All(a => a.InterfaceGuid != pinned))
        {
            var sameDriver = usable.Where(a => string.Equals(a.Description, pinnedDescription, StringComparison.OrdinalIgnoreCase)).ToList();
            if (sameDriver.Count == 1)
            {
                return new(sameDriver[0], PrimaryAdapterStatus.PinnedRebound);
            }
        }

        if (allowFallback && usable.Count > 0)
        {
            return new(usable[0], PrimaryAdapterStatus.FallbackFromPinned);
        }

        return new(null, PrimaryAdapterStatus.PinnedMissing);
    }

    /// <summary>Публичные on-link-сети чужих интерфейсов (например, Radmin VPN 26.0.0.0/8).</summary>
    public static IEnumerable<(AdapterCandidate Adapter, Ipv4Cidr Prefix)> PublicOnLinkConflicts(IEnumerable<AdapterCandidate> adapters)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        return adapters
            .Where(a => a.IsUp)
            .SelectMany(a => a.OnLinkPrefixes.Select(p => (Adapter: a, Prefix: p)))
            .Where(x => x.Prefix.PrefixLength >= 8 && !Policy.SpecialRanges.AllNonPublic.Overlaps(x.Prefix.ToRange()));
    }
}
