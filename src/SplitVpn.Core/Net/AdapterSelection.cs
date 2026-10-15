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

    public bool IsUp { get; init; }

    /// <summary>Шлюз маршрута 0.0.0.0/0 через этот интерфейс, если есть.</summary>
    public uint? DefaultGateway { get; init; }

    /// <summary>Метрика маршрута по умолчанию с учётом метрики интерфейса.</summary>
    public uint? DefaultRouteMetric { get; init; }

    public IReadOnlyList<Ipv4Cidr> OnLinkPrefixes { get; init; } = [];

    public IReadOnlyList<uint> Addresses { get; init; } = [];

    public IReadOnlyList<uint> DnsServers { get; init; } = [];

    public string TypeName => IfType switch
    {
        6 => "Ethernet",
        71 => "Wi-Fi",
        23 => "PPP",
        131 => "Туннель",
        _ => IsHardware ? "Сетевой адаптер" : "Виртуальный адаптер",
    };
}

public enum PrimaryAdapterStatus
{
    Selected,
    PinnedMissing,
    FallbackFromPinned,
    NoneAvailable,
}

public sealed record PrimaryAdapterResult(AdapterCandidate? Adapter, PrimaryAdapterStatus Status);

public static class PrimaryAdapterSelector
{
    /// <summary>
    /// Auto — аппаратный интерфейс в состоянии Up с маршрутом по умолчанию и минимальной метрикой.
    /// Pinned — закреплённый по GUID; при его отсутствии переход разрешён только флагом.
    /// </summary>
    public static PrimaryAdapterResult Select(IReadOnlyList<AdapterCandidate> adapters, Guid? pinned, bool allowFallback)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        var usable = adapters
            .Where(a => a.IsHardware && a.IsUp && a.DefaultGateway is not null)
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
