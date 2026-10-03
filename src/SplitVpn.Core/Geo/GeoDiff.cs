using SplitVpn.Core.Net;

namespace SplitVpn.Core.Geo;

public sealed record GeoDiffResult(
    int OldRangeCount,
    int NewRangeCount,
    ulong OldAddresses,
    ulong NewAddresses,
    int AddedRanges,
    int RemovedRanges,
    ulong AddedAddresses,
    ulong RemovedAddresses)
{
    public double AddressChangeShare => OldAddresses == 0 ? 1 : (double)(AddedAddresses + RemovedAddresses) / OldAddresses;

    public double CountChangeShare => OldRangeCount == 0 ? 1 : Math.Abs(NewRangeCount - OldRangeCount) / (double)OldRangeCount;
}

/// <summary>Пороги ручного рассмотрения обновления (RESEARCH, шаг 7).</summary>
public sealed record GeoAnomalyThresholds
{
    public double MaxAddressChangeShare { get; init; } = 0.10;

    public double MaxCountChangeShare { get; init; } = 0.20;

    /// <summary>
    /// Пороги под конкретный список. Состав RU-базы меняется медленно, и резкий скачок — повод
    /// спросить пользователя. Список обхода блокировок состоит в основном из отдельных адресов и
    /// обновляется ежедневно: с порогами RU-базы подтверждения требовалось бы почти каждый день.
    /// </summary>
    public static GeoAnomalyThresholds For(GeoListKind kind) => kind == GeoListKind.Bypass
        ? new GeoAnomalyThresholds { MaxAddressChangeShare = 0.50, MaxCountChangeShare = 0.50 }
        : new GeoAnomalyThresholds();
}

public static class GeoDiff
{
    public static GeoDiffResult Compare(RangeSet oldSet, RangeSet newSet)
    {
        ArgumentNullException.ThrowIfNull(oldSet);
        ArgumentNullException.ThrowIfNull(newSet);
        var added = newSet.Subtract(oldSet);
        var removed = oldSet.Subtract(newSet);
        return new GeoDiffResult(
            oldSet.Count,
            newSet.Count,
            oldSet.TotalAddresses,
            newSet.TotalAddresses,
            added.Count,
            removed.Count,
            added.TotalAddresses,
            removed.TotalAddresses);
    }

    /// <summary>Резкое изменение относительно рабочей базы. Первая база аномалией не считается.</summary>
    public static bool IsAnomalous(GeoDiffResult diff, GeoAnomalyThresholds thresholds)
    {
        ArgumentNullException.ThrowIfNull(diff);
        ArgumentNullException.ThrowIfNull(thresholds);
        if (diff.OldRangeCount == 0)
        {
            return false;
        }

        return diff.AddressChangeShare > thresholds.MaxAddressChangeShare
            || diff.CountChangeShare > thresholds.MaxCountChangeShare;
    }
}
