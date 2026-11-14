using Microsoft.Extensions.Logging;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Два автообновляемых списка адресов: RU-база и список обхода блокировок. Устройство у них одно
/// (хранилище версий, проверка, откат, подтверждение), различаются источник, пороги проверки и цель.
/// </summary>
public sealed partial class Coordinator
{
    internal Task GeoWork => Task.WhenAll(_geo.FetchWork, _bypass.FetchWork);

    /// <summary>Менеджер запрошенного списка; без указания — RU-база.</summary>
    private GeoManager List(GeoListRequest request) =>
        request.List == GeoListKind.Bypass ? _bypass : _geo;

    /// <summary>
    /// Куда идут адреса из списка обхода блокировок. Без загруженного списка и без своей цели —
    /// туда же, куда «остальной интернет»: тогда слой ничего не меняет.
    /// </summary>
    internal RouteTarget BypassTarget =>
        _bypass.HasBase && _settings.BypassTarget is { } target ? target : _settings.DefaultTarget;

    private (RangeSet Bypass, RangeSet Geo, int Prefix, RangeSet Result)? _bypassForPolicy;

    /// <summary>
    /// Список обхода в том виде, в каком он идёт в политику: свёрнутый до подсетей без адресов RU-базы.
    /// Результат запоминается: кеш компиляции сравнивает наборы по ссылке, и новая ссылка на каждой
    /// сверке пересобирала бы всю политику.
    /// </summary>
    internal RangeSet BypassForPolicy()
    {
        var bypass = _bypass.ActiveSet;
        var geo = _geo.ActiveSet;
        var prefix = _settings.BypassAggregatePrefix;
        if (_bypassForPolicy is { } cached && ReferenceEquals(cached.Bypass, bypass) && ReferenceEquals(cached.Geo, geo) && cached.Prefix == prefix)
        {
            return cached.Result;
        }

        var result = BypassAggregation.Aggregate(bypass, geo, prefix);
        if (!ReferenceEquals(result, bypass) && _deps.Logger.IsEnabled(LogLevel.Information))
        {
            _deps.Logger.LogInformation("Список обхода свёрнут до /{Prefix}: диапазонов {Before} → {After}, адресов {BeforeAddresses} → {AfterAddresses}",
                prefix, bypass.Count, result.Count, bypass.TotalAddresses, result.TotalAddresses);
        }

        _bypassForPolicy = (bypass, geo, prefix, result);
        return result;
    }

    private GeoListStatusDto BuildListStatus(GeoManager list)
    {
        var state = list.StoreState;
        return new GeoListStatusDto
        {
            List = list.Kind,
            TargetName = _settings.TargetName(BypassTarget),
            FollowsDefault = _settings.BypassTarget is null,
            Revision = state.Active,
            DownloadedUtc = list.ActiveRevision?.DownloadedUtc,
            V4Count = list.ActiveRevision?.V4Count ?? 0,
            V6Count = list.ActiveRevision?.V6Count ?? 0,
            PendingRevision = state.Pending,
            PendingReason = state.PendingReason,
            LastCheckUtc = state.LastCheckUtc,
            NextCheckUtc = state.NextCheckUtc,
            LastResult = state.LastResult,
            SkippedCount = state.Skipped.Count,
        };
    }

    /// <summary>Версия списка обхода блокировок ждёт решения пользователя — как и у RU-базы.</summary>
    private IEnumerable<StatusWarning> BypassWarnings()
    {
        if (_bypass.StoreState is { Pending: not null } state)
        {
            yield return new StatusWarning("bypass-pending",
                "Новый список обхода блокировок ждёт подтверждения: " + state.PendingReason, "geo-review");
        }
    }
}
