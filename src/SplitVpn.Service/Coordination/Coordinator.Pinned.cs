using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    /// <summary>Сколько ждать применения маршрута, прежде чем всё-таки отдать ответ DNS.</summary>
    private static readonly TimeSpan PinApplyTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Адреса, полученные по правилу для домена. Маршрут и фильтр ставятся до того, как ответ DNS
    /// уйдёт клиенту: иначе первое соединение успело бы уйти не по назначенному пути.
    /// </summary>
    internal async ValueTask ObservePinnedAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(notice);
        var expires = _deps.Time.GetUtcNow() + notice.Ttl;
        var changed = false;
        foreach (var address in notice.Addresses)
        {
            var known = Facts.Pinned.TryGetValue(address, out var existing) && existing.Target == notice.Target;
            Facts.Pinned[address] = new PinnedRoute(notice.Target, known && existing!.ExpiresUtc > expires ? existing.ExpiresUtc : expires);
            changed |= !known;
        }

        if (!changed || _state.Intent == Core.State.Intent.Off || _state.ProtectionSuspended)
        {
            return;
        }

        var applied = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await EnqueueAsync("Pinned", () =>
        {
            try
            {
                EnsureRoutesSafe();
            }
            finally
            {
                applied.TrySetResult();
            }

            return Task.CompletedTask;
        });

        try
        {
            await applied.Task.WaitAsync(PinApplyTimeout, cancellationToken);
        }
        catch (TimeoutException)
        {
            // Актор занят: ответ DNS уходит сразу, маршрут появится следующим шагом сверки.
        }
    }

    /// <summary>Снимает закрепления с истёкшим сроком. true — набор изменился и нужна сверка.</summary>
    private bool DropExpiredPins(DateTimeOffset now)
    {
        var expired = Facts.Pinned.Where(p => p.Value.ExpiresUtc <= now).Select(p => p.Key).ToList();
        foreach (var address in expired)
        {
            Facts.Pinned.TryRemove(address, out _);
        }

        return expired.Count > 0;
    }
}

/// <summary>Мост от DNS-посредника к координатору.</summary>
public sealed class CoordinatorRouteSink(Coordinator coordinator) : IPinnedRouteSink
{
    public ValueTask ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) =>
        coordinator.ObservePinnedAsync(notice, cancellationToken);
}
