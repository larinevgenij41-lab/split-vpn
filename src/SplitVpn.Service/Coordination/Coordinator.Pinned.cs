using Microsoft.Extensions.Logging;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    /// <summary>Сколько ответ DNS ждёт применения маршрута, прежде чем стать отказом.</summary>
    private static readonly TimeSpan PinApplyTimeout = TimeSpan.FromSeconds(2);

    private readonly Lock _pinGate = new();

    /// <summary>
    /// Желаемые закрепления: их пишут потоки DNS-посредника. Применённые лежат в <see cref="CoordinatorFacts.Pinned"/>
    /// и меняются только в очереди актора — иначе маршруты, фильтры и ответ DNS видят разные наборы.
    /// </summary>
    private readonly Dictionary<uint, PinnedRoute> _desiredPins = [];

    /// <summary>Номер последнего изменения желаемого набора и номера применённого и неудавшегося.</summary>
    private long _pinVersion;
    private long _appliedPinVersion;
    private long _failedPinVersion;

    /// <summary>Общее ожидание одной работы применения: параллельные запросы DNS ждут её вместе.</summary>
    private TaskCompletionSource? _pinApplied;
    private bool _pinWorkQueued;

    /// <summary>
    /// Адреса, полученные по правилу для домена. Маршрут и фильтр ставятся до того, как ответ DNS уйдёт
    /// клиенту: иначе первое соединение успело бы уйти не по назначенному пути. Возвращает false, если
    /// применение не подтверждено, — тогда посредник отвечает отказом, а не адресом без защиты.
    /// </summary>
    internal async ValueTask<bool> ObservePinnedAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(notice);
        var expires = _deps.Time.GetUtcNow() + notice.Ttl;
        long version;
        lock (_pinGate)
        {
            foreach (var address in notice.Addresses)
            {
                var known = _desiredPins.TryGetValue(address, out var existing)
                    && existing.Target == notice.Target
                    && string.Equals(existing.Suffix, notice.Suffix, StringComparison.Ordinal);
                var deadline = known && existing.ExpiresUtc > expires ? existing.ExpiresUtc : expires;
                _desiredPins[address] = new PinnedRoute(notice.Target, deadline, notice.Suffix);
                if (!known)
                {
                    _pinVersion++;
                }
            }

            version = _pinVersion;
        }

        // Защиты нет: маршрут ничего не решает, ответ можно отдать сразу.
        return _state.Intent == Core.State.Intent.Off || _state.ProtectionSuspended
            || await WaitForPinsAsync(version, cancellationToken);
    }

    /// <summary>
    /// Ждёт, пока очередь применит набор с указанным номером. Все ожидающие делят одну работу: сотня
    /// ответов DNS подряд не даёт сотню полных пересборок политики.
    /// </summary>
    private async Task<bool> WaitForPinsAsync(long version, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            var schedule = false;
            lock (_pinGate)
            {
                if (_appliedPinVersion >= version)
                {
                    return true;
                }

                if (_failedPinVersion >= version)
                {
                    return false;
                }

                _pinApplied ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                wait = _pinApplied.Task;
                schedule = !_pinWorkQueued;
                _pinWorkQueued |= schedule;
            }

            if (schedule)
            {
                await EnqueueAsync("Pinned", ApplyPinsAsync);
            }

            try
            {
                await wait.WaitAsync(PinApplyTimeout, _deps.Time, cancellationToken);
            }
            catch (TimeoutException)
            {
                // Актор занят дольше, чем клиент готов ждать: маршрута ещё нет, отвечать адресом нельзя.
                return false;
            }
        }
    }

    /// <summary>Применяет желаемые закрепления. Ошибка применения — отказ ожидающим, а не молчаливый успех.</summary>
    private Task ApplyPinsAsync()
    {
        lock (_pinGate)
        {
            _pinWorkQueued = false;
        }

        var applied = false;
        try
        {
            EnsureRoutesSafe();
            applied = true;
        }
        catch (Exception ex) when (ex is Windows.Native.NativeCallException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            // Маршрут или фильтр не применились: ответ DNS уйдёт отказом, а полная сверка проверит всё заново.
            _deps.Logger.LogWarning(ex, "Закрепления по правилам для доменов не применены");
            Facts.ForceProtection = true;
        }
        finally
        {
            if (applied && !ProtectionActive)
            {
                // Политики ещё нет или защита снята: ставить нечего, и ждать ожидающим тоже нечего.
                lock (_pinGate)
                {
                    _promotedPinVersion = _pinVersion;
                }
            }

            CompletePins(applied);
        }

        return Task.CompletedTask;
    }

    private void CompletePins(bool applied)
    {
        lock (_pinGate)
        {
            if (applied)
            {
                _appliedPinVersion = Math.Max(_appliedPinVersion, _promotedPinVersion);
            }
            else
            {
                _failedPinVersion = Math.Max(_failedPinVersion, _pinVersion);
            }

            var waiters = _pinApplied;
            _pinApplied = null;
            waiters?.TrySetResult();
        }
    }

    /// <summary>Номер набора, попавшего в последнюю собранную политику.</summary>
    private long _promotedPinVersion;

    /// <summary>
    /// Переносит желаемые закрепления в применяемые. Вызывается из очереди актора перед сборкой политики:
    /// маршруты, фильтры и диагностика строятся по одному набору. Здесь же отзываются закрепления,
    /// у которых правило исчезло или сменило цель, — иначе прежний путь жил бы до конца TTL.
    /// </summary>
    private void PromotePins()
    {
        var now = _deps.Time.GetUtcNow();
        var rules = DomainTargets();
        lock (_pinGate)
        {
            foreach (var (address, pin) in _desiredPins.ToList())
            {
                if (pin.ExpiresUtc <= now || !StillRuled(rules, pin))
                {
                    _desiredPins.Remove(address);
                }
            }

            Facts.Pinned.Clear();
            foreach (var (address, pin) in _desiredPins)
            {
                Facts.Pinned[address] = pin;
            }

            _promotedPinVersion = _pinVersion;
        }
    }

    /// <summary>Правило, создавшее закрепление, всё ещё действует и ведёт туда же.</summary>
    private static bool StillRuled(Dictionary<string, RouteTarget> rules, PinnedRoute pin) =>
        rules.TryGetValue(pin.Suffix, out var target) && target == pin.Target;

    /// <summary>Действующие правила для доменов, которые закрепляют адреса: суффикс и его цель.</summary>
    private Dictionary<string, RouteTarget> DomainTargets()
    {
        var targets = new Dictionary<string, RouteTarget>(StringComparer.Ordinal);
        foreach (var route in BuildDomainRoutes().Where(r => r.PinAddresses))
        {
            targets.TryAdd(route.Suffix, route.Target);
        }

        return targets;
    }

    /// <summary>Закрепляет адрес за прямым выходом от имени правила для домена (узлы проверки отзыва).</summary>
    private void PinDirect(string suffix, uint address, DateTimeOffset expires)
    {
        lock (_pinGate)
        {
            _desiredPins[address] = new PinnedRoute(RouteTarget.Direct, expires, suffix);
            _pinVersion++;
        }
    }

    /// <summary>Снимает закрепления с истёкшим сроком. true — набор изменился и нужна сверка.</summary>
    private bool DropExpiredPins(DateTimeOffset now)
    {
        lock (_pinGate)
        {
            var expired = _desiredPins.Where(p => p.Value.ExpiresUtc <= now).Select(p => p.Key).ToList();
            foreach (var address in expired)
            {
                _desiredPins.Remove(address);
            }

            return expired.Count > 0;
        }
    }

    /// <summary>Снятие защиты: закрепления больше не нужны ни в желаемом наборе, ни в применённом.</summary>
    private void ClearPins()
    {
        lock (_pinGate)
        {
            _desiredPins.Clear();
            Facts.Pinned.Clear();
            _promotedPinVersion = _pinVersion;
            _appliedPinVersion = _pinVersion;
        }
    }
}

/// <summary>Мост от DNS-посредника к координатору.</summary>
public sealed class CoordinatorRouteSink(Coordinator coordinator) : IPinnedRouteSink
{
    public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) =>
        coordinator.ObservePinnedAsync(notice, cancellationToken);
}
