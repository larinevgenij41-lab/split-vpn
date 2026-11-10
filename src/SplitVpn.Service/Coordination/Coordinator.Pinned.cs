using Microsoft.Extensions.Logging;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    /// <summary>Сколько ответ DNS ждёт применения маршрута, прежде чем стать отказом.</summary>
    private static readonly TimeSpan PinApplyTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Предел новых IP из DNS: один домен с меняющимися ответами не должен заполнить память и таблицу маршрутов.</summary>
    internal const int MaxDomainPins = 10_000;

    private readonly Lock _pinGate = new();

    /// <summary>
    /// Желаемые закрепления: их пишут потоки DNS-посредника. Применённые лежат в <see cref="CoordinatorFacts.Pinned"/>
    /// и меняются только в очереди актора — иначе маршруты, фильтры и ответ DNS видят разные наборы.
    /// </summary>
    private readonly Dictionary<uint, List<PinnedRoute>> _desiredPins = [];
    private HashSet<uint> _dnsTransportAddresses = [];

    /// <summary>Номер последнего изменения желаемого набора и номера применённого и неудавшегося.</summary>
    private long _pinVersion;
    private long _appliedPinVersion;
    private long _failedPinVersion;

    /// <summary>Когда применение закреплений последний раз не удалось или повторялось.</summary>
    private DateTimeOffset _lastPinFailureUtc;

    /// <summary>Пауза между повторными применениями после сбоя: каждый запрос DNS не должен пересобирать политику.</summary>
    private static readonly TimeSpan PinRetryPause = TimeSpan.FromSeconds(5);

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
        var now = _deps.Time.GetUtcNow();
        var expires = now + notice.Ttl;
        long version;
        lock (_pinGate)
        {
            // Общий IP нельзя переназначить домену, если через него работает сам DNS-посредник.
            // Проверка всего ответа до записи не оставляет частичных закреплений.
            if (notice.IsCurrent?.Invoke() == false || !PinContextMatches(notice) || notice.Addresses.Any(_dnsTransportAddresses.Contains))
            {
                return false;
            }

            if ((long)_desiredPins.Count + notice.Addresses.Count > MaxDomainPins
                && notice.Addresses.Distinct().Count(a => !_desiredPins.ContainsKey(a)) > Math.Max(0, MaxDomainPins - _desiredPins.Count))
            {
                return false;
            }

            // Таблица маршрутов различает IP, но не домены. Нельзя перенаправлять уже выданный
            // адрес в другую цель. Проверяем весь ответ до записи, чтобы отказ не оставил часть адресов.
            var revocation = IsRevocationPin(notice.Suffix, notice.Target);
            if (revocation && notice.Suffix == ConnectivityCheckWebHost && !CanPinConnectivityCheck(notice.Addresses, now))
            {
                return false;
            }

            foreach (var address in notice.Addresses)
            {
                if (PinConflicts(address, notice.Target, revocation, now))
                {
                    return false;
                }
            }

            foreach (var address in notice.Addresses)
            {
                RememberPin(address, new PinnedRoute(notice.Target, expires, notice.Suffix, notice.LeaseId), now);
            }

            version = _pinVersion;
        }

        // Защиты нет: маршрут ничего не решает, ответ можно отдать сразу.
        if (_state.Intent == Core.State.Intent.Off || _state.ProtectionSuspended)
        {
            return true;
        }

        if (!await WaitForPinsAsync(version, cancellationToken))
        {
            return false;
        }

        // Пока ответ ждал очередь, правило могло исчезнуть, а набор — успешно примениться уже без него.
        lock (_pinGate)
        {
            var checkedAt = _deps.Time.GetUtcNow();
            if (!PinContextMatches(notice))
            {
                return false;
            }

            if (IsRevocationPin(notice.Suffix, notice.Target) && notice.Suffix == ConnectivityCheckWebHost
                && !CanPinConnectivityCheck(notice.Addresses, checkedAt))
            {
                return false;
            }

            return notice.Addresses.All(address => _desiredPins.TryGetValue(address, out var owners)
                && owners.Exists(p => p.Suffix == notice.Suffix && p.Target == notice.Target && p.ExpiresUtc > checkedAt));
        }
    }

    // Вызываются под _pinGate. У общего IP может быть несколько правил с одной целью и разными TTL.
    // Служебное закрепление узла проверки отзыва ни с чем не конфликтует: маршрут оно не ставит и адрес целиком не
    // выпускает, а лишь открывает TCP на порт ссылки через основной адаптер. Обычное закрепление того же адреса важнее
    // (см. PromotePins). Иначе адрес сети доставки, закреплённый правилом пользователя за туннелем, отклонял бы ответ
    // DNS для узла отзыва (дозвон падал бы на проверке отзыва), а служебное закрепление - правило пользователя.
    private bool PinConflicts(uint address, RouteTarget target, bool revocation, DateTimeOffset now) =>
        !revocation && _desiredPins.TryGetValue(address, out var owners)
        && owners.Exists(p => p.ExpiresUtc > now && p.Target != target && !IsRevocationPin(p.Suffix, p.Target));

    /// <summary>
    /// Закрепление от служебного правила узла проверки отзыва или веб-проверки интернета Windows
    /// (<see cref="ConnectivityCheckWebHost"/>): прямой выход по имени из последней сборки политики
    /// или из начального разрешения узла (<see cref="PinDirect"/>). Правило пользователя с тем же именем служебное
    /// правило отменяет, поэтому по суффиксу их не спутать. Вызывается под _pinGate.
    /// </summary>
    private bool IsRevocationPin(string suffix, RouteTarget target) =>
        target == RouteTarget.Direct && _revocationPinSuffixes.Contains(suffix);

    private void RememberPin(uint address, PinnedRoute pin, DateTimeOffset now, bool advanceVersion = true)
    {
        if (!_desiredPins.TryGetValue(address, out var owners))
        {
            _desiredPins[address] = owners = [];
        }

        owners.RemoveAll(p => p.ExpiresUtc <= now);
        var index = owners.FindIndex(p => p.Suffix == pin.Suffix && p.Target == pin.Target && p.LeaseId == pin.LeaseId);
        if (index >= 0)
        {
            var previous = owners[index];
            owners[index] = pin with { ExpiresUtc = previous.ExpiresUtc > pin.ExpiresUtc ? previous.ExpiresUtc : pin.ExpiresUtc };
            return;
        }

        // Новый ответ на уже закреплённый адрес ждёт ту же версию маршрута. Отдельный временный
        // владелец нужен для отмены, но не должен пересобирать политику на каждом попадании в DNS-кеш.
        var newRoute = !owners.Exists(p => p.Suffix == pin.Suffix && p.Target == pin.Target);
        owners.Add(pin);
        if (advanceVersion && newRoute) { _pinVersion++; }
    }

    /// <summary>
    /// Ответ становится выданным только после последней проверки конфигурации. Отмена удаляет его
    /// отдельного владельца: прежний ответ и параллельные запросы того же домена сохраняют свои TTL.
    /// </summary>
    internal async ValueTask<bool> CompletePinnedAsync(PinnedRouteNotice notice, bool accepted)
    {
        if (notice.LeaseId is not { } leaseId)
        {
            return accepted;
        }

        long version;
        var changed = false;
        lock (_pinGate)
        {
            var now = _deps.Time.GetUtcNow();
            accepted &= notice.IsCurrent?.Invoke() != false && PinContextMatches(notice)
                && notice.Addresses.All(a => _desiredPins.TryGetValue(a, out var owners)
                    && owners.Exists(p => p.LeaseId == leaseId && p.ExpiresUtc > now));
            foreach (var address in notice.Addresses.Distinct())
            {
                if (!_desiredPins.TryGetValue(address, out var owners)) { continue; }
                var pending = owners.Where(p => p.LeaseId == leaseId).ToArray();
                changed |= owners.RemoveAll(p => p.LeaseId == leaseId) > 0;
                if (accepted)
                {
                    foreach (var pin in pending)
                    {
                        RememberPin(address, pin with { LeaseId = null }, now, advanceVersion: false);
                    }
                }

                if (owners.Count == 0) { _desiredPins.Remove(address); }
            }

            // Смена временного владельца на постоянного не меняет маршрут. Отмена - меняет.
            if (changed && !accepted) { _pinVersion++; }
            version = _pinVersion;
        }

        if (changed && !accepted && ProtectionActive)
        {
            await WaitForPinsAsync(version, CancellationToken.None);
        }

        return accepted;
    }

    /// <summary>
    /// Ждёт, пока очередь применит набор с указанным номером. Все ожидающие делят одну работу: сотня
    /// ответов DNS подряд не даёт сотню полных пересборок политики.
    /// </summary>
    private async Task<bool> WaitForPinsAsync(long version, CancellationToken cancellationToken)
    {
        var retried = false;
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
                    // Набор уже не применился. Повторный ответ по тому же адресу номер не меняет, и без
                    // нового применения отказы шли бы до полной сверки. Одна попытка на ответ, не чаще паузы.
                    if (retried || _deps.Time.GetUtcNow() - _lastPinFailureUtc < PinRetryPause)
                    {
                        return false;
                    }

                    retried = true;
                    _lastPinFailureUtc = _deps.Time.GetUtcNow();
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
                _lastPinFailureUtc = _deps.Time.GetUtcNow();
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
        RefreshConnectivityCheckContext();
        var now = _deps.Time.GetUtcNow();
        var rules = DomainTargets(out var revocation);
        var dns = ServiceDnsAddresses().Concat(UpstreamDnsAddresses())
            .Concat(Facts.Tunnels.Values.SelectMany(t => TunnelDnsRoute(t)?.Servers.Select(s => Ipv4.ToUInt(s.Address)) ?? []))
            .ToHashSet();
        lock (_pinGate)
        {
            _dnsTransportAddresses = dns;
            _revocationPinSuffixes = new HashSet<string>(revocation, StringComparer.Ordinal);
            foreach (var (address, owners) in _desiredPins.ToList())
            {
                owners.RemoveAll(pin => dns.Contains(address) || pin.ExpiresUtc <= now || !StillRuled(rules, pin));
                if (owners.Count == 0)
                {
                    _desiredPins.Remove(address);
                }
            }

            Facts.Pinned.Clear();
            Facts.RevocationPins.Clear();
            foreach (var (address, owners) in _desiredPins)
            {
                // Служебное закрепление узла проверки отзыва не уводит адрес напрямую: защита открывает к нему только
                // порт ссылки. Обычное закрепление того же адреса важнее: правило пользователя решает судьбу адреса
                // целиком (прямой выход открывает и порт ссылки, туннель или блокировка - выбор пользователя), а
                // разрешение порта рядом с блокировкой того же адреса и того же веса не имело бы определённого исхода.
                var ordinary = owners.Where(p => !revocation.Contains(p.Suffix)).ToList();
                if (ordinary.Count > 0)
                {
                    Facts.Pinned[address] = ordinary.MaxBy(p => p.ExpiresUtc);
                }
                else
                {
                    Facts.RevocationPins[address] = owners.Select(p => p.Suffix).ToHashSet(StringComparer.Ordinal);
                }
            }

            _promotedPinVersion = _pinVersion;
        }

        // Проверка отзыва снова понадобилась (туннель лёг): Windows могла запомнить адрес узла, пока имя шло по общей
        // политике, и тогда не спросит посредника - закрепления по запросу не будет. Сброс кеша заставит спросить.
        if (revocation.Except(_revocationSuffixes).Any())
        {
            _deps.Dns.FlushCache();
        }

        _revocationSuffixes = revocation;
    }

    /// <summary>Имена узлов проверки отзыва, нужные при последней сборке политики.</summary>
    private HashSet<string> _revocationSuffixes = [];

    /// <summary>
    /// Имена узлов проверки отзыва для проверки конфликтов закреплений: читаются потоками DNS-посредника, поэтому
    /// меняются только под _pinGate. Сборка политики заменяет набор целиком, начальное разрешение узла дополняет его.
    /// </summary>
    private HashSet<string> _revocationPinSuffixes = new(StringComparer.Ordinal);

    /// <summary>Правило, создавшее закрепление, всё ещё действует и ведёт туда же.</summary>
    private static bool StillRuled(Dictionary<string, RouteTarget> rules, PinnedRoute pin) =>
        rules.TryGetValue(pin.Suffix, out var target) && target == pin.Target;

    /// <summary>Действующие правила для доменов, которые закрепляют адреса: суффикс и его цель.</summary>
    /// <param name="revocation">Из них служебные - узлы проверки отзыва, которые сейчас нужны.</param>
    private Dictionary<string, RouteTarget> DomainTargets(out HashSet<string> revocation)
    {
        var targets = new Dictionary<string, RouteTarget>(StringComparer.Ordinal);
        foreach (var route in BuildDomainRoutes(out revocation).Where(r => r.PinAddresses))
        {
            targets.TryAdd(route.Suffix, route.Target);
        }

        return targets;
    }

    /// <summary>
    /// Служебное закрепление адресов узла проверки отзыва за прямым выходом. С закреплениями других целей оно не
    /// конфликтует (см. <see cref="PinConflicts"/>). Адреса DNS-посредника запрещены; для проверки интернета Windows
    /// дополнительно проверяется лимит публичных адресов.
    /// </summary>
    private bool PinDirect(string suffix, IReadOnlyList<uint> addresses, DateTimeOffset expires)
    {
        lock (_pinGate)
        {
            var now = _deps.Time.GetUtcNow();
            if (addresses.Any(_dnsTransportAddresses.Contains))
            {
                return false;
            }

            if (suffix == ConnectivityCheckWebHost && !CanPinConnectivityCheck(addresses, now))
            {
                return false;
            }

            // Сборка политики могла ещё не видеть этот узел: без отметки его закрепление до неё отклоняло бы правила пользователя.
            _revocationPinSuffixes.Add(suffix);
            foreach (var address in addresses)
            {
                RememberPin(address, new PinnedRoute(RouteTarget.Direct, expires, suffix), now);
            }

            return true;
        }
    }

    /// <summary>Снимает закрепления с истёкшим сроком. true — набор изменился и нужна сверка.</summary>
    private bool DropExpiredPins(DateTimeOffset now)
    {
        lock (_pinGate)
        {
            var changed = false;
            foreach (var owners in _desiredPins.Values)
            {
                changed |= owners.RemoveAll(p => p.ExpiresUtc <= now) > 0;
            }

            if (changed)
            {
                foreach (var address in _desiredPins.Where(p => p.Value.Count == 0).Select(p => p.Key).ToArray())
                {
                    _desiredPins.Remove(address);
                }
            }

            return changed;
        }
    }

    /// <summary>Снятие защиты: закрепления больше не нужны ни в желаемом наборе, ни в применённом.</summary>
    private void ClearPins()
    {
        lock (_pinGate)
        {
            _desiredPins.Clear();
            Facts.Pinned.Clear();
            Facts.RevocationPins.Clear();
            _revocationPinSuffixes = new(StringComparer.Ordinal);
            _promotedPinVersion = _pinVersion;
            _appliedPinVersion = _pinVersion;
            ResetConnectivityCheckContext();
        }

        _revocationSuffixes = [];
    }
}

/// <summary>Мост от DNS-посредника к координатору.</summary>
public sealed class CoordinatorRouteSink(Coordinator coordinator) : IPinnedRouteSink
{
    public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) =>
        coordinator.ObservePinnedAsync(notice, cancellationToken);

    public ValueTask<bool> CompleteAsync(PinnedRouteNotice notice, bool accepted) =>
        coordinator.CompletePinnedAsync(notice, accepted);
}
