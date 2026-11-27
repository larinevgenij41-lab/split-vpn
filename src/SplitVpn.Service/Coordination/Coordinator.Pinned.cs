using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    /// <summary>Сколько ответ DNS ждёт применения маршрута, прежде чем стать отказом.</summary>
    private static readonly TimeSpan PinApplyTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// То же для веб-проверки интернета Windows. Отказ здесь - это сеть «без интернета» и сброс Wi-Fi через ~30 с,
    /// а маршрута этот ответ не ставит, поэтому он ждёт дольше обычного, но меньше, чем клиент DNS Windows ждёт ответа.
    /// </summary>
    internal static readonly TimeSpan ConnectivityPinApplyTimeout = TimeSpan.FromSeconds(8);

    /// <summary>Предел новых IP из DNS: один домен с меняющимися ответами не должен заполнить память и таблицу маршрутов.</summary>
    internal const int MaxDomainPins = 10_000;

    private readonly Lock _pinGate = new();

    /// <summary>
    /// Желаемые закрепления: их пишут потоки DNS-посредника. Применённые лежат в <see cref="CoordinatorFacts.Pinned"/>
    /// и меняются только в очереди актора — иначе маршруты, фильтры и ответ DNS видят разные наборы.
    /// </summary>
    private DateTimeOffset _nextPinExpiry = DateTimeOffset.MaxValue;
    private readonly HashSet<uint> _warmConnectivityAddresses = [];
    private readonly Dictionary<uint, List<PinnedRoute>> _desiredPins = [];
    private Dictionary<string, RoutePriority> _manualPriorities = new(StringComparer.OrdinalIgnoreCase);
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
    internal async ValueTask<bool> ObservePinnedAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) =>
        await ObservePinnedCoreAsync(notice, partial: false, cancellationToken) is not null;

    /// <summary>
    /// Как <see cref="ObservePinnedAsync"/>, но адрес, который закрепить нельзя (отказ политики, конфликт с другой целью,
    /// адрес DNS-посредника, предел закреплений), не отклоняет весь ответ: возвращаются принятые адреса, и посредник
    /// вырезает остальные записи A из ответа клиенту. null - не принят ни один адрес или применение не подтверждено.
    /// Служебные закрепления (узлы проверки отзыва, веб-проверка интернета Windows) - по-прежнему всё или ничего.
    /// </summary>
    internal ValueTask<IReadOnlyList<uint>?> ObservePinnedPartialAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) =>
        ObservePinnedCoreAsync(notice, partial: true, cancellationToken);

    private async ValueTask<IReadOnlyList<uint>?> ObservePinnedCoreAsync(PinnedRouteNotice notice, bool partial, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(notice);
        long version;
        List<uint> accepted;
        lock (_pinGate)
        {
            // Срок - по часам, проверенным на скачок под тем же замком: перевод назад между этим ответом и ближайшей
            // работой актора не сдвинет его второй раз (и не снимет маршрут, едва поставленный).
            var now = ClockNowLocked();
            var expires = now + notice.Ttl;

            // Таблица маршрутов различает IP, но не домены. Нельзя перенаправлять уже выданный
            // адрес в другую цель. Проверяем весь ответ до записи, чтобы отказ не оставил часть адресов.
            var revocation = IsRevocationPin(notice.Suffix, notice.Target);
            partial &= !revocation;

            // Общий IP нельзя переназначить домену, если через него работает сам DNS-посредник.
            // Проверка до записи не оставляет частичных закреплений: отклонённый адрес не записывается вовсе.
            if (notice.IsCurrent?.Invoke() == false || !PinContextMatches(notice)
                || !MatchesManualRule(notice.Suffix, notice.Name)
                || notice.Origins?.Any(origin => !MatchesManualRule(notice.Suffix, origin)) == true
                || (!partial && notice.Addresses.Any(_dnsTransportAddresses.Contains)))
            {
                if (notice.Suffix == ConnectivityCheckWebHost)
                {
                    LogConnectivityRefusal(!PinContextMatches(notice) ? "ответ относится к прежнему пути DNS" : "политика сменилась или адрес занят DNS", now);
                }

                return null;
            }

            accepted = notice.Addresses.Where(a => !_dnsTransportAddresses.Contains(a)).Distinct().ToList();

            // Адрес, который политика не закрепит (запрет пользователя, CIDR-правило с более высоким приоритетом, сеть шлюза,
            // зарезервированный диапазон), программе не отдаётся: иначе её трафик пошёл бы мимо правила для домена.
            if (!revocation && RejectedByPolicy(notice, accepted, partial, now))
            {
                return null;
            }

            var connectivity = revocation && notice.Suffix == ConnectivityCheckWebHost;
            if (connectivity && !CanPinConnectivityCheck(notice.Addresses, now))
            {
                LogConnectivityRefusal($"выдано уже больше {MaxConnectivityCheckAddresses} адресов или адрес не публичный", now);
                return null;
            }

            var usable = new List<uint>(accepted.Count);
            foreach (var address in accepted)
            {
                if (_desiredPins.TryGetValue(address, out var owners) && owners.Count + (notice.Origins?.Count ?? 1) > 512
                    && (owners.Count(p => p.ExpiresUtc > now) > 1024 ||
                        owners.Where(p => p.ExpiresUtc > now)
                            .Select(p => (p.Suffix, p.Target, p.Name?.ToUpperInvariant(), p.Origin?.ToUpperInvariant()))
                            .Concat((notice.Origins is { Count: > 0 } origins ? origins.Cast<string?>() : [null]).Select(origin =>
                                (notice.Suffix, notice.Target, notice.Name?.ToUpperInvariant(), origin?.ToUpperInvariant())))
                            .Distinct().Take(513).Count() > 512))
                {
                    if (!partial) return null;
                    continue;
                }

                // Продлённое закрепление (TTL истёк, держится ради открытых соединений) конфликта не создаёт: см. PinConflicts.
                if (PinConflicts(address, notice.Target, revocation, now))
                {
                    if (notice.Suffix == ConnectivityCheckWebHost)
                    {
                        LogConnectivityRefusal("адрес закреплён правилом за другой целью", now);
                    }

                    if (!partial) return null;
                    continue;
                }

                usable.Add(address);
            }

            accepted = usable;
            if (!FitPinLimits(notice, accepted, partial, revocation, now) || accepted.Count == 0 && notice.Addresses.Count > 0)
            {
                return null;
            }

            // Снятие прогрева этот ответ не ждёт: лишний разрешающий фильтр до следующего применения безвреден,
            // а ответ с уже открытыми адресами уходит сразу.
            if (connectivity)
            {
                DropWarmConnectivityPins(notice.Addresses);
            }

            if (!revocation)
            {
                YieldLingeringPins(accepted, notice.Target, now);
            }

            foreach (var address in accepted)
            {
                var pin = new PinnedRoute(notice.Target, expires, notice.Suffix, notice.LeaseId, Name: notice.Name);
                if (notice.Origins is { Count: > 0 } origins)
                {
                    foreach (var origin in origins) { RememberPin(address, pin with { Origin = origin }, now); }
                }
                else
                {
                    RememberPin(address, pin, now);
                }
            }

            // Готовность решается по адресам этого ответа, а не по общему номеру набора. Иначе ответ с уже открытыми
            // адресами ждал чужое закрепление (ответ другой программы при запуске Windows), очередь была занята
            // дозвоном, и проверка интернета Windows получала отказ DNS - сброс Wi-Fi через ~30 с.
            if (_promotedPinsApplied && accepted.All(address => IsPinApplied(address, notice, revocation, now)))
            {
                return accepted;
            }

            version = _pinVersion;
        }

        // Защиты нет: маршрут ничего не решает, ответ можно отдать сразу.
        if (_state.Intent == Core.State.Intent.Off || _state.ProtectionSuspended)
        {
            return accepted;
        }

        var connectivityCheck = notice.Suffix == ConnectivityCheckWebHost;
        if (!await WaitForPinsAsync(version, cancellationToken, connectivityCheck ? ConnectivityPinApplyTimeout : PinApplyTimeout))
        {
            if (connectivityCheck)
            {
                // Отказ ведёт к сбросу Wi-Fi через ~30 с: без этой строки причину в журнале не найти.
                _deps.Logger.LogWarning("Ответ DNS для проверки интернета Windows отклонён: адрес не открыт вовремя (очередь службы занята или применение не удалось)");
            }

            return null;
        }

        // Пока ответ ждал очередь, правило могло исчезнуть, а набор — успешно примениться уже без него.
        lock (_pinGate)
        {
            var checkedAt = ClockNowLocked();
            if (!PinContextMatches(notice))
            {
                return null;
            }

            if (IsRevocationPin(notice.Suffix, notice.Target) && notice.Suffix == ConnectivityCheckWebHost
                && !CanPinConnectivityCheck(notice.Addresses, checkedAt))
            {
                return null;
            }

            var still = accepted.Where(address => _desiredPins.TryGetValue(address, out var owners)
                && owners.Exists(p => p.Suffix == notice.Suffix && p.Target == notice.Target && p.ExpiresUtc > checkedAt)).ToList();
            return still.Count == accepted.Count ? accepted : partial && still.Count > 0 ? still : null;
        }
    }

    // Вызываются под _pinGate. У общего IP может быть несколько правил с одной целью и разными TTL.
    // Служебное закрепление узла проверки отзыва ни с чем не конфликтует: маршрут оно не ставит и адрес целиком не
    // выпускает, а лишь открывает TCP на порт ссылки через основной адаптер. Обычное закрепление того же адреса важнее
    // (см. PromotePins). Иначе адрес сети доставки, закреплённый правилом пользователя за туннелем, отклонял бы ответ
    // DNS для узла отзыва (дозвон падал бы на проверке отзыва), а служебное закрепление - правило пользователя.
    // Закрепление, которое политика молча не применяет (служебный адрес, «напрямую» на адресе локальной сети), маршрута
    // не ставит и потому ни с чем не конфликтует. Продлённое (TTL истёк, держится ради открытых соединений) тоже не
    // конфликтует: оно уступает адрес новому ответу (YieldLingeringPins), иначе второй домен на общем адресе сети
    // доставки не разрешался бы, пока у первого живо хоть одно соединение.
    private bool PinConflicts(uint address, RouteTarget target, bool revocation, DateTimeOffset now) =>
        !revocation && _desiredPins.TryGetValue(address, out var owners)
        && owners.Exists(p => p.ExpiresUtc > now && p.Target != target && !IsRevocationPin(p.Suffix, p.Target) && !PinIgnored(address, p.Target));

    /// <summary>
    /// Последняя собранная политика для проверок под _pinGate: потоки DNS-посредника оценивают по ней закрепления до
    /// записи (<see cref="CompiledPolicy.EvaluatePin"/>). null - защиты нет, проверять не по чему.
    /// </summary>
    private CompiledPolicy? _pinPolicy;

    /// <summary>Политика молча не закрепляет адрес за этой целью (см. <see cref="CompiledPolicy.IgnoredPins"/>). Под _pinGate.</summary>
    private bool PinIgnored(uint address, RouteTarget target) =>
        _pinPolicy?.EvaluatePin(new PinnedHost(address, target)) is (false, null);

    /// <summary>Действующий приоритет правила для домена. Под _pinGate.</summary>
    private RoutePriority PinPriority(string suffix) => _manualPriorities.GetValueOrDefault(suffix, RoutePriority.Normal);

    /// <summary>
    /// Отказы в закреплении для предупреждения на главной: пара «правило, причина», последний адрес и время. Под _pinGate.
    /// Записей немного (<see cref="MaxRejectedPinWarnings"/>), каждая живёт час после последнего отказа и снимается раньше,
    /// если правило исчезло, сменило цель или политика теперь адрес примет.
    /// </summary>
    private readonly Dictionary<(string Suffix, string Reason), RejectedPinWarning> _rejectedPinWarnings = [];

    internal const int MaxRejectedPinWarnings = 20;

    private static readonly TimeSpan RejectedPinWarningLifetime = TimeSpan.FromHours(1);

    /// <summary>Отказ, о котором ещё не сказано в журнале. Под _pinGate; журнал пишет очередь актора.</summary>
    private readonly List<(string Suffix, string Reason)> _rejectedPinJournal = [];

    /// <summary>
    /// Адреса ответа, закрепление которых политика отклонит, убираются из <paramref name="addresses"/>, отказ попадает в
    /// предупреждения. true - ответ не отдаётся вовсе (SERVFAIL): отклонён хоть один адрес, а частичный ответ не разрешён.
    /// Вызывается под _pinGate.
    /// </summary>
    private bool RejectedByPolicy(PinnedRouteNotice notice, List<uint> addresses, bool partial, DateTimeOffset now)
    {
        if (_pinPolicy is not { } policy)
        {
            return false;
        }

        var priority = PinPriority(notice.Suffix);
        for (var i = 0; i < addresses.Count; i++)
        {
            var address = addresses[i];
            if (policy.EvaluatePin(new PinnedHost(address, notice.Target, priority)) is (false, { } reason))
            {
                RememberRejectedPin(notice.Suffix, reason, new PinnedHost(address, notice.Target, priority), now);
                if (!partial)
                {
                    return true;
                }

                addresses.RemoveAt(i--);
            }
        }

        return false;
    }

    /// <summary>Предел закреплений на одно правило для домена (суффикс): одно правило не съедает общий предел.</summary>
    internal const int MaxPinsPerRule = 2000;

    /// <summary>
    /// Пределы числа адресов: доля правила (<see cref="MaxPinsPerRule"/>, только обычные закрепления) и общий
    /// (<see cref="MaxDomainPins"/>). При нехватке общего места первыми вытесняются продлённые закрепления (TTL истёк,
    /// держатся ради открытых соединений). Лишние новые адреса убираются из <paramref name="addresses"/> (частичный
    /// ответ) или ответ отклоняется целиком (false). Отказ - только этому правилу; о нём - предупреждение и журнал.
    /// Вызывается под _pinGate.
    /// </summary>
    private bool FitPinLimits(PinnedRouteNotice notice, List<uint> addresses, bool partial, bool revocation, DateTimeOffset now)
    {
        if (!revocation)
        {
            // Счёт по всему набору нужен, только если правило вообще может выйти за долю: обычный ответ его не платит.
            var fresh = addresses.Where(a => !_desiredPins.TryGetValue(a, out var owners)
                || !owners.Exists(p => p.Suffix == notice.Suffix && p.ExpiresUtc > now)).ToList();
            if (fresh.Count > 0 && (long)_desiredPins.Count + fresh.Count > MaxPinsPerRule)
            {
                var used = _desiredPins.Values.Count(owners => owners.Exists(p => p.Suffix == notice.Suffix && p.ExpiresUtc > now));
                var room = Math.Max(0, MaxPinsPerRule - used);
                if (fresh.Count > room)
                {
                    RememberPinLimit(notice.Suffix, $"у правила уже {used} закреплённых адресов при пределе {MaxPinsPerRule}", now);
                    if (!partial)
                    {
                        return false;
                    }

                    var dropped = fresh.Skip(room).ToHashSet();
                    addresses.RemoveAll(dropped.Contains);
                }
            }
        }

        var added = addresses.Where(a => !_desiredPins.ContainsKey(a)).ToList();
        var free = Math.Max(0, MaxDomainPins - _desiredPins.Count);
        if (added.Count > free)
        {
            free += EvictLingeringPins(added.Count - free, addresses, now);
        }

        if (added.Count > free)
        {
            if (!revocation)
            {
                RememberPinLimit(notice.Suffix, $"занят общий предел {MaxDomainPins} закреплённых адресов", now);
            }

            if (!partial)
            {
                return false;
            }

            var dropped = added.Skip(free).ToHashSet();
            addresses.RemoveAll(dropped.Contains);
        }

        return true;
    }

    /// <summary>
    /// Вытесняет до <paramref name="count"/> адресов, у которых все закрепления продлённые (основной срок истёк), - самые
    /// старые первыми; адреса текущего ответа не трогаются. Возвращает число освобождённых мест. Под _pinGate.
    /// </summary>
    private int EvictLingeringPins(int count, List<uint> keep, DateTimeOffset now)
    {
        var victims = _desiredPins
            .Where(p => p.Value.TrueForAll(o => o.ExpiresUtc <= now && o.LeaseId is null) && !keep.Contains(p.Key))
            .OrderBy(p => p.Value.Count == 0 ? DateTimeOffset.MinValue : p.Value.Max(o => o.ExpiresUtc))
            .Take(count)
            .Select(p => p.Key)
            .ToList();
        foreach (var address in victims)
        {
            _desiredPins.Remove(address);
        }

        if (victims.Count > 0)
        {
            _pinVersion++;
        }

        return victims.Count;
    }

    /// <summary>
    /// Адрес отдаётся новому ответу с другой целью: продлённые закрепления этого адреса за прежней целью снимаются сразу.
    /// Маршрут различает только IP, и двух целей у адреса быть не может. Безопаснее уступить свежему ответу DNS, правило
    /// которого действует сейчас: оставленное продление увело бы новые соединения этого домена мимо его правила (а то и в
    /// открытую сеть), тогда как рвётся лишь старое соединение, чьё закрепление уже пережило TTL. Под _pinGate.
    /// </summary>
    private void YieldLingeringPins(List<uint> addresses, RouteTarget target, DateTimeOffset now)
    {
        foreach (var address in addresses)
        {
            if (_desiredPins.TryGetValue(address, out var owners)
                && owners.RemoveAll(p => p.ExpiresUtc <= now && p.LeaseId is null && p.Target != target && !IsRevocationPin(p.Suffix, p.Target)) > 0)
            {
                _pinVersion++;
            }
        }
    }

    /// <summary>Отказы по пределам числа адресов для предупреждения на главной: правило, причина и время. Под _pinGate.</summary>
    private readonly Dictionary<string, (string Reason, DateTimeOffset LastSeenUtc)> _pinLimitWarnings = new(StringComparer.Ordinal);

    /// <summary>Когда о пределе правила последний раз писалось в журнал; записи ждут очереди актора. Под _pinGate.</summary>
    private readonly Dictionary<string, DateTimeOffset> _pinLimitJournaledUtc = new(StringComparer.Ordinal);
    private readonly List<(string Suffix, string Reason)> _pinLimitJournal = [];

    /// <summary>О пределе одного правила журнал пишет не чаще этого: отказы идут на каждый ответ DNS.</summary>
    private static readonly TimeSpan PinLimitJournalInterval = TimeSpan.FromMinutes(10);

    private void RememberPinLimit(string suffix, string reason, DateTimeOffset now)
    {
        if (!_pinLimitWarnings.ContainsKey(suffix) && _pinLimitWarnings.Count >= MaxRejectedPinWarnings)
        {
            _pinLimitWarnings.Remove(_pinLimitWarnings.MinBy(p => p.Value.LastSeenUtc).Key);
        }

        _pinLimitWarnings[suffix] = (reason, now);
        if (_pinLimitJournaledUtc.TryGetValue(suffix, out var last) && now - last < PinLimitJournalInterval && now >= last)
        {
            return;
        }

        if (_pinLimitJournaledUtc.Count >= 1000)
        {
            _pinLimitJournaledUtc.Clear();
        }

        _pinLimitJournaledUtc[suffix] = now;
        if (_pinLimitJournal.Count < MaxRejectedPinWarnings)
        {
            _pinLimitJournal.Add((suffix, reason));
        }
    }

    /// <summary>Пишет в журнал отказы по пределам, накопленные потоками DNS-посредника. Только в очереди актора.</summary>
    private void JournalPinLimits()
    {
        List<(string Suffix, string Reason)> journal;
        lock (_pinGate)
        {
            if (_pinLimitJournal.Count == 0)
            {
                return;
            }

            journal = [.. _pinLimitJournal];
            _pinLimitJournal.Clear();
        }

        foreach (var (suffix, reason) in journal)
        {
            Journal("Предупреждение", $"Правило для домена «{suffix}»: новые адреса из ответов DNS не закрепляются ({reason}); "
                + "лишние адреса вырезаются из ответа, а ответ без единого закреплённого адреса уходит ошибкой DNS.");
        }
    }

    private void RememberRejectedPin(string suffix, string reason, PinnedHost pin, DateTimeOffset now)
    {
        var key = (suffix, reason);
        if (!_rejectedPinWarnings.ContainsKey(key))
        {
            if (_rejectedPinWarnings.Count >= MaxRejectedPinWarnings)
            {
                _rejectedPinWarnings.Remove(_rejectedPinWarnings.MinBy(p => p.Value.LastSeenUtc).Key);
            }

            if (_rejectedPinJournal.Count < MaxRejectedPinWarnings)
            {
                _rejectedPinJournal.Add(key);
            }
        }

        _rejectedPinWarnings[key] = new RejectedPinWarning(pin, now);
    }

    /// <summary>
    /// После сборки политики: закрепления, которые она отклонила с причиной, уходят из реестра (желаемого и применённого
    /// наборов). Иначе ожидающий ответ DNS подтвердился бы по реестру, а не по политике, отклонённый адрес держал бы
    /// конфликт с другими доменами и не давал служебному закреплению проверки отзыва открыть порт. Ожидающий этот адрес
    /// ответ получает отказ (SERVFAIL), отказ попадает в предупреждения.
    /// </summary>
    private void DropRejectedPins(CompiledPolicy policy)
    {
        List<(string Suffix, string Reason)> journal;
        lock (_pinGate)
        {
            var now = ClockNowLocked();
            _pinPolicy = policy;
            foreach (var rejected in policy.RejectedPins)
            {
                if (_desiredPins.TryGetValue(rejected.Address, out var owners))
                {
                    foreach (var owner in owners.Where(p => p.Target == rejected.Target && !IsRevocationPin(p.Suffix, p.Target)).ToList())
                    {
                        RememberRejectedPin(owner.Suffix, rejected.Reason, new PinnedHost(rejected.Address, rejected.Target, PinPriority(owner.Suffix)), now);
                    }

                    owners.RemoveAll(p => p.Target == rejected.Target && !IsRevocationPin(p.Suffix, p.Target));
                    if (owners.Count == 0)
                    {
                        _desiredPins.Remove(rejected.Address);
                    }
                    else if (!owners.Exists(p => !IsRevocationPin(p.Suffix, p.Target)))
                    {
                        Facts.RevocationPins[rejected.Address] = owners.Select(p => p.Suffix).ToHashSet(StringComparer.Ordinal);
                    }
                }

                Facts.Pinned.Remove(rejected.Address);
            }

            // Отказ, который политика больше не подтверждает (правило изменено), и устаревший - из предупреждений.
            foreach (var (key, warning) in _rejectedPinWarnings.ToList())
            {
                if (now - warning.LastSeenUtc > RejectedPinWarningLifetime || policy.EvaluatePin(warning.Pin) is not (false, { }))
                {
                    _rejectedPinWarnings.Remove(key);
                }
            }

            journal = [.. _rejectedPinJournal];
            _rejectedPinJournal.Clear();
        }

        foreach (var (suffix, reason) in journal)
        {
            if (_reportedRejectedPins.Count < 10_000 && _reportedRejectedPins.Add((suffix, reason)))
            {
                Journal("Предупреждение", $"Правило для домена «{suffix}»: адрес из ответа DNS не закреплён ({reason}); программа получает ошибку DNS.");
            }
        }
    }

    /// <summary>О каких отказах в закреплении (суффикс правила, причина) уже сказано в журнале.</summary>
    private readonly HashSet<(string Suffix, string Reason)> _reportedRejectedPins = [];

    /// <summary>Предупреждения об отказах в закреплении: правило и причина, без адресов и запрошенных имён.</summary>
    private List<StatusWarning> RejectedPinWarnings()
    {
        lock (_pinGate)
        {
            var now = ClockNowLocked();
            return _rejectedPinWarnings
                .Where(p => now - p.Value.LastSeenUtc <= RejectedPinWarningLifetime)
                .OrderByDescending(p => p.Value.LastSeenUtc)
                .Take(MaxRejectedPinWarnings)
                .Select(p => new StatusWarning("domain-pin-rejected",
                    $"Правило для домена «{p.Key.Suffix}»: адрес из ответа DNS не закреплён ({p.Key.Reason}). Программа получает ошибку DNS: "
                    + "иначе её трафик пошёл бы мимо правила. Измените правило для домена или адресное правило.", null))
                .Concat(_pinLimitWarnings
                    .Where(p => now - p.Value.LastSeenUtc <= RejectedPinWarningLifetime)
                    .OrderByDescending(p => p.Value.LastSeenUtc)
                    .Take(MaxRejectedPinWarnings)
                    .Select(p => new StatusWarning("domain-pin-limit",
                        $"Правило для домена «{p.Key}»: новые адреса из ответов DNS не закрепляются ({p.Value.Reason}). Лишние адреса "
                        + "вырезаются из ответа; если не остаётся ни одного, программа получает ошибку DNS. Сузьте правило "
                        + "(например, до нужных поддоменов).", null)))
                .ToList();
        }
    }

    /// <summary>
    /// Применённые наборы (<see cref="CoordinatorFacts.Pinned"/>, <see cref="CoordinatorFacts.RevocationPins"/>) совпадают с
    /// последним успешно применённым: сборка политики сбрасывает признак, успешное применение ставит. Меняется под _pinGate.
    /// </summary>
    private bool _promotedPinsApplied = true;

    /// <summary>
    /// Адрес уже открыт применённым набором так, как просит ответ: обычное закрепление ведёт в ту же цель, служебное -
    /// разрешает порт этого имени (или адрес целиком выпущен напрямую обычным закреплением). Вызывается под _pinGate.
    /// Маршрут различает только IP, поэтому для обычного закрепления важна цель, а не имя: другие цели исключает
    /// <see cref="PinConflicts"/>.
    /// </summary>
    private bool IsPinApplied(uint address, PinnedRouteNotice notice, bool revocation, DateTimeOffset now)
    {
        if (Facts.Pinned.TryGetValue(address, out var applied) && applied.ExpiresUtc > now)
        {
            return revocation ? applied.Target == RouteTarget.Direct : applied.Target == notice.Target;
        }

        return revocation && Facts.RevocationPins.TryGetValue(address, out var suffixes) && suffixes.Contains(notice.Suffix);
    }

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
        if (pin.ExpiresUtc < _nextPinExpiry) _nextPinExpiry = pin.ExpiresUtc;
        if (pin.Warm && pin.Suffix == ConnectivityCheckWebHost) _warmConnectivityAddresses.Add(address);
        if (!_desiredPins.TryGetValue(address, out var owners))
        {
            _desiredPins[address] = owners = [];
        }

        owners.RemoveAll(p => PinGone(address, p, now));
        var index = owners.FindIndex(p => p.Suffix == pin.Suffix && p.Target == pin.Target && p.LeaseId == pin.LeaseId && p.Warm == pin.Warm
            && string.Equals(p.Origin, pin.Origin, StringComparison.OrdinalIgnoreCase)
            && string.Equals(p.Name, pin.Name, StringComparison.OrdinalIgnoreCase));
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
    internal ValueTask<bool> CompletePinnedAsync(PinnedRouteNotice notice, bool accepted)
    {
        if (notice.LeaseId is not { } leaseId)
        {
            return ValueTask.FromResult(accepted);
        }

        var changed = false;
        bool connectivity;
        lock (_pinGate)
        {
            var now = ClockNowLocked();
            connectivity = notice.Suffix == ConnectivityCheckWebHost && IsRevocationPin(notice.Suffix, notice.Target);
            accepted &= notice.IsCurrent?.Invoke() != false && PinContextMatches(notice)
                && notice.Addresses.All(a => _desiredPins.TryGetValue(a, out var owners)
                    && owners.Exists(p => p.LeaseId == leaseId && p.ExpiresUtc > now));
            foreach (var address in notice.Addresses.Distinct())
            {
                if (!_desiredPins.TryGetValue(address, out var owners)) { continue; }
                var pending = owners.Where(p => p.LeaseId == leaseId).ToArray();
                owners.RemoveAll(p => p.LeaseId == leaseId);
                changed |= pending.Any(p => !owners.Exists(o => o.ExpiresUtc > now && o.Suffix == p.Suffix && o.Target == p.Target));
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
        }

        // Снятие ставится в очередь, но ответ его не ждёт. Наблюдение уже ждало применения до PinApplyTimeout, и ещё
        // столько же ожидания снятия задерживало отказ до 4 с: клиент DNS Windows за это время повторяет запрос по
        // всем серверам, и каждый повтор плодит новые временные закрепления. Дыры это не создаёт: клиент адреса не
        // получил, а временный маршрут ведёт туда же, куда правило этого домена, и снимется ближайшим применением.
        // Снятие разрешения порта веб-проверки очереди не требует вовсе: лишний разрешающий фильтр до следующего
        // применения безвреден.
        if (changed && !accepted && ProtectionActive && !connectivity)
        {
            SchedulePinApply();
        }

        return ValueTask.FromResult(accepted);
    }

    /// <summary>Ставит применение закреплений в очередь актора, если оно ещё не стоит там; не ждёт его.</summary>
    private void SchedulePinApply()
    {
        lock (_pinGate)
        {
            if (_pinWorkQueued)
            {
                return;
            }

            _pinWorkQueued = true;
        }

        if (!TryEnqueue("Pinned", ApplyPinsAsync))
        {
            // Очередь закрыта (служба останавливается): применять уже нечего.
            lock (_pinGate)
            {
                _pinWorkQueued = false;
            }
        }
    }

    /// <summary>
    /// Ждёт, пока очередь применит набор с указанным номером. Все ожидающие делят одну работу: сотня
    /// ответов DNS подряд не даёт сотню полных пересборок политики.
    /// </summary>
    private async Task<bool> WaitForPinsAsync(long version, CancellationToken cancellationToken, TimeSpan? timeout = null)
    {
        var started = _deps.Time.GetTimestamp();
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
                    var now = ClockNowLocked();
                    if (retried || now - _lastPinFailureUtc < PinRetryPause)
                    {
                        return false;
                    }

                    retried = true;
                    _lastPinFailureUtc = now;
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
                var remaining = (timeout ?? PinApplyTimeout) - _deps.Time.GetElapsedTime(started);
                if (remaining <= TimeSpan.Zero) return false;
                await wait.WaitAsync(remaining, _deps.Time, cancellationToken);
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
        // В очереди актора: перевод часов, замеченный здесь, сдвигает сроки актора сразу, а не в следующей работе.
        DetectClockJumpBack();
        lock (_pinGate)
        {
            if (applied)
            {
                _appliedPinVersion = Math.Max(_appliedPinVersion, _promotedPinVersion);
                _promotedPinsApplied = true;
            }
            else
            {
                _failedPinVersion = Math.Max(_failedPinVersion, _pinVersion);
                _lastPinFailureUtc = ClockNowLocked();
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
        var rules = DomainTargets(out var revocation, out var priorities, out var unavailable);
        var dns = ServiceDnsAddresses().Concat(UpstreamDnsAddresses())
            .Concat(Facts.Tunnels.Values.SelectMany(t => TunnelDnsRoute(t)?.Servers.Select(s => Ipv4.ToUInt(s.Address)) ?? []))
            .ToHashSet();
        DetectClockJumpBack();
        lock (_pinGate)
        {
            var now = ClockNowLocked();
            _manualPriorities = priorities;
            _dnsTransportAddresses = dns;
            _revocationPinSuffixes = new HashSet<string>(revocation, StringComparer.Ordinal);
            foreach (var (address, owners) in _desiredPins.ToList())
            {
                // Продлённое закрепление (TTL истёк, держится ради открытых соединений) снимается сразу, если правило
                // больше не ведёт в ту же цель (StillRuled): адрес, оставшийся «напрямую» после смены правила на «туннель»
                // или «блокировать», увёл бы трафик мимо нового правила. И если цель недоступна (туннель разорван): его
                // соединения уже мертвы, а держать адрес за лежащей целью незачем.
                owners.RemoveAll(pin => dns.Contains(address) || PinGone(address, pin, now) || !StillRuled(rules, pin)
                    || (pin.ExpiresUtc <= now && unavailable.Contains(pin.Suffix))
                    || !MatchesManualRule(pin.Suffix, pin.Name) || !MatchesManualRule(pin.Suffix, pin.Origin));
                if (owners.Count == 0)
                {
                    _desiredPins.Remove(address);
                }
            }

            // Предупреждение об отказе живёт, пока живо правило с той же целью.
            foreach (var key in _rejectedPinWarnings.Where(p => !rules.TryGetValue(p.Key.Suffix, out var target) || target != p.Value.Pin.Target)
                .Select(p => p.Key).ToList())
            {
                _rejectedPinWarnings.Remove(key);
            }

            Facts.Pinned.Clear();
            Facts.RevocationPins.Clear();
            _appliedPinPriorities.Clear();
            foreach (var (address, owners) in _desiredPins)
            {
                // Служебное закрепление узла проверки отзыва не уводит адрес напрямую: защита открывает к нему только
                // порт ссылки. Обычное закрепление того же адреса важнее: правило пользователя решает судьбу адреса
                // целиком (прямой выход открывает и порт ссылки, туннель или блокировка - выбор пользователя), а
                // разрешение порта рядом с блокировкой того же адреса и того же веса не имело бы определённого исхода.
                // Закрепление, которое политика молча не применяет («напрямую» на адресе локальной сети), уступает
                // применимому (в туннель): иначе оно заслонило бы его, и адрес ушёл бы мимо туннеля.
                var ordinary = owners.Where(p => !revocation.Contains(p.Suffix)).ToList();
                if (ordinary.Count > 0)
                {
                    var chosen = ordinary.OrderBy(p => PinIgnored(address, p.Target) ? 1 : 0).ThenBy(p => p.ExpiresUtc > now ? 0 : 1)
                        .ThenByDescending(p => p.ExpiresUtc).First();
                    Facts.Pinned[address] = chosen;
                    // Приоритет - наибольший среди правил этой цели: при равенстве с CIDR-правилом домен важнее.
                    _appliedPinPriorities[address] = ordinary.Where(p => p.Target == chosen.Target).Max(p => PinPriority(p.Suffix));
                }
                else
                {
                    Facts.RevocationPins[address] = owners.Select(p => p.Suffix).ToHashSet(StringComparer.Ordinal);
                }
            }

            _promotedPinVersion = _pinVersion;

            // Применённый набор собран заново из желаемого, сроки которого уже по текущим часам.
            _pendingAppliedPinShift = TimeSpan.Zero;

            // Набор ещё не применён: до успешного применения ответы DNS по нему не подтверждаются.
            _promotedPinsApplied = false;
        }

        // Проверка отзыва снова понадобилась (туннель лёг): Windows могла запомнить адрес узла, пока имя шло по общей
        // политике, и тогда не спросит посредника - закрепления по запросу не будет. Сброс кеша заставит спросить.
        if (revocation.Except(_revocationSuffixes).Any())
        {
            // Сбой сброса не должен обрывать сборку политики (иначе он повторялся бы на каждой сверке и защита не
            // перестраивалась): сброс повторит настройка посредника в этой же сверке.
            FlushDnsCacheSafely("проверка отзыва снова нужна");
        }

        _revocationSuffixes = revocation;
    }

    /// <summary>Имена узлов проверки отзыва, нужные при последней сборке политики.</summary>
    private HashSet<string> _revocationSuffixes = [];

    /// <summary>Приоритет правила для домена у применяемых закреплений (<see cref="CoordinatorFacts.Pinned"/>); меняется в очереди актора.</summary>
    private readonly Dictionary<uint, RoutePriority> _appliedPinPriorities = [];

    /// <summary>Входы политики по применяемым закреплениям: адрес, цель и приоритет правила для домена.</summary>
    private List<PinnedHost> PinnedHostsForPolicy() =>
        Facts.Pinned.Select(p => new PinnedHost(p.Key, p.Value.Target, _appliedPinPriorities.GetValueOrDefault(p.Key, RoutePriority.Normal))).ToList();

    /// <summary>
    /// Имена узлов проверки отзыва для проверки конфликтов закреплений: читаются потоками DNS-посредника, поэтому
    /// меняются только под _pinGate. Сборка политики заменяет набор целиком, начальное разрешение узла дополняет его.
    /// </summary>
    private HashSet<string> _revocationPinSuffixes = new(StringComparer.Ordinal);

    /// <summary>Правило, создавшее закрепление, всё ещё действует и ведёт туда же.</summary>
    private static bool StillRuled(Dictionary<string, RouteTarget> rules, PinnedRoute pin) =>
        rules.TryGetValue(pin.Suffix, out var target) && target == pin.Target;

    // Под _pinGate. Для CNAME без собственного правила проверяем исходный суффикс.
    private bool MatchesManualRule(string suffix, string? name)
    {
        if (name is null || !_manualPriorities.ContainsKey(suffix))
        {
            return true;
        }

        var winner = WinningSuffix(name.TrimEnd('.')) ?? WinningSuffix(suffix);
        return string.Equals(winner, suffix, StringComparison.OrdinalIgnoreCase);
    }

    private string? WinningSuffix(string name)
    {
        string? winner = null;
        var best = RoutePriority.Inherit;
        while (true)
        {
            if (_manualPriorities.TryGetValue(name, out var priority) && priority > best)
            {
                best = priority;
                winner = name;
            }

            var dot = name.IndexOf('.');
            if (dot < 0)
            {
                return winner;
            }

            name = name[(dot + 1)..];
        }
    }

    /// <summary>Действующие правила для доменов, которые закрепляют адреса: суффикс и его цель.</summary>
    /// <param name="revocation">Из них служебные - узлы проверки отзыва, которые сейчас нужны.</param>
    /// <param name="unavailable">Правила, цель которых сейчас недоступна (туннель не поднят, нет основного адаптера).</param>
    private Dictionary<string, RouteTarget> DomainTargets(out HashSet<string> revocation, out Dictionary<string, RoutePriority> priorities,
        out HashSet<string> unavailable)
    {
        priorities = new(StringComparer.OrdinalIgnoreCase);
        unavailable = new(StringComparer.Ordinal);
        var targets = new Dictionary<string, RouteTarget>(StringComparer.Ordinal);
        foreach (var route in BuildDomainRoutes(out revocation).Where(r => r.PinAddresses))
        {
            if (targets.TryAdd(route.Suffix, route.Target) && route.Unavailable)
            {
                unavailable.Add(route.Suffix);
            }

            if (route.Priority is { } priority)
            {
                priorities.TryAdd(route.Suffix, priority);
            }
        }

        return targets;
    }

    /// <summary>
    /// Служебное закрепление адресов узла проверки отзыва за прямым выходом. С закреплениями других целей оно не
    /// конфликтует (см. <see cref="PinConflicts"/>). Адреса DNS-посредника запрещены; для проверки интернета Windows
    /// дополнительно проверяется лимит публичных адресов.
    /// </summary>
    private bool PinDirect(string suffix, IReadOnlyList<uint> addresses, TimeSpan ttl)
    {
        lock (_pinGate)
        {
            var now = ClockNowLocked();
            var expires = now + ttl;
            if (addresses.Any(_dnsTransportAddresses.Contains))
            {
                return false;
            }

            var warm = suffix == ConnectivityCheckWebHost;
            if (warm && !CanPinConnectivityCheck(addresses, now))
            {
                return false;
            }

            // Новый прогрев заменяет прежний: иначе прежний час держал бы место в пределе адресов.
            if (warm)
            {
                DropWarmConnectivityPins(addresses);
            }

            // Сборка политики могла ещё не видеть этот узел: без отметки его закрепление до неё отклоняло бы правила пользователя.
            _revocationPinSuffixes.Add(suffix);
            foreach (var address in addresses)
            {
                RememberPin(address, new PinnedRoute(RouteTarget.Direct, expires, suffix, Warm: warm), now);
            }

            return true;
        }
    }

    /// <summary>
    /// Запас после TTL, в течение которого закрепление держится всегда: соединения UDP и QUIC (HTTP/3, видео, звонки)
    /// по системной таблице соединений не видны, а клиент продолжает слать их на адрес, полученный до истечения TTL.
    /// </summary>
    internal static readonly TimeSpan PinLingerGrace = TimeSpan.FromMinutes(5);

    /// <summary>Как часто после запаса проверяется, что к адресу продлённого закрепления ещё есть живые соединения TCP.</summary>
    internal static readonly TimeSpan PinLingerRecheck = TimeSpan.FromMinutes(1);

    /// <summary>Наибольшее продление после TTL: соединение, висящее сутки, не держит адрес вечно.</summary>
    internal static readonly TimeSpan MaxPinLinger = TimeSpan.FromHours(24);

    /// <summary>
    /// Наибольшее продление закрепления, которое выводит адрес из-под защиты: цель «напрямую», а адресная политика ведёт
    /// адрес в туннель или блокирует (<see cref="PinLeavesProtection"/>). Маршрут различает только IP, поэтому пока такое
    /// закрепление живо, мимо VPN идут и соединения других доменов с тем же адресом (общий адрес сети доставки), а
    /// продлевает его любое соединение к адресу. Предел - наибольший TTL записи (1 ч): окно утечки после истечения не
    /// больше того, что прежде давал один ответ DNS. Тот же предел - у закрепления с любой целью на адресе, который адресная
    /// политика блокирует. Остальное продление в туннель такого риска не несёт и живёт по <see cref="MaxPinLinger"/>.
    /// </summary>
    internal static readonly TimeSpan MaxUnprotectedPinLinger = TimeSpan.FromHours(1);

    /// <summary>Снимок таблицы соединений годится для всех решений в этих пределах: таблица не читается на каждом тике.</summary>
    private static readonly TimeSpan TcpSnapshotReuse = TimeSpan.FromSeconds(15);

    /// <summary>Последний снимок соединений TCP и его время по монотонным часам. Только в очереди актора.</summary>
    private IReadOnlySet<uint>? _tcpSnapshot;
    private long _tcpSnapshotTimestamp;
    private bool _tcpSnapshotTaken;
    private long _tcpFailureLoggedTimestamp;

    /// <summary>
    /// Закрепление может пережить TTL ради открытых соединений: обычное закрепление правила пользователя с выданным
    /// ответом. Служебные (узлы проверки отзыва, веб-проверка), заранее поставленные и ещё не выданные - нет. Под _pinGate.
    /// </summary>
    private bool CanLinger(PinnedRoute pin) =>
        pin.LeaseId is null && !pin.Warm && pin.Target.Kind is TargetKind.Direct or TargetKind.Tunnel or TargetKind.Group
        && !IsRevocationPin(pin.Suffix, pin.Target) && pin.Suffix != ConnectivityCheckWebHost;

    /// <summary>
    /// Закрепление снимается без решения о продлении: основной срок истёк, а продлить его нельзя или предел продления
    /// вышел. Продлённое и ещё не решённое снимает только <see cref="DropExpiredPins"/> (по таблице соединений), правило
    /// или его цель (<see cref="PromotePins"/>), уступка другому домену и вытеснение по пределу. Под _pinGate.
    /// </summary>
    private bool PinGone(uint address, PinnedRoute pin, DateTimeOffset now) =>
        pin.ExpiresUtc <= now && (!CanLinger(pin) || now >= pin.ExpiresUtc + MaxLinger(address, pin));

    /// <summary>Предел продления закрепления после TTL: короткий, если оно выводит адрес из-под защиты. Под _pinGate.</summary>
    private TimeSpan MaxLinger(uint address, PinnedRoute pin) =>
        PinLeavesProtection(address, pin) ? MaxUnprotectedPinLinger : MaxPinLinger;

    /// <summary>
    /// Закрепление «напрямую» на адресе, который адресная политика (без закреплений) не выпускает напрямую: ведёт в туннель,
    /// блокирует или это служебный адрес. Закрепление с любой целью на адресе, который адресная политика блокирует: правило
    /// домена сильнее, и заблокированный пользователем адрес доступен через туннель, пока живо закрепление. Адресная
    /// политика берётся из последней сборки (<see cref="_pinPolicy"/>); её нет - считается, что выводит (короткий предел
    /// безопаснее). Под _pinGate.
    /// </summary>
    private bool PinLeavesProtection(uint address, PinnedRoute pin) =>
        _pinPolicy is not { } policy
            ? pin.Target.Kind == TargetKind.Direct
            : policy.BlockRanges.Contains(address)
              || pin.Target.Kind == TargetKind.Direct && !policy.DirectRanges.Contains(address) && !policy.LocalRanges.Contains(address);

    /// <summary>
    /// Снимает закрепления с истёкшим сроком. Закрепление по правилу пользователя переживает TTL, пока к адресу могут идти
    /// уже открытые соединения: <see cref="PinLingerGrace"/> всегда (UDP и QUIC не видны), дальше - пока в таблице
    /// соединений TCP есть установленное соединение к адресу, но не дольше <see cref="MaxPinLinger"/> (закрепление, которое
    /// выводит адрес из-под защиты, - не дольше <see cref="MaxUnprotectedPinLinger"/>). Клиенту TTL
    /// по-прежнему обрезается по основному сроку: новые соединения идут через новый запрос DNS. true — набор изменился и
    /// нужна сверка.
    /// </summary>
    private bool DropExpiredPins()
    {
        DetectClockJumpBack();
        JournalPinLimits();
        DateTimeOffset now;
        bool needConnections;
        lock (_pinGate)
        {
            now = ClockNowLocked();
            if (now < _nextPinExpiry) return false;
            needConnections = _desiredPins.Any(entry => entry.Value.Exists(p => p.ExpiresUtc <= now && p.LingerUntilUtc <= now
                && !PinGone(entry.Key, p, now) && now >= p.ExpiresUtc + PinLingerGrace));
        }

        // Таблица читается вне замка (потоки DNS-посредника его ждут) и одним снимком на все закрепления.
        var connections = needConnections ? EstablishedConnections() : null;
        lock (_pinGate)
        {
            _nextPinExpiry = DateTimeOffset.MaxValue;
            var changed = false;
            foreach (var (address, owners) in _desiredPins)
            {
                for (var i = owners.Count - 1; i >= 0; i--)
                {
                    var pin = owners[i];
                    if (pin.ExpiresUtc > now || pin.LingerUntilUtc > now)
                    {
                        continue;
                    }

                    if (LingerUntil(pin, address, now, connections) is { } until)
                    {
                        owners[i] = pin with { LingerUntilUtc = until };
                    }
                    else
                    {
                        owners.RemoveAt(i);
                        changed = true;
                    }
                }

                foreach (var owner in owners)
                {
                    var due = owner.ExpiresUtc > now ? owner.ExpiresUtc : owner.LingerUntilUtc;
                    if (due < _nextPinExpiry) _nextPinExpiry = due;
                }
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

    /// <summary>
    /// До какого времени держать закрепление с истёкшим TTL; null - снять. Нет сведений о соединениях (таблица не
    /// прочитана) - снимается, как до продления: держать адрес вслепую до суток хуже. Под _pinGate.
    /// </summary>
    private DateTimeOffset? LingerUntil(PinnedRoute pin, uint address, DateTimeOffset now, IReadOnlySet<uint>? connections)
    {
        if (PinGone(address, pin, now))
        {
            return null;
        }

        var limit = pin.ExpiresUtc + MaxLinger(address, pin);
        var grace = pin.ExpiresUtc + PinLingerGrace;
        if (now < grace)
        {
            return grace < limit ? grace : limit;
        }

        if (connections is null || !connections.Contains(address))
        {
            return null;
        }

        var next = now + PinLingerRecheck;
        return next < limit ? next : limit;
    }

    /// <summary>
    /// Удалённые адреса установленных соединений TCP. Снимок переиспользуется <see cref="TcpSnapshotReuse"/>: закрепления
    /// с разными сроками не читают таблицу на каждом тике. Сбой чтения - null (и запись в журнал не чаще раза в 10 минут).
    /// Только в очереди актора.
    /// </summary>
    private IReadOnlySet<uint>? EstablishedConnections()
    {
        if (_tcpSnapshotTaken && _deps.Time.GetElapsedTime(_tcpSnapshotTimestamp) < TcpSnapshotReuse)
        {
            return _tcpSnapshot;
        }

        IReadOnlySet<uint>? snapshot;
        try
        {
            snapshot = _deps.EstablishedTcpRemotes();
        }
        catch (Exception ex) when (ex is Windows.Native.NativeCallException or InvalidOperationException or DllNotFoundException
            or EntryPointNotFoundException)
        {
            snapshot = null;
        }

        if (snapshot is null && (_tcpFailureLoggedTimestamp == 0 || _deps.Time.GetElapsedTime(_tcpFailureLoggedTimestamp) >= TimeSpan.FromMinutes(10)))
        {
            _tcpFailureLoggedTimestamp = _deps.Time.GetTimestamp();
            _deps.Logger.LogWarning("Таблица соединений TCP не прочитана: закрепления по правилам для доменов снимаются по TTL без продления");
        }

        _tcpSnapshot = snapshot;
        _tcpSnapshotTimestamp = _deps.Time.GetTimestamp();
        _tcpSnapshotTaken = true;
        return snapshot;
    }

    /// <summary>Снятие защиты: закрепления больше не нужны ни в желаемом наборе, ни в применённом.</summary>
    private void ClearPins()
    {
        lock (_pinGate)
        {
            _desiredPins.Clear();
            _warmConnectivityAddresses.Clear();
            _nextPinExpiry = DateTimeOffset.MaxValue;
            Facts.Pinned.Clear();
            Facts.RevocationPins.Clear();
            _pendingAppliedPinShift = TimeSpan.Zero;
            _revocationPinSuffixes = new(StringComparer.Ordinal);
            _promotedPinVersion = _pinVersion;
            _appliedPinVersion = _pinVersion;
            _promotedPinsApplied = true;
            _pinPolicy = null;
            _rejectedPinWarnings.Clear();
            _pinLimitWarnings.Clear();
            _appliedPinPriorities.Clear();
            ResetConnectivityCheckContext();
        }

        _revocationSuffixes = [];
    }

    /// <summary>
    /// Как часто тик сохраняет изменившиеся закрепления на диск. Потеря при сбое процесса - закрепления последних секунд:
    /// при штатной остановке файл пишется сразу (<see cref="SavePinFile"/> из <see cref="RunAsync"/>).
    /// </summary>
    internal static readonly TimeSpan PinSaveInterval = TimeSpan.FromSeconds(30);

    /// <summary>Сколько владельцев одного адреса сохраняется: остальные (одноимённые ответы разных доменов) лишь продлевают его.</summary>
    internal const int MaxSavedOwnersPerAddress = 8;

    /// <summary>
    /// Сколько записей всего попадает в файл: не больше, чем адресов в наборе (<see cref="MaxDomainPins"/>). Вместе с
    /// пределом длины имён (255) это держит файл заметно ниже предела чтения <see cref="ServiceStores.MaxPinFileBytes"/>;
    /// запас на случай экранирования проверяет сама запись (<see cref="ServiceStores.SavePins"/>).
    /// </summary>
    internal const int MaxSavedPinRecords = MaxDomainPins;

    /// <summary>
    /// Шаг, с которым основной срок закрепления входит в отпечаток набора: продление срока новым ответом DNS (каждую
    /// минуту у коротких TTL) не переписывает файл, пока срок не ушёл на следующий шаг. Срок продления в отпечаток не
    /// входит вовсе: при восстановлении он всё равно не длиннее <see cref="PinLingerGrace"/>. Отставший срок в файле
    /// безопасен: восстановленное закрепление лишь раньше уйдёт на решение о продлении по таблице соединений.
    /// </summary>
    internal static readonly TimeSpan PinFileExpiryGranularity = TimeSpan.FromMinutes(5);

    /// <summary>Отпечаток последнего записанного набора: неизменный набор не переписывается. Только в очереди актора.</summary>
    private int _savedPinHash;
    private bool _pinFileSaved;
    private long _pinFileSavedTimestamp;

    /// <summary>
    /// Файл уже прочитан при запуске (<see cref="RestorePinFile"/>): до этого набор не пишется, иначе остановка службы с
    /// нечитаемыми настройками затёрла бы ещё не восстановленный файл пустым набором. Только в очереди актора.
    /// </summary>
    private bool _pinFileRestored;

    /// <summary>Номер загрузки Windows для файла закреплений; читается один раз при восстановлении.</summary>
    private string? _pinFileBootId;

    private const string PinFileFailureSource = "закрепления:файл";

    /// <summary>
    /// Запись файла в фоне: сериализация и замена файла (с повторами при занятости до пары секунд) не держат очередь
    /// актора. Одна запись за раз; ждущая заменяется более свежей (null - удалить файл), так что удаление после снятия
    /// защиты не обгоняет и не воскрешает уже начатую запись: она закончится раньше, удаление выполнится после неё.
    /// </summary>
    private readonly Lock _pinFileGate = new();
    private PinFileWrite? _pinFileNext;
    private Task _pinFileWriter = Task.CompletedTask;
    private bool _pinFileWriterActive;

    /// <summary>Итог последней фоновой записи для журнала: его забирает очередь актора.</summary>
    private PinFileOutcome? _pinFileOutcome;

    private sealed record PinFileWrite(PinFileContent? Content);

    private sealed record PinFileOutcome(Exception? Error);

    /// <summary>
    /// Сохраняет обычные закрепления (правила пользователя, ответ уже выдан): при следующем запуске службы первая сверка
    /// поставит их маршруты и фильтры сразу, и программы со своим кешем адресов и уже открытыми соединениями не уйдут по
    /// адресной политике мимо правила для домена. Служебные (узлы проверки отзыва, веб-проверка интернета), заранее
    /// поставленные и ещё не выданные клиенту закрепления не сохраняются. <paramref name="force"/> - без паузы
    /// <see cref="PinSaveInterval"/> (остановка службы). Под замком берётся только снимок; отбор, отпечаток - здесь,
    /// сериализация и запись - в фоне (<see cref="PinFileWritesAsync"/> ждёт её). Сбой записи - в журнал службы без
    /// повторов на каждом тике. Только в очереди актора (или после её остановки).
    /// </summary>
    internal void SavePinFile(bool force)
    {
        ReportPinFileOutcome();
        if (_emergency is not null || !_pinFileRestored)
        {
            return;
        }

        if (!force && _pinFileSavedTimestamp != 0 && _deps.Time.GetElapsedTime(_pinFileSavedTimestamp) < PinSaveInterval)
        {
            return;
        }

        List<(uint Address, PinnedRoute Pin)> snapshot;
        DateTimeOffset now;
        lock (_pinGate)
        {
            now = ClockNowLocked();
            snapshot = SavablePinsLocked(now);
        }

        var uptime = _deps.SystemUptime();
        var pins = PinFileEntries(snapshot);
        var signature = PinFileSignature(pins);
        _pinFileSavedTimestamp = _deps.Time.GetTimestamp();
        if (_pinFileSaved && signature == _savedPinHash)
        {
            return;
        }

        _savedPinHash = signature;
        _pinFileSaved = true;
        QueuePinFileWrite(pins.Count == 0 ? null : new PinFileContent(ServiceStores.PinFileVersion, now, uptime, _pinFileBootId, pins));
    }

    /// <summary>
    /// Запись при остановке службы (<see cref="RunAsync"/>). Экстренное отключение останавливает работающую службу через
    /// диспетчер служб, без «Отключить», а отметку EmergencyOff ставит раньше: координатор же прочитал её только при запуске.
    /// Поэтому отметка читается здесь заново, и с ней (или если она не прочиталась) файл удаляется, а не пишется: иначе
    /// адреса открытых сайтов лежали бы на диске всё время отключения. Только после остановки очереди актора.
    /// </summary>
    internal void SavePinFileOnStop()
    {
        if (ReadEmergencyFlag(_deps) is not null)
        {
            _deps.Logger.LogInformation("Служба остановлена при экстренном отключении: файл закреплений по правилам для доменов удаляется");
            DiscardPinFile();
            return;
        }

        SavePinFile(force: true);
    }

    /// <summary>
    /// Снятие защиты: файл закреплений (по нему видно, какие сайты открывались) удаляется сразу, а не на следующем тике.
    /// Удаление встаёт в ту же фоновую очередь записи: начатая запись закончится раньше и файл не воскресит. Только в
    /// очереди актора.
    /// </summary>
    private void DiscardPinFile()
    {
        _savedPinHash = PinFileSignature([]);
        _pinFileSaved = true;
        _pinFileSavedTimestamp = _deps.Time.GetTimestamp();
        QueuePinFileWrite(null);
    }

    private void QueuePinFileWrite(PinFileContent? content)
    {
        lock (_pinFileGate)
        {
            _pinFileNext = new PinFileWrite(content);
            if (!_pinFileWriterActive)
            {
                _pinFileWriterActive = true;
                _pinFileWriter = Task.Run(WritePinFiles);
            }
        }
    }

    /// <summary>Фоновая запись: выполняет самую свежую ждущую запись, пока они есть. Исключения - в итог, не наружу.</summary>
    private void WritePinFiles()
    {
        while (true)
        {
            PinFileWrite next;
            lock (_pinFileGate)
            {
                if (_pinFileNext is not { } pending)
                {
                    _pinFileWriterActive = false;
                    return;
                }

                next = pending;
                _pinFileNext = null;
            }

            Exception? error = null;
            try
            {
                if (next.Content is null)
                {
                    _deps.Stores.DeletePins();
                }
                else
                {
                    _deps.Stores.SavePins(next.Content);
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                error = ex;
            }

            Volatile.Write(ref _pinFileOutcome, new PinFileOutcome(error));
        }
    }

    /// <summary>Ждёт, пока фоновая запись файла закреплений (с уже поставленными в очередь) не закончится.</summary>
    internal async Task PinFileWritesAsync()
    {
        while (true)
        {
            Task writer;
            lock (_pinFileGate)
            {
                if (!_pinFileWriterActive)
                {
                    return;
                }

                writer = _pinFileWriter;
            }

            await writer.ConfigureAwait(false);
        }
    }

    /// <summary>Итог фоновой записи - в журнал службы без повторов; сбой - повтор записи после паузы. Только в очереди актора.</summary>
    private void ReportPinFileOutcome()
    {
        if (Interlocked.Exchange(ref _pinFileOutcome, null) is not { } outcome)
        {
            return;
        }

        if (outcome.Error is { } error)
        {
            // Без файла закрепления не переживут перезапуск службы, как было прежде; работе это не мешает.
            _pinFileSaved = false;
            _failures.Failure(PinFileFailureSource, "Закрепления по правилам для доменов не сохранены на диск", error, LogLevel.Warning, withStack: false);
        }
        else
        {
            _failures.Recovered(PinFileFailureSource, "Закрепления по правилам для доменов снова сохраняются на диск");
        }
    }

    /// <summary>Снимок для файла: только обычные и ещё живые закрепления, без сортировки и форматирования. Под _pinGate.</summary>
    private List<(uint Address, PinnedRoute Pin)> SavablePinsLocked(DateTimeOffset now)
    {
        var result = new List<(uint, PinnedRoute)>();
        foreach (var (address, owners) in _desiredPins)
        {
            foreach (var pin in owners)
            {
                if (Savable(address, pin, now))
                {
                    result.Add((address, pin));
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Записи файла из снимка: адреса со свежими сроками - первыми, у адреса - не больше <see cref="MaxSavedOwnersPerAddress"/>
    /// самых свежих владельцев, всего - не больше <see cref="MaxSavedPinRecords"/>. Вне замка.
    /// </summary>
    private static List<PinFileEntry> PinFileEntries(List<(uint Address, PinnedRoute Pin)> snapshot)
    {
        var result = new List<PinFileEntry>();
        foreach (var group in snapshot.GroupBy(p => p.Address).OrderByDescending(g => g.Max(p => p.Pin.ExpiresUtc)))
        {
            var text = Ipv4.Format(group.Key);
            foreach (var (_, pin) in group.OrderByDescending(p => p.Pin.ExpiresUtc)
                .Take(Math.Min(MaxSavedOwnersPerAddress, MaxSavedPinRecords - result.Count)))
            {
                result.Add(new PinFileEntry(text, pin.Target.Kind, pin.Target.Id, pin.Suffix, pin.Name, pin.Origin, pin.ExpiresUtc, pin.LingerUntilUtc));
            }

            if (result.Count >= MaxSavedPinRecords)
            {
                break;
            }
        }

        return result;
    }

    /// <summary>
    /// Отпечаток набора для решения «переписывать ли файл»: адрес, цель, правило и имена, основной срок - с шагом
    /// <see cref="PinFileExpiryGranularity"/>, срок продления - нет. Не зависит от порядка записей.
    /// </summary>
    private static int PinFileSignature(List<PinFileEntry> pins)
    {
        var sum = 0;
        foreach (var pin in pins)
        {
            unchecked
            {
                sum += HashCode.Combine(pin.Address, pin.Kind, pin.Id, pin.Suffix, pin.Name, pin.Origin,
                    pin.ExpiresUtc.UtcTicks / PinFileExpiryGranularity.Ticks);
            }
        }

        return HashCode.Combine(pins.Count, sum);
    }

    /// <summary>
    /// Закрепление переносится в следующий запуск службы: правило пользователя, ответ выдан клиенту, срок (с продлением)
    /// не вышел. Под _pinGate.
    /// </summary>
    private bool Savable(uint address, PinnedRoute pin, DateTimeOffset now) =>
        pin.LeaseId is null && !pin.Warm && pin.Suffix != ConnectivityCheckWebHost && !IsRevocationPin(pin.Suffix, pin.Target)
        && !PinGone(address, pin, now);

    /// <summary>
    /// Восстанавливает закрепления прежнего запуска службы до первой сверки: её политика сразу содержит их маршруты и
    /// фильтры. Дальше они проходят те же проверки, что и живые: сборка политики (<see cref="PromotePins"/>) снимает
    /// закрепления, правило которых исчезло или сменило цель, цель которых недоступна (продлённые), адреса DNS и
    /// отклонённые политикой (<see cref="DropRejectedPins"/>); сроки и продление - как у живых. Здесь же - пределы числа
    /// адресов и сроков: испорченный или подложенный файл не закрепит адрес дольше, чем мог бы один ответ DNS.
    /// Снятая или приостановленная защита закреплений не держит, а после перезагрузки Windows прежние адреса никто не
    /// держит (программы спросят DNS заново), зато устаревший /32 до часа уводил бы общий адрес сети доставки чужих
    /// доменов: в этих случаях файл удаляется. Перезагрузка узнаётся по времени работы Windows (меньше записанного) и
    /// номеру загрузки, а не по настенным часам; только если номер загрузки сравнить нельзя, простой ещё сверяется с
    /// настенными часами (<see cref="WallClockAgrees"/>). Вызывается один раз - при запуске службы с прочитанными настройками.
    /// </summary>
    private void RestorePinFile()
    {
        if (_pinFileRestored)
        {
            return;
        }

        _pinFileRestored = true;
        _pinFileBootId = CurrentBootId();
        DeleteStalePinTemps();
        if (_state.Intent == Core.State.Intent.Off || _state.ProtectionSuspended)
        {
            DeletePinFileOnStartup();
            return;
        }

        PinFileContent? content;
        try
        {
            content = _deps.Stores.LoadPins();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            // Закрепления - подсказка для первой сверки: без них служба работает, как работала до их сохранения.
            _deps.Logger.LogWarning("Закрепления прежнего запуска службы не восстановлены: {Error}", ex.Message);
            return;
        }

        if (content is null)
        {
            return;
        }

        var uptime = _deps.SystemUptime();
        if (content.SavedUptime is not { } savedUptime || savedUptime < TimeSpan.Zero || uptime < savedUptime
            || content.BootId is { } savedBoot && _pinFileBootId is { } boot && !string.Equals(savedBoot, boot, StringComparison.Ordinal)
            || (content.BootId is null || _pinFileBootId is null) && !WallClockAgrees(content.SavedUtc, uptime - savedUptime))
        {
            _deps.Logger.LogInformation("Закрепления прежнего запуска службы не восстанавливаются: после их записи Windows перезагружалась");
            DeletePinFileOnStartup();
            return;
        }

        var restored = RestorePins(content, uptime - savedUptime);
        if (restored > 0)
        {
            // Закрепления, TTL которых истёк за время простоя, держатся, только пока к адресу есть соединения TCP: решение -
            // до первой политики, а не на первом тике после неё.
            DropExpiredPins();
        }

        _deps.Logger.LogInformation("Восстановлено закреплений по правилам для доменов от прежнего запуска службы: {Count}", restored);
    }

    /// <summary>
    /// Насколько простой по настенным часам может расходиться с простоем по времени работы Windows, когда номер загрузки
    /// сравнить нельзя (<see cref="WallClockAgrees"/>).
    /// </summary>
    internal static readonly TimeSpan PinFileClockTolerance = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Перекрёстная проверка, когда номер загрузки не прочитан при записи или при запуске. Перезагрузка, после которой
    /// служба запустилась позже записанного времени работы, по одному времени работы не видна: оно снова больше
    /// записанного. Простой по настенным часам тогда больше простоя по времени работы как минимум на записанное время
    /// работы. Расхождение больше <see cref="PinFileClockTolerance"/> - файл не восстанавливается (как после перезагрузки):
    /// перевод часов за время простоя тоже даёт расхождение, но закрепления - лишь подсказка, их потеря безопасна.
    /// </summary>
    private bool WallClockAgrees(DateTimeOffset savedUtc, TimeSpan uptimeDowntime) =>
        (_deps.Time.GetUtcNow() - savedUtc - uptimeDowntime).Duration() <= PinFileClockTolerance;

    /// <summary>
    /// Недописанные временные файлы атомарной записи (pins.json.&lt;процесс&gt;-&lt;номер&gt;.tmp): процесс, завершённый
    /// посреди записи, оставляет их, и в них те же адреса открытых сайтов. Удаляются при запуске, до первой записи, - только
    /// файлы с точно таким именем и только в каталоге данных (<see cref="ServiceStores.DeleteStalePinTemps"/>).
    /// </summary>
    private void DeleteStalePinTemps()
    {
        try
        {
            if (_deps.Stores.DeleteStalePinTemps() is var deleted and > 0)
            {
                _deps.Logger.LogInformation("Удалено недописанных временных файлов закреплений: {Count}", deleted);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _deps.Logger.LogWarning(ex, "Недописанные временные файлы закреплений не удалены");
        }
    }

    /// <summary>Удаление файла при запуске: фоновой записи ещё нет, удаление синхронное.</summary>
    private void DeletePinFileOnStartup()
    {
        try
        {
            _deps.Stores.DeletePins();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _deps.Logger.LogWarning(ex, "Файл закреплений по правилам для доменов не удалён");
        }
    }

    /// <summary>
    /// Переносит закрепления из файла в желаемый набор; возвращает число восстановленных адресов. <paramref name="downtime"/> -
    /// простой службы по времени работы Windows (монотонный счётчик, переводы часов на него не влияют): остаток срока
    /// записи - её срок минус время записи файла минус простой, по часам записи, и отсчитывается от текущего момента.
    /// В любом случае основной срок не длиннее наибольшего TTL (<see cref="DnsProxyServer.MaxRouteTtl"/>), а срок
    /// продления - не длиннее запаса <see cref="PinLingerGrace"/>: дальше продление решает таблица соединений, как у живого
    /// закрепления.
    /// </summary>
    internal int RestorePins(PinFileContent content, TimeSpan downtime)
    {
        ArgumentNullException.ThrowIfNull(content);
        lock (_pinGate)
        {
            var now = ClockNowLocked();
            if (downtime < TimeSpan.Zero || content.SavedUtc > DateTimeOffset.MaxValue - downtime)
            {
                return 0;
            }

            // Момент запуска по часам, которыми записан файл.
            var origin = content.SavedUtc + downtime;
            var candidates = new List<(uint Address, PinnedRoute Pin)>();
            foreach (var entry in content.Pins ?? [])
            {
                if (RestoredPin(entry, origin, now) is { } restored)
                {
                    candidates.Add(restored);
                }
            }

            var perRule = new Dictionary<string, int>(StringComparer.Ordinal);
            var restoredAddresses = 0;
            // Адреса со свежими сроками - первыми: при нехватке места теряются самые старые, как при вытеснении.
            foreach (var group in candidates.GroupBy(c => c.Address).OrderByDescending(g => g.Max(c => c.Pin.ExpiresUtc)))
            {
                var address = group.Key;
                if (_desiredPins.Count >= MaxDomainPins && !_desiredPins.ContainsKey(address))
                {
                    break;
                }

                // Маршрут различает только IP: у адреса одна цель - та, что у самого свежего закрепления.
                var target = group.MaxBy(c => c.Pin.ExpiresUtc).Pin.Target;
                if (_desiredPins.TryGetValue(address, out var existing) && existing.Exists(p => p.Target != target && p.ExpiresUtc > now))
                {
                    continue;
                }

                var owners = group.Select(c => c.Pin).Where(p => p.Target == target).OrderByDescending(p => p.ExpiresUtc)
                    .Take(MaxSavedOwnersPerAddress).ToList();
                if (owners.Select(p => p.Suffix).Distinct(StringComparer.Ordinal)
                    .Any(suffix => perRule.GetValueOrDefault(suffix) >= MaxPinsPerRule))
                {
                    continue;
                }

                foreach (var suffix in owners.Select(p => p.Suffix).Distinct(StringComparer.Ordinal))
                {
                    perRule[suffix] = perRule.GetValueOrDefault(suffix) + 1;
                }

                // RememberPin ставит и ближайший срок проверки: у закрепления с истёкшим TTL он уже наступил, и первый же
                // тик решит о продлении по таблице соединений.
                foreach (var pin in owners)
                {
                    RememberPin(address, pin, now);
                }

                restoredAddresses++;
            }

            return restoredAddresses;
        }
    }

    /// <summary>
    /// Закрепление из записи файла или null: запись испорчена (в том числе без вида цели), служебная или её срок вышел.
    /// Политики при восстановлении ещё нет (<see cref="_pinPolicy"/> - null), и предел продления считается осторожно
    /// (<see cref="PinLeavesProtection"/>): «напрямую» - всегда короткий <see cref="MaxUnprotectedPinLinger"/>. Закрепление
    /// в туннель на адресе, который адресная политика блокирует, здесь проходит по длинному пределу, но его срок
    /// продления не длиннее <see cref="PinLingerGrace"/>, а следующее решение о продлении принимается уже по собранной
    /// политике - с коротким пределом. Под _pinGate.
    /// </summary>
    private (uint Address, PinnedRoute Pin)? RestoredPin(PinFileEntry? entry, DateTimeOffset origin, DateTimeOffset now)
    {
        const int maxName = 255;
        if (entry is null || !Ipv4.TryParse(entry.Address, out var address) || string.IsNullOrWhiteSpace(entry.Suffix)
            || entry.Suffix.Length > maxName || entry.Name?.Length > maxName || entry.Origin?.Length > maxName
            || entry.Suffix == ConnectivityCheckWebHost || entry.Kind is not { } kind || !Enum.IsDefined(kind))
        {
            return null;
        }

        RouteTarget target;
        switch (kind)
        {
            case TargetKind.Direct or TargetKind.Block:
                target = new RouteTarget(kind);
                break;
            case TargetKind.Tunnel or TargetKind.Group when entry.Id is { } id && id != Guid.Empty:
                target = new RouteTarget(kind, id);
                break;
            default:
                return null;
        }

        // Остаток срока от момента отсчёта. Сильно просроченное (дольше наибольшего продления) не восстанавливается: оно
        // снялось бы и в живой службе, а «now + остаток» не уходит за пределы DateTimeOffset.
        var remaining = entry.ExpiresUtc - origin;
        if (remaining <= -(MaxPinLinger + PinLingerGrace))
        {
            return null;
        }

        var expires = now + (remaining < DnsProxyServer.MaxRouteTtl ? remaining : DnsProxyServer.MaxRouteTtl);
        var linger = default(DateTimeOffset);
        if (entry.LingerUntilUtc != default && entry.LingerUntilUtc - origin is var lingerLeft && lingerLeft > TimeSpan.Zero)
        {
            linger = now + (lingerLeft < PinLingerGrace ? lingerLeft : PinLingerGrace);
        }

        var pin = new PinnedRoute(target, expires, entry.Suffix, Name: entry.Name, Origin: entry.Origin, LingerUntilUtc: linger);
        return IsRevocationPin(pin.Suffix, pin.Target) || PinGone(address, pin, now) ? null : (address, pin);
    }
}

/// <summary>Отказ в закреплении для предупреждения: закрепление (для перепроверки новой политикой) и время последнего отказа.</summary>
internal sealed record RejectedPinWarning(PinnedHost Pin, DateTimeOffset LastSeenUtc);

/// <summary>Мост от DNS-посредника к координатору.</summary>
public sealed class CoordinatorRouteSink(Coordinator coordinator) : IPinnedRouteSink
{
    public ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) =>
        coordinator.ObservePinnedAsync(notice, cancellationToken);

    public ValueTask<IReadOnlyList<uint>?> ObservePartialAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) =>
        coordinator.ObservePinnedPartialAsync(notice, cancellationToken);

    public ValueTask<bool> CompleteAsync(PinnedRouteNotice notice, bool accepted) =>
        coordinator.CompletePinnedAsync(notice, accepted);

    public IReadOnlyList<uint> OpenAddresses(PinnedRouteNotice notice) =>
        coordinator.OpenConnectivityCheckAddresses(notice);
}
