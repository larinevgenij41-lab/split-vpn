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
