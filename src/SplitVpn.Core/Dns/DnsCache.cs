namespace SplitVpn.Core.Dns;

/// <summary>
/// Кеш ответов посредника. Только в памяти: история запрошенных имён на диск не попадает (PLAN §7).
/// </summary>
public sealed class DnsCache
{
    public static readonly TimeSpan OfflineTtl = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan MaxTtl = TimeSpan.FromHours(1);

    /// <summary>
    /// Предельный возраст записи, которую аварийный режим отдаёт просроченной. Без него сменивший адрес
    /// ресурс оставался бы недоступным, пока запись не вытеснят или процесс не перезапустят.
    /// </summary>
    public static readonly TimeSpan MaxStaleAge = TimeSpan.FromHours(24);

    /// <summary>
    /// Ключ включает путь разрешения: один и тот же вопрос через корпоративный и через публичный DNS —
    /// разные ответы, и ответ одного пути нельзя отдавать на другом (split-DNS). Признаки запроса (CD, DO,
    /// EDNS) тоже в ключе: ответ с RRSIG или без проверки DNSSEC не должен достаться клиенту, который его не просил.
    /// </summary>
    private readonly LinkedList<(string Name, ushort Type, DnsQueryFlags Flags, string Context)> _writeOrder = new();
    private readonly Dictionary<(string Name, ushort Type, DnsQueryFlags Flags, string Context), Entry> _entries = [];
    private readonly Dictionary<(string Name, ushort Type, DnsQueryFlags Flags), Dictionary<string, Entry>> _byQuestion = [];
    private readonly Dictionary<string, PinnedEntry> _pinned = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>CNAME-связи: каноническое имя → суффикс правила исходного имени и срок связи.</summary>
    private sealed record CanonicalLease(string Suffix, string Origin, TimeSpan ExpiresAt, Guid? LeaseId);
    private readonly Dictionary<string, List<CanonicalLease>> _links = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, string[]> _linkReservations = [];
    private readonly TimeProvider _time;

    /// <summary>
    /// Начало монотонного отсчёта: сроки закреплений и CNAME-связей — по нему, как и возраст записей кеша. Перевод
    /// системных часов (синхронизация после сна, ручная правка) не продлевает и не обрывает их.
    /// </summary>
    private readonly long _origin;
    private readonly int _capacity;
    private readonly Lock _lock = new();
    private long _generation;

    public DnsCache(TimeProvider time, int capacity = 10_000)
    {
        _time = time;
        _origin = time.GetTimestamp();
        _capacity = capacity;
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Имя VPN-сервера закрепляется бессрочно; временным служебным именам задаётся срок.</summary>
    public void Pin(string name, IReadOnlyList<uint> addresses, TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }

        lock (_lock)
        {
            var now = Now();
            RemoveExpiredPins(now);
            var key = Normalize(name);
            // Временный запрос к тому же узлу не сокращает жизнь закрепления VPN-сервера.
            var permanent = lifetime is null || (_pinned.TryGetValue(key, out var existing) && existing.ExpiresAt is null);
            _pinned[key] = new PinnedEntry(addresses.ToArray(), permanent ? null : now + lifetime!.Value);
        }
    }

    /// <summary>Удаляет бессрочные имена прежних профилей и просроченные временные записи.</summary>
    public void RetainPins(IEnumerable<string> permanentNames)
    {
        ArgumentNullException.ThrowIfNull(permanentNames);
        var keep = permanentNames.Select(Normalize).ToHashSet(StringComparer.OrdinalIgnoreCase);
        lock (_lock)
        {
            RemoveExpiredPins(Now());
            foreach (var name in _pinned.Where(p => p.Value.ExpiresAt is null && !keep.Contains(p.Key)).Select(p => p.Key).ToArray())
            {
                _pinned.Remove(name);
            }
        }
    }

    /// <summary>Монотонное время с создания кеша.</summary>
    private TimeSpan Now() => _time.GetElapsedTime(_origin);

    private void RemoveExpiredPins(TimeSpan now)
    {
        foreach (var name in _pinned.Where(p => p.Value.ExpiresAt <= now).Select(p => p.Key).ToArray())
        {
            _pinned.Remove(name);
        }
    }

    public void Unpin(string name)
    {
        lock (_lock)
        {
            _pinned.Remove(Normalize(name));
        }
    }

    public bool TryGetPinned(string name, out IReadOnlyList<uint> addresses) => TryGetPinned(name, out addresses, out _);

    public bool TryGetPinned(string name, out IReadOnlyList<uint> addresses, out TimeSpan? remaining)
    {
        lock (_lock)
        {
            var key = Normalize(name);
            if (_pinned.TryGetValue(key, out var entry))
            {
                var now = Now();
                if (entry.ExpiresAt is null || entry.ExpiresAt > now)
                {
                    addresses = entry.Addresses;
                    remaining = entry.ExpiresAt - now;
                    return true;
                }

                _pinned.Remove(key);
            }

            addresses = [];
            remaining = null;
            return false;
        }
    }

    /// <summary>
    /// Запоминает, что каноническое имя получено по CNAME от имени под правилом с суффиксом suffix:
    /// отдельный запрос канонического имени до истечения связи пойдёт по тому же правилу (DOMAIN-ROUTING-PLAN).
    /// Число связей ограничено ёмкостью кеша: переполнение не продлевает чужие связи и не растит память.
    /// </summary>
    public bool LinkCanonical(string canonicalName, string suffix, TimeSpan lifetime)
    {
        var lease = Guid.NewGuid();
        if (!TryReserveCanonicalLinks([canonicalName], suffix, lifetime, lease, existing => existing == suffix)) { return false; }
        CompleteCanonicalLinks(lease, true);
        return true;
    }

    /// <summary>Резервирует весь ответ атомарно; ожидающий ответ тоже защищает свою цель от переназначения.</summary>
    public bool TryReserveCanonicalLinks(IEnumerable<string> names, string suffix, TimeSpan lifetime, Guid leaseId, Func<string, bool> compatible, IReadOnlyList<string>? origins = null)
    {
        var uniqueOrigins = origins is null ? [suffix] : origins.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var keys = names.Select(Normalize).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (keys.Length == 0) { return true; }
        if (uniqueOrigins.Length > 256) { return false; }
        lock (_lock)
        {
            var now = Now();
            foreach (var key in keys) { RemoveExpiredLink(key, now); }
            if (_links.Count + keys.Count(k => !_links.ContainsKey(k)) > _capacity) { RemoveExpiredLinks(now); }
            if (_links.Count + keys.Count(k => !_links.ContainsKey(k)) > _capacity
                || keys.Any(key => _links.TryGetValue(key, out var owners) && !CanReserve(owners, suffix, uniqueOrigins, compatible)))
            {
                return false;
            }
            foreach (var key in keys)
            {
                if (!_links.TryGetValue(key, out var owners)) { _links[key] = owners = []; }
                foreach (var origin in uniqueOrigins)
                {
                    owners.Add(new CanonicalLease(suffix, origin, now + lifetime, leaseId));
                }
            }
            _linkReservations.Add(leaseId, keys);
            return true;
        }
    }

    private static bool CanReserve(List<CanonicalLease> owners, string suffix, string[] origins, Func<string, bool> compatible)
    {
        if (owners.Any(o => !compatible(o.Suffix)) || owners.Count(o => o.LeaseId.HasValue) + origins.Length > 256)
        {
            return false;
        }
        if (owners.Count + origins.Length <= 256) { return true; }
        return owners.Select(o => (o.Suffix, o.Origin)).Concat(origins.Select(o => (suffix, o))).Distinct().Count() <= 256;
    }

    /// <summary>Отмена затрагивает только этот ответ; принятые сроки других владельцев остаются.</summary>
    public void CompleteCanonicalLinks(Guid leaseId, bool accepted)
    {
        lock (_lock)
        {
            if (!_linkReservations.Remove(leaseId, out var keys)) { return; }
            var now = Now();
            foreach (var key in keys)
            {
                if (!_links.TryGetValue(key, out var owners)) { continue; }
                var pending = owners.Where(o => o.LeaseId == leaseId).ToArray();
                owners.RemoveAll(o => o.LeaseId == leaseId);
                foreach (var lease in accepted ? pending : [])
                {
                    var existing = owners.Find(o => o.LeaseId is null && o.Suffix == lease.Suffix && o.Origin == lease.Origin);
                    var expires = existing is null || existing.ExpiresAt < lease.ExpiresAt ? lease.ExpiresAt : existing.ExpiresAt;
                    owners.RemoveAll(o => o.LeaseId is null && o.Suffix == lease.Suffix && o.Origin == lease.Origin);
                    owners.Add(lease with { ExpiresAt = expires, LeaseId = null });
                }
                RemoveExpiredLink(key, now);
            }
        }
    }

    public string? TryGetCanonicalLink(string name)
    {
        var links = GetCanonicalLinks(name);
        return links.Count == 0 ? null : links[0];
    }

    public IReadOnlyList<string> GetCanonicalLinks(string name) =>
        GetCanonicalOwners(name).Select(owner => owner.Suffix).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    public IReadOnlyList<(string Suffix, string Origin)> GetCanonicalOwners(string name)
    {
        lock (_lock)
        {
            if (!_links.TryGetValue(Normalize(name), out var owners)) { return []; }
            var now = Now();
            return owners.Where(o => o.LeaseId is null && o.ExpiresAt > now).Select(o => (o.Suffix, o.Origin)).ToArray();
        }
    }

    private void RemoveExpiredLinks(TimeSpan now)
    {
        foreach (var key in _links.Keys.ToArray())
        {
            RemoveExpiredLink(key, now);
        }
    }

    private void RemoveExpiredLink(string key, TimeSpan now)
    {
        if (!_links.TryGetValue(key, out var owners)) { return; }
        owners.RemoveAll(o => o.ExpiresAt <= now);
        if (owners.Count == 0) { _links.Remove(key); }
    }

    /// <summary>
    /// Поколение кеша: растёт при каждой очистке. Обработчик запоминает его до пересылки и передаёт в
    /// <see cref="Put"/>: ответ, пришедший до смены сети, но записываемый после очистки, в кеш не попадает.
    /// </summary>
    public long Generation
    {
        get
        {
            lock (_lock)
            {
                return _generation;
            }
        }
    }

    /// <summary>
    /// Кладёт ответ в кеш. generation - поколение кеша на момент отправки запроса: если с тех пор кеш очищен,
    /// ответ не кешируется.
    /// </summary>
    public void Put(DnsQuestion question, string context, byte[] response, DnsQueryFlags flags = default, long? generation = null)
    {
        ArgumentNullException.ThrowIfNull(response);
        var ttl = DnsMessage.GetMinTtl(response);
        // Кешируется только класс IN: в ключе класса нет, и ответ CHAOS выдавался бы на запрос IN того же имени.
        if (question.Class != DnsMessage.ClassIn || ttl is null || ttl == 0 || DnsMessage.IsTruncated(response))
        {
            return;
        }

        var lifetime = TimeSpan.FromSeconds(Math.Min(ttl.Value, MaxTtl.TotalSeconds));
        lock (_lock)
        {
            if (generation is not null && generation != _generation)
            {
                // Кеш очищен, пока шёл запрос: ответ прежней сети в новую не попадает.
                return;
            }

            var key = (Normalize(question.Name), question.Type, flags, context);
            if (_entries.TryGetValue(key, out var previous)) { _writeOrder.Remove(previous.Order); }
            else
            {
                EvictIfFull();
            }

            var entry = new Entry(response.ToArray(), _time.GetTimestamp(), lifetime, _writeOrder.AddLast(key));
            _entries[key] = entry;
            var questionKey = (key.Item1, key.Type, flags);
            if (!_byQuestion.TryGetValue(questionKey, out var paths))
            {
                _byQuestion[questionKey] = paths = new Dictionary<string, Entry>(StringComparer.Ordinal);
            }

            paths[context] = entry;
        }
    }

    /// <summary>
    /// Возвращает копию ответа с подставленным ID и оставшимся TTL. В режиме offline отдаёт и просроченные
    /// записи с коротким TTL, но не старше <see cref="MaxStaleAge"/>.
    /// </summary>
    public byte[]? TryGet(DnsQuestion question, string context, ushort id, bool offline, DnsQueryFlags flags = default)
    {
        Entry entry;
        lock (_lock)
        {
            if (question.Class != DnsMessage.ClassIn
                || !_entries.TryGetValue((Normalize(question.Name), question.Type, flags, context), out entry))
            {
                return null;
            }
        }

        return Materialize(entry, id, offline);
    }

    /// <summary>
    /// Ответ по любому известному пути. Нужен, когда пути нет вовсе: выбирать не из чего, и без этого кеш
    /// в аварийном режиме бесполезен. Берётся самая свежая запись.
    /// </summary>
    public byte[]? TryGetAnyPath(DnsQuestion question, ushort id, DnsQueryFlags flags = default)
    {
        Entry entry;
        lock (_lock)
        {
            if (question.Class != DnsMessage.ClassIn
                || !_byQuestion.TryGetValue((Normalize(question.Name), question.Type, flags), out var paths))
            {
                return null;
            }

            var found = false;
            entry = default;
            var now = _time.GetTimestamp();
            foreach (var candidate in paths.Values)
            {
                if ((!found || candidate.Stored >= entry.Stored) && _time.GetElapsedTime(candidate.Stored, now) <= candidate.Lifetime + MaxStaleAge)
                {
                    entry = candidate;
                    found = true;
                }
            }
            if (!found) { return null; }
        }

        return Materialize(entry, id, offline: true);
    }

    private byte[]? Materialize(Entry entry, ushort id, bool offline)
    {
        var age = _time.GetElapsedTime(entry.Stored);
        var remaining = entry.Lifetime - age;
        if (remaining <= TimeSpan.Zero && (!offline || age > entry.Lifetime + MaxStaleAge))
        {
            return null;
        }

        var ttl = remaining > TimeSpan.Zero ? remaining : OfflineTtl;
        if (offline && ttl > OfflineTtl)
        {
            ttl = OfflineTtl;
        }

        var copy = entry.Response.ToArray();
        DnsMessage.SetId(copy, id);
        if (remaining <= TimeSpan.Zero)
        {
            DnsMessage.RewriteTtls(copy, (uint)OfflineTtl.TotalSeconds);
        }
        else
        {
            DnsMessage.AgeTtls(copy, (uint)Math.Max(0, age.TotalSeconds), (uint)Math.Max(1, ttl.TotalSeconds));
        }
        return copy;
    }

    public void Clear()
    {
        lock (_lock)
        {
            _generation++;
            _entries.Clear();
            _writeOrder.Clear();
            _byQuestion.Clear();
            // Клиенты ещё используют выданные CNAME. Связь хранит суффикс, а путь и цель
            // выбираются по действующей конфигурации, без сохранения старого DNS-ответа.
            RemoveExpiredLinks(Now());
            // Служебный ответ прежнего пути тоже не должен обходить новую доменную политику.
            foreach (var name in _pinned.Where(p => p.Value.ExpiresAt is not null).Select(p => p.Key).ToArray())
            {
                _pinned.Remove(name);
            }
        }
    }

    /// <summary>
    /// Ключ имени. Запросы приходят в ASCII (Punycode), а имя сервера в настройках может быть записано
    /// по-русски (vpn.пример.рф): без перевода в ASCII закреплённое имя не нашлось бы по запросу.
    /// </summary>
    private static string Normalize(string name)
    {
        var trimmed = name.TrimEnd('.');
        if (!System.Text.Ascii.IsValid(trimmed))
        {
            try
            {
                trimmed = new System.Globalization.IdnMapping().GetAscii(trimmed);
            }
            catch (ArgumentException)
            {
                // Недопустимое IDN-имя: остаётся как есть, совпадёт только с таким же написанием.
            }
        }

        return trimmed.ToLowerInvariant();
    }

    private void EvictIfFull()
    {
        if (_entries.Count < _capacity)
        {
            return;
        }

        for (var i = 0; i < Math.Max(1, _capacity / 10) && _writeOrder.First is { } oldest; i++)
        {
            var key = oldest.Value;
            _writeOrder.RemoveFirst();
            _entries.Remove(key);
            var questionKey = (key.Name, key.Type, key.Flags);
            var paths = _byQuestion[questionKey];
            paths.Remove(key.Context);
            if (paths.Count == 0)
            {
                _byQuestion.Remove(questionKey);
            }
        }
    }

    private readonly record struct Entry(byte[] Response, long Stored, TimeSpan Lifetime,
        LinkedListNode<(string Name, ushort Type, DnsQueryFlags Flags, string Context)> Order);

    private readonly record struct PinnedEntry(IReadOnlyList<uint> Addresses, TimeSpan? ExpiresAt);
}
