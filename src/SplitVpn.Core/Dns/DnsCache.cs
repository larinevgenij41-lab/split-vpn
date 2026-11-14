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
    private readonly Dictionary<(string Name, ushort Type, DnsQueryFlags Flags, string Context), Entry> _entries = [];
    private readonly Dictionary<(string Name, ushort Type, DnsQueryFlags Flags), Dictionary<string, Entry>> _byQuestion = [];
    private readonly Dictionary<string, PinnedEntry> _pinned = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>CNAME-связи: каноническое имя → суффикс правила исходного имени и срок связи.</summary>
    private sealed record CanonicalLease(string Suffix, DateTimeOffset ExpiresUtc, Guid? LeaseId);
    private readonly Dictionary<string, List<CanonicalLease>> _links = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, string[]> _linkReservations = [];
    private readonly TimeProvider _time;
    private readonly int _capacity;
    private readonly Lock _lock = new();

    public DnsCache(TimeProvider time, int capacity = 10_000)
    {
        _time = time;
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
            var now = _time.GetUtcNow();
            RemoveExpiredPins(now);
            var key = Normalize(name);
            // Временный запрос к тому же узлу не сокращает жизнь закрепления VPN-сервера.
            var permanent = lifetime is null || (_pinned.TryGetValue(key, out var existing) && existing.ExpiresUtc is null);
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
            RemoveExpiredPins(_time.GetUtcNow());
            foreach (var name in _pinned.Where(p => p.Value.ExpiresUtc is null && !keep.Contains(p.Key)).Select(p => p.Key).ToArray())
            {
                _pinned.Remove(name);
            }
        }
    }

    private void RemoveExpiredPins(DateTimeOffset now)
    {
        foreach (var name in _pinned.Where(p => p.Value.ExpiresUtc <= now).Select(p => p.Key).ToArray())
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
                if (entry.ExpiresUtc is null || entry.ExpiresUtc > _time.GetUtcNow())
                {
                    addresses = entry.Addresses;
                    remaining = entry.ExpiresUtc - _time.GetUtcNow();
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
    public bool TryReserveCanonicalLinks(IEnumerable<string> names, string suffix, TimeSpan lifetime, Guid leaseId, Func<string, bool> compatible)
    {
        var keys = names.Select(Normalize).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (keys.Length == 0) { return true; }
        lock (_lock)
        {
            var now = _time.GetUtcNow();
            foreach (var key in keys) { RemoveExpiredLink(key, now); }
            if (_links.Count + keys.Count(k => !_links.ContainsKey(k)) > _capacity) { RemoveExpiredLinks(now); }
            if (_links.Count + keys.Count(k => !_links.ContainsKey(k)) > _capacity
                || keys.Any(k => _links.TryGetValue(k, out var owners) && owners.Any(o => !compatible(o.Suffix))))
            {
                return false;
            }
            foreach (var key in keys)
            {
                if (!_links.TryGetValue(key, out var owners)) { _links[key] = owners = []; }
                owners.Add(new CanonicalLease(suffix, now + lifetime, leaseId));
            }
            _linkReservations.Add(leaseId, keys);
            return true;
        }
    }

    /// <summary>Отмена затрагивает только этот ответ; принятые сроки других владельцев остаются.</summary>
    public void CompleteCanonicalLinks(Guid leaseId, bool accepted)
    {
        lock (_lock)
        {
            if (!_linkReservations.Remove(leaseId, out var keys)) { return; }
            var now = _time.GetUtcNow();
            foreach (var key in keys)
            {
                if (!_links.TryGetValue(key, out var owners)) { continue; }
                var pending = owners.Where(o => o.LeaseId == leaseId).ToArray();
                owners.RemoveAll(o => o.LeaseId == leaseId);
                foreach (var lease in accepted ? pending : [])
                {
                    var existing = owners.Find(o => o.LeaseId is null && o.Suffix == lease.Suffix);
                    var expires = existing is null || existing.ExpiresUtc < lease.ExpiresUtc ? lease.ExpiresUtc : existing.ExpiresUtc;
                    owners.RemoveAll(o => o.LeaseId is null && o.Suffix == lease.Suffix);
                    owners.Add(lease with { ExpiresUtc = expires, LeaseId = null });
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

    public IReadOnlyList<string> GetCanonicalLinks(string name)
    {
        lock (_lock)
        {
            if (!_links.TryGetValue(Normalize(name), out var owners)) { return []; }
            var now = _time.GetUtcNow();
            return owners.Where(o => o.LeaseId is null && o.ExpiresUtc > now).Select(o => o.Suffix).ToArray();
        }
    }

    private void RemoveExpiredLinks(DateTimeOffset now)
    {
        foreach (var key in _links.Keys.ToArray())
        {
            RemoveExpiredLink(key, now);
        }
    }

    private void RemoveExpiredLink(string key, DateTimeOffset now)
    {
        if (!_links.TryGetValue(key, out var owners)) { return; }
        owners.RemoveAll(o => o.ExpiresUtc <= now);
        if (owners.Count == 0) { _links.Remove(key); }
    }

    public void Put(DnsQuestion question, string context, byte[] response, DnsQueryFlags flags = default)
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
            var key = (Normalize(question.Name), question.Type, flags, context);
            if (!_entries.ContainsKey(key))
            {
                EvictIfFull();
            }

            var entry = new Entry(response.ToArray(), _time.GetUtcNow(), lifetime);
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

            entry = paths.Values.MaxBy(e => e.StoredUtc);
        }

        return Materialize(entry, id, offline: true);
    }

    private byte[]? Materialize(Entry entry, ushort id, bool offline)
    {
        var age = _time.GetUtcNow() - entry.StoredUtc;
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
            _entries.Clear();
            _byQuestion.Clear();
            // Клиенты ещё используют выданные CNAME. Связь хранит суффикс, а путь и цель
            // выбираются по действующей конфигурации, без сохранения старого DNS-ответа.
            RemoveExpiredLinks(_time.GetUtcNow());
            // Служебный ответ прежнего пути тоже не должен обходить новую доменную политику.
            foreach (var name in _pinned.Where(p => p.Value.ExpiresUtc is not null).Select(p => p.Key).ToArray())
            {
                _pinned.Remove(name);
            }
        }
    }

    private static string Normalize(string name) => name.TrimEnd('.').ToLowerInvariant();

    private void EvictIfFull()
    {
        if (_entries.Count < _capacity)
        {
            return;
        }

        var oldest = _entries.OrderBy(e => e.Value.StoredUtc).Take(Math.Max(1, _capacity / 10)).Select(e => e.Key).ToList();
        foreach (var key in oldest)
        {
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

    private readonly record struct Entry(byte[] Response, DateTimeOffset StoredUtc, TimeSpan Lifetime);

    private readonly record struct PinnedEntry(IReadOnlyList<uint> Addresses, DateTimeOffset? ExpiresUtc);
}
