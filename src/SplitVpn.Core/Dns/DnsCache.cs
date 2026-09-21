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
    /// разные ответы, и ответ одного пути нельзя отдавать на другом (split-DNS).
    /// </summary>
    private readonly Dictionary<(string Name, ushort Type, string Context), Entry> _entries = [];
    private readonly Dictionary<string, IReadOnlyList<uint>> _pinned = new(StringComparer.OrdinalIgnoreCase);
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

    /// <summary>Закреплённые A-записи (имя SSTP-сервера): отдаются без истечения и без upstream.</summary>
    public void Pin(string name, IReadOnlyList<uint> addresses)
    {
        lock (_lock)
        {
            _pinned[Normalize(name)] = addresses.ToArray();
        }
    }

    public void Unpin(string name)
    {
        lock (_lock)
        {
            _pinned.Remove(Normalize(name));
        }
    }

    public bool TryGetPinned(string name, out IReadOnlyList<uint> addresses)
    {
        lock (_lock)
        {
            return _pinned.TryGetValue(Normalize(name), out addresses!);
        }
    }

    public void Put(DnsQuestion question, string context, byte[] response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var ttl = DnsMessage.GetMinTtl(response);
        if (ttl is null || ttl == 0 || DnsMessage.IsTruncated(response))
        {
            return;
        }

        var lifetime = TimeSpan.FromSeconds(Math.Min(ttl.Value, MaxTtl.TotalSeconds));
        lock (_lock)
        {
            EvictIfFull();
            _entries[(Normalize(question.Name), question.Type, context)] = new Entry(response.ToArray(), _time.GetUtcNow(), lifetime);
        }
    }

    /// <summary>
    /// Возвращает копию ответа с подставленным ID и оставшимся TTL. В режиме offline отдаёт и просроченные
    /// записи с коротким TTL, но не старше <see cref="MaxStaleAge"/>.
    /// </summary>
    public byte[]? TryGet(DnsQuestion question, string context, ushort id, bool offline)
    {
        Entry entry;
        lock (_lock)
        {
            if (!_entries.TryGetValue((Normalize(question.Name), question.Type, context), out entry))
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
    public byte[]? TryGetAnyPath(DnsQuestion question, ushort id)
    {
        Entry entry;
        lock (_lock)
        {
            var name = Normalize(question.Name);
            var found = _entries
                .Where(e => e.Key.Name == name && e.Key.Type == question.Type)
                .OrderByDescending(e => e.Value.StoredUtc)
                .Select(e => (Entry?)e.Value)
                .FirstOrDefault();
            if (found is null)
            {
                return null;
            }

            entry = found.Value;
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
        DnsMessage.RewriteTtls(copy, (uint)Math.Max(1, ttl.TotalSeconds));
        return copy;
    }

    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
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
        }
    }

    private readonly record struct Entry(byte[] Response, DateTimeOffset StoredUtc, TimeSpan Lifetime);
}
