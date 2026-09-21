namespace SplitVpn.Core.Dns;

/// <summary>
/// Кеш ответов посредника. Только в памяти: история запрошенных имён на диск не попадает (PLAN §7).
/// </summary>
public sealed class DnsCache
{
    public static readonly TimeSpan OfflineTtl = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan MaxTtl = TimeSpan.FromHours(1);

    private readonly Dictionary<(string Name, ushort Type), Entry> _entries = [];
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

    public void Put(DnsQuestion question, byte[] response)
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
            _entries[(Normalize(question.Name), question.Type)] = new Entry(response.ToArray(), _time.GetUtcNow(), lifetime);
        }
    }

    /// <summary>
    /// Возвращает копию ответа с подставленным ID и оставшимся TTL. В режиме offline отдаёт
    /// и просроченные записи с коротким TTL.
    /// </summary>
    public byte[]? TryGet(DnsQuestion question, ushort id, bool offline)
    {
        Entry entry;
        lock (_lock)
        {
            if (!_entries.TryGetValue((Normalize(question.Name), question.Type), out entry))
            {
                return null;
            }
        }

        var age = _time.GetUtcNow() - entry.StoredUtc;
        var remaining = entry.Lifetime - age;
        if (remaining <= TimeSpan.Zero && !offline)
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
