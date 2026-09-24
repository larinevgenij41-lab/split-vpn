using System.Security.Cryptography;
using System.Text.Json;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Geo;

public sealed record GeoRevision
{
    /// <summary>SHA-256 содержимого в нижнем регистре — идентификатор версии.</summary>
    public required string Id { get; init; }

    public required string SourceId { get; init; }

    public string? Url { get; init; }

    public DateTimeOffset DownloadedUtc { get; init; }

    public DateTimeOffset? DataDateUtc { get; init; }

    public string? ETag { get; init; }

    public int V4Count { get; init; }

    public int V6Count { get; init; }

    public ulong V4Addresses { get; init; }
}

public sealed record GeoStoreState
{
    public string? Active { get; init; }

    public string? Previous { get; init; }

    public string? Pending { get; init; }

    public string? PendingReason { get; init; }

    /// <summary>Ревизии, от которых откатились или которые заменили импортом: автоматически не применяются.</summary>
    public IReadOnlyList<string> Skipped { get; init; } = [];

    public DateTimeOffset? LastCheckUtc { get; init; }

    public DateTimeOffset? NextCheckUtc { get; init; }

    public string? LastResult { get; init; }

    public string? LastETag { get; init; }
}

/// <summary>Хранилище версий списка: active, previous, pending. Остальные ревизии удаляются.</summary>
public sealed class GeoStore
{
    private const string ListFileName = "list.txt";
    private const string MetaFileName = "meta.json";
    private const int MaxSkipped = 20;

    private readonly string _root;

    public GeoStore(string root)
    {
        _root = root;
        Directory.CreateDirectory(RevisionsRoot);
    }

    private string RevisionsRoot => Path.Combine(_root, "revisions");

    private string StatePath => Path.Combine(_root, "state.json");

    /// <summary>Куда сообщать о повреждённых файлах хранилища: журнал событий и предупреждение в статусе.</summary>
    public Action<CorruptFile>? OnCorrupt { get; init; }

    public static string ComputeId(ReadOnlySpan<byte> content) => Convert.ToHexStringLower(SHA256.HashData(content));

    /// <summary>Состояние хранилища; повреждённый файл откладывается в копию, база считается не загруженной.</summary>
    public GeoStoreState LoadState() => SafeFile.Load(
        StatePath,
        text => JsonSerializer.Deserialize<GeoStoreState>(text, JsonDefaults.Options),
        () => new GeoStoreState(),
        "Состояние списка адресов было повреждено и заменено значениями по умолчанию",
        OnCorrupt);

    public void SaveState(GeoStoreState state)
    {
        AtomicFile.WriteAllText(StatePath, JsonSerializer.Serialize(state, JsonDefaults.Options));
    }

    public bool HasRevision(string id) => File.Exists(Path.Combine(RevisionsRoot, id, MetaFileName));

    public void SaveRevision(byte[] content, GeoRevision meta)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(meta);
        if (HasRevision(meta.Id))
        {
            return;
        }

        var target = Path.Combine(RevisionsRoot, meta.Id);
        var temp = target + ".tmp";
        if (Directory.Exists(target))
        {
            // Каталог без описания версии остаётся от повреждённого meta.json: он мешает переносу нового.
            Directory.Delete(target, recursive: true);
        }

        if (Directory.Exists(temp))
        {
            Directory.Delete(temp, recursive: true);
        }

        Directory.CreateDirectory(temp);
        File.WriteAllBytes(Path.Combine(temp, ListFileName), content);
        File.WriteAllText(Path.Combine(temp, MetaFileName), JsonSerializer.Serialize(meta, JsonDefaults.Options));
        Directory.Move(temp, target);
    }

    public string ReadRevisionText(string id) => File.ReadAllText(Path.Combine(RevisionsRoot, id, ListFileName));

    /// <summary>Описание версии; повреждённый файл откладывается в копию, а версия считается непригодной.</summary>
    public GeoRevision? ReadRevisionMeta(string id) => SafeFile.Load<GeoRevision?>(
        Path.Combine(RevisionsRoot, id, MetaFileName),
        text => JsonSerializer.Deserialize<GeoRevision>(text, JsonDefaults.Options),
        () => null,
        "Описание версии списка адресов было повреждено: версия не используется",
        OnCorrupt);

    /// <summary>Делает ревизию активной. Сохранённая, но не упомянутая в состоянии ревизия удаляется при следующей фиксации.</summary>
    public GeoStoreState Activate(string id, bool skipReplaced = false)
    {
        if (!HasRevision(id))
        {
            throw new InvalidOperationException("Ревизия базы не найдена в хранилище.");
        }

        var state = LoadState();
        if (state.Active == id)
        {
            return state;
        }

        var skipped = skipReplaced && state.Active is not null ? AddSkipped(state.Skipped, state.Active) : state.Skipped;
        var updated = state with
        {
            Active = id,
            Previous = state.Active ?? state.Previous,
            Pending = state.Pending == id ? null : state.Pending,
            PendingReason = state.Pending == id ? null : state.PendingReason,
            Skipped = skipped.Where(s => s != id).ToList(),
        };
        return Commit(updated);
    }

    public GeoStoreState SetPending(string id, string reason)
    {
        return Commit(LoadState() with { Pending = id, PendingReason = reason });
    }

    public GeoStoreState RejectPending()
    {
        var state = LoadState();
        if (state.Pending is null)
        {
            return state;
        }

        return Commit(state with { Skipped = AddSkipped(state.Skipped, state.Pending), Pending = null, PendingReason = null });
    }

    /// <summary>Возврат к предыдущей базе; текущая помечается пропускаемой.</summary>
    public GeoStoreState? Rollback()
    {
        var state = LoadState();
        if (state.Previous is null || state.Active is null)
        {
            return null;
        }

        var skipped = AddSkipped(state.Skipped, state.Active).Where(s => s != state.Previous).ToList();
        return Commit(state with { Active = state.Previous, Previous = null, Skipped = skipped });
    }

    public GeoStoreState ClearSkipped() => Commit(LoadState() with { Skipped = [] });

    private static List<string> AddSkipped(IReadOnlyList<string> skipped, string id)
    {
        var list = skipped.Where(s => s != id).Append(id).ToList();
        return list.Count > MaxSkipped ? list.Skip(list.Count - MaxSkipped).ToList() : list;
    }

    private GeoStoreState Commit(GeoStoreState state)
    {
        SaveState(state);
        RemoveUnreferenced(state);
        return state;
    }

    private void RemoveUnreferenced(GeoStoreState state)
    {
        var keep = new HashSet<string?>(StringComparer.Ordinal) { state.Active, state.Previous, state.Pending };
        foreach (var dir in Directory.GetDirectories(RevisionsRoot))
        {
            if (!keep.Contains(Path.GetFileName(dir)))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }
}
