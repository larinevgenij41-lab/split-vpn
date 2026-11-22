using SplitVpn.Core.Protection;

namespace SplitVpn.Windows.Wfp;

/// <summary>Граница нативных вызовов: позволяет проверять транзакции и кеш ID без изменения сети.</summary>
internal interface IWfpSession : IDisposable
{
    IDisposable? TrackProgress(Action<int, int>? progress) => null;
    void EnsureProvider();
    IReadOnlyList<WfpFilterInfo> ListFilters();
    IReadOnlyList<ulong> AddFilters(IEnumerable<FilterSpec> specs, bool persistent, bool indexed);
    void DeleteFilters(IEnumerable<ulong> ids);
    bool FilterExists(ulong id);
    void InTransaction(Action body);
    void DeleteAll();
}

internal sealed class WfpSession(WfpIdentity identity) : IWfpSession
{
    private readonly WfpEngine _engine = WfpEngine.Open(dynamicSession: false);
    private Action<int, int>? _progress;

    public IDisposable TrackProgress(Action<int, int>? progress)
    {
        var previous = _progress;
        _progress = progress;
        return new ProgressScope(() => _progress = previous);
    }

    public void EnsureProvider() => WfpOps.EnsureProviderAndSubLayer(_engine, identity, persistent: true);
    public IReadOnlyList<WfpFilterInfo> ListFilters() => WfpOps.ListFilters(_engine, identity);
    public IReadOnlyList<ulong> AddFilters(IEnumerable<FilterSpec> specs, bool persistent, bool indexed)
    {
        if (_progress is null) { return WfpOps.AddFilters(_engine, identity, specs, persistent, indexed); }
        var items = specs.ToArray();
        var total = items.Sum(s => WfpOps.LayersOf(s.Family).Count);
        var completed = 0;
        _progress(0, total);
        return WfpOps.AddFilters(_engine, identity, items, persistent, indexed,
            () => _progress?.Invoke(++completed, total));
    }

    public void DeleteFilters(IEnumerable<ulong> ids)
    {
        if (_progress is null) { WfpOps.DeleteFilters(_engine, ids); return; }
        var items = ids.ToArray();
        var completed = 0;
        _progress(0, items.Length);
        WfpOps.DeleteFilters(_engine, items, () => _progress?.Invoke(++completed, items.Length));
    }
    public bool FilterExists(ulong id) => WfpOps.FilterExists(_engine, id);
    public void InTransaction(Action body) => _engine.InTransaction(_ => body());
    public void DeleteAll() => WfpOps.DeleteAll(_engine, identity, _progress);
    public void Dispose() => _engine.Dispose();

    private sealed class ProgressScope(Action restore) : IDisposable
    {
        public void Dispose() => restore();
    }
}
