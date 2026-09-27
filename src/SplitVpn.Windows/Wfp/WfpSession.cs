using SplitVpn.Core.Protection;

namespace SplitVpn.Windows.Wfp;

/// <summary>Граница нативных вызовов: позволяет проверять транзакции и кеш ID без изменения сети.</summary>
internal interface IWfpSession : IDisposable
{
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

    public void EnsureProvider() => WfpOps.EnsureProviderAndSubLayer(_engine, identity, persistent: true);
    public IReadOnlyList<WfpFilterInfo> ListFilters() => WfpOps.ListFilters(_engine, identity);
    public IReadOnlyList<ulong> AddFilters(IEnumerable<FilterSpec> specs, bool persistent, bool indexed) =>
        WfpOps.AddFilters(_engine, identity, specs, persistent, indexed);
    public void DeleteFilters(IEnumerable<ulong> ids) => WfpOps.DeleteFilters(_engine, ids);
    public bool FilterExists(ulong id) => WfpOps.FilterExists(_engine, id);
    public void InTransaction(Action body) => _engine.InTransaction(_ => body());
    public void DeleteAll() => WfpOps.DeleteAll(_engine, identity);
    public void Dispose() => _engine.Dispose();
}
