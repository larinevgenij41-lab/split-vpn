using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace SplitVpn.Windows.Wfp;

public sealed record WfpProviderInfo(Guid Key, string Name, string? ServiceName, bool Persistent, bool Disabled);

public sealed record WfpSubLayerInfo(Guid Key, string Name, ushort Weight, Guid? ProviderKey, int FilterCount, int HardPermitCount);

public sealed record WfpInventory(IReadOnlyList<WfpProviderInfo> Providers, IReadOnlyList<WfpSubLayerInfo> SubLayers, int TotalFilters);

/// <summary>Чтение чужих и собственных объектов WFP для диагностики (только чтение).</summary>
public static unsafe class WfpInspector
{
    private const uint ProviderFlagPersistent = 0x00000001;
    private const uint ProviderFlagDisabled = 0x00000010;
    private const uint EnumAll = uint.MaxValue;

    private static readonly HashSet<Guid> AleLayers =
    [
        PInvoke.FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        PInvoke.FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        PInvoke.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        PInvoke.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ];

    public static WfpInventory Capture()
    {
        using var engine = WfpEngine.Open(dynamicSession: true);
        var filters = ReadFilterStats(engine);
        return new WfpInventory(ReadProviders(engine), ReadSubLayers(engine, filters), filters.Values.Sum(f => f.Total));
    }

    private static List<WfpProviderInfo> ReadProviders(WfpEngine engine)
    {
        var handle = engine.Handle;
        FWPM_PROVIDER_ENUM_HANDLE enumHandle;
        NativeCallException.ThrowIfFailed(PInvoke.FwpmProviderCreateEnumHandle0(handle, null, &enumHandle), "FwpmProviderCreateEnumHandle0");
        FWPM_PROVIDER0** entries = null;
        try
        {
            uint count;
            NativeCallException.ThrowIfFailed(PInvoke.FwpmProviderEnum0(handle, enumHandle, EnumAll, &entries, &count), "FwpmProviderEnum0");
            var result = new List<WfpProviderInfo>((int)count);
            for (var i = 0; i < count; i++)
            {
                var p = entries[i];
                result.Add(new WfpProviderInfo(
                    p->providerKey,
                    p->displayData.name.ToString() ?? "",
                    p->serviceName.Value == null ? null : p->serviceName.ToString(),
                    (p->flags & ProviderFlagPersistent) != 0,
                    (p->flags & ProviderFlagDisabled) != 0));
            }

            return result;
        }
        finally
        {
            var memory = (void*)entries;
            PInvoke.FwpmFreeMemory0(&memory);
            _ = PInvoke.FwpmProviderDestroyEnumHandle0(handle, enumHandle);
        }
    }

    private static List<WfpSubLayerInfo> ReadSubLayers(WfpEngine engine, Dictionary<Guid, (int Total, int HardPermit)> filters)
    {
        var handle = engine.Handle;
        FWPM_SUBLAYER_ENUM_HANDLE enumHandle;
        NativeCallException.ThrowIfFailed(PInvoke.FwpmSubLayerCreateEnumHandle0(handle, null, &enumHandle), "FwpmSubLayerCreateEnumHandle0");
        FWPM_SUBLAYER0** entries = null;
        try
        {
            uint count;
            NativeCallException.ThrowIfFailed(PInvoke.FwpmSubLayerEnum0(handle, enumHandle, EnumAll, &entries, &count), "FwpmSubLayerEnum0");
            var result = new List<WfpSubLayerInfo>((int)count);
            for (var i = 0; i < count; i++)
            {
                var s = entries[i];
                var stats = filters.GetValueOrDefault(s->subLayerKey);
                result.Add(new WfpSubLayerInfo(
                    s->subLayerKey,
                    s->displayData.name.ToString() ?? "",
                    s->weight,
                    s->providerKey == null ? null : *s->providerKey,
                    stats.Total,
                    stats.HardPermit));
            }

            return result;
        }
        finally
        {
            var memory = (void*)entries;
            PInvoke.FwpmFreeMemory0(&memory);
            _ = PInvoke.FwpmSubLayerDestroyEnumHandle0(handle, enumHandle);
        }
    }

    private static Dictionary<Guid, (int Total, int HardPermit)> ReadFilterStats(WfpEngine engine)
    {
        var handle = engine.Handle;
        FWPM_FILTER_ENUM_HANDLE enumHandle;
        NativeCallException.ThrowIfFailed(PInvoke.FwpmFilterCreateEnumHandle0(handle, null, &enumHandle), "FwpmFilterCreateEnumHandle0");
        FWPM_FILTER0** entries = null;
        try
        {
            uint count;
            NativeCallException.ThrowIfFailed(PInvoke.FwpmFilterEnum0(handle, enumHandle, EnumAll, &entries, &count), "FwpmFilterEnum0");
            var result = new Dictionary<Guid, (int Total, int HardPermit)>();
            for (var i = 0; i < count; i++)
            {
                var f = entries[i];
                var current = result.GetValueOrDefault(f->subLayerKey);
                var hardPermit = IsHardPermit(f) ? 1 : 0;
                result[f->subLayerKey] = (current.Total + 1, current.HardPermit + hardPermit);
            }

            return result;
        }
        finally
        {
            var memory = (void*)entries;
            PInvoke.FwpmFreeMemory0(&memory);
            _ = PInvoke.FwpmFilterDestroyEnumHandle0(handle, enumHandle);
        }
    }

    private static bool IsHardPermit(FWPM_FILTER0* filter)
    {
        return filter->action.type == FWP_ACTION_TYPE.FWP_ACTION_PERMIT
            && (filter->flags & FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) != 0
            && AleLayers.Contains(filter->layerKey);
    }
}
