using System.Net.Sockets;
using SplitVpn.Core.Protection;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;
using Windows.Win32.Security;

namespace SplitVpn.Windows.Wfp;

/// <summary>Ключи провайдера и sublayer. У прототипа свои ключи и несуществующая служба.</summary>
public sealed record WfpIdentity(Guid ProviderKey, Guid SubLayerKey, string Name, string ServiceName)
{
    public static WfpIdentity Product { get; } = new(
        new Guid("5e1d6b6a-3c1f-4f7e-9a4e-2b8f0c6d7a11"),
        new Guid("5e1d6b6a-3c1f-4f7e-9a4e-2b8f0c6d7a12"),
        "Раздельный VPN",
        "SplitVpn");

    /// <summary>Служба не существует: при перезагрузке BFE отключит persistent-объекты прототипа.</summary>
    public static WfpIdentity Prototype { get; } = new(
        new Guid("5e1d6b6a-3c1f-4f7e-9a4e-2b8f0c6d7a21"),
        new Guid("5e1d6b6a-3c1f-4f7e-9a4e-2b8f0c6d7a22"),
        "Раздельный VPN (прототип)",
        "SplitVpnPrototypeNoSuchService");
}

public sealed record WfpFilterInfo(ulong Id, string Name, byte Weight, bool Persistent);

/// <summary>Преобразование плана фильтров в объекты WFP.</summary>
public static unsafe class WfpOps
{
    private const uint ProviderFlagPersistent = 0x00000001;
    private const uint SubLayerFlagPersistent = 0x00000001;
    private const uint ConditionFlagIsLoopback = 0x00000001;
    private const uint AlreadyExists = 0x80320009;
    private const uint NotFound = 0x80320008;
    private const uint FilterNotFound = 0x80320003;
    private const uint ProviderNotFound = 0x80320005;
    private const uint SubLayerNotFound = 0x80320007;
    private const uint SddlRevision1 = 1;

    /// <summary>
    /// Дескриптор безопасности «только SYSTEM» для условия ALE_USER_ID. WFP сверяет право FWP_ACTRL_MATCH_FILTER (0x1, в SDDL — CC);
    /// общие права в ACE при проверке не раскрываются, поэтому с GA условие не совпадало и разрешение «DNS службы» не действовало.
    /// </summary>
    private const string SystemOnlySddl = "O:SYD:(A;;CC;;;SY)";

    public static void EnsureProviderAndSubLayer(WfpEngine engine, WfpIdentity identity, bool persistent)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(identity);
        using var arena = new NativeArena();
        var providerKey = identity.ProviderKey;
        var provider = new FWPM_PROVIDER0
        {
            providerKey = providerKey,
            displayData = new FWPM_DISPLAY_DATA0 { name = new PWSTR(arena.String(identity.Name)) },
            flags = persistent ? ProviderFlagPersistent : 0,
            serviceName = new PWSTR(arena.String(identity.ServiceName)),
        };
        IgnoreExists(PInvoke.FwpmProviderAdd0(engine.Handle, &provider, default), "FwpmProviderAdd0");

        var subLayer = new FWPM_SUBLAYER0
        {
            subLayerKey = identity.SubLayerKey,
            displayData = new FWPM_DISPLAY_DATA0 { name = new PWSTR(arena.String(identity.Name)) },
            flags = persistent ? SubLayerFlagPersistent : 0,
            providerKey = &providerKey,
            weight = 0xFFFF,
        };
        IgnoreExists(PInvoke.FwpmSubLayerAdd0(engine.Handle, &subLayer, default), "FwpmSubLayerAdd0");
    }

    /// <summary>Добавляет фильтры на все слои семейства; возвращает идентификаторы для последующего удаления группы.</summary>
    public static IReadOnlyList<ulong> AddFilters(WfpEngine engine, WfpIdentity identity, IEnumerable<FilterSpec> specs, bool persistent, bool indexed = false)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(specs);
        var ids = new List<ulong>();
        using var cache = new ConditionCache();
        foreach (var spec in specs)
        {
            foreach (var layer in LayersOf(spec.Family))
            {
                ids.Add(AddFilter(engine, identity, spec, layer, persistent, indexed, cache));
            }
        }

        return ids;
    }

    /// <summary>
    /// Фильтр с таким идентификатором есть в BFE. Точечный запрос: перечисление всех фильтров системы
    /// стоит около 300 мс на 25 тыс. фильтров, и почти всё это время уходит на снимок внутри BFE.
    /// </summary>
    public static bool FilterExists(WfpEngine engine, ulong id)
    {
        ArgumentNullException.ThrowIfNull(engine);
        FWPM_FILTER0* filter = null;
        var code = PInvoke.FwpmFilterGetById0(engine.Handle, id, &filter);
        if (code is NotFound or FilterNotFound)
        {
            return false;
        }

        NativeCallException.ThrowIfFailed(code, "FwpmFilterGetById0");
        var memory = (void*)filter;
        PInvoke.FwpmFreeMemory0(&memory);
        return true;
    }

    public static void DeleteFilters(WfpEngine engine, IEnumerable<ulong> ids)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(ids);
        foreach (var id in ids)
        {
            var code = PInvoke.FwpmFilterDeleteById0(engine.Handle, id);
            if (code is not 0 and not NotFound and not FilterNotFound)
            {
                throw new NativeCallException("FwpmFilterDeleteById0", code);
            }
        }
    }

    public static IReadOnlyList<WfpFilterInfo> ListFilters(WfpEngine engine, WfpIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(identity);
        var result = new List<WfpFilterInfo>();
        FWPM_FILTER_ENUM_HANDLE enumHandle;
        NativeCallException.ThrowIfFailed(PInvoke.FwpmFilterCreateEnumHandle0(engine.Handle, null, &enumHandle), "FwpmFilterCreateEnumHandle0");
        FWPM_FILTER0** entries = null;
        try
        {
            uint count;
            NativeCallException.ThrowIfFailed(PInvoke.FwpmFilterEnum0(engine.Handle, enumHandle, uint.MaxValue, &entries, &count), "FwpmFilterEnum0");
            for (var i = 0; i < count; i++)
            {
                var filter = entries[i];
                if (filter->providerKey != null && *filter->providerKey == identity.ProviderKey)
                {
                    result.Add(new WfpFilterInfo(
                        filter->filterId,
                        filter->displayData.name.ToString() ?? "",
                        filter->weight.type == FWP_DATA_TYPE.FWP_UINT8 ? filter->weight.uint8 : (byte)0,
                        (filter->flags & FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_PERSISTENT) != 0));
                }
            }
        }
        finally
        {
            var memory = (void*)entries;
            PInvoke.FwpmFreeMemory0(&memory);
            _ = PInvoke.FwpmFilterDestroyEnumHandle0(engine.Handle, enumHandle);
        }

        return result;
    }

    /// <summary>Удаляет все фильтры провайдера, его sublayer и самого провайдера. Идемпотентно.</summary>
    public static int DeleteAll(WfpEngine engine, WfpIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(identity);
        var filters = ListFilters(engine, identity);
        engine.InTransaction(e =>
        {
            DeleteFilters(e, filters.Select(f => f.Id));
            var subLayerKey = identity.SubLayerKey;
            IgnoreNotFound(PInvoke.FwpmSubLayerDeleteByKey0(e.Handle, &subLayerKey), "FwpmSubLayerDeleteByKey0");
            var providerKey = identity.ProviderKey;
            IgnoreNotFound(PInvoke.FwpmProviderDeleteByKey0(e.Handle, &providerKey), "FwpmProviderDeleteByKey0");
        });
        return filters.Count;
    }

    private static ulong AddFilter(WfpEngine engine, WfpIdentity identity, FilterSpec spec, Guid layer, bool persistent, bool indexed, ConditionCache cache)
    {
        using var arena = new NativeArena();
        var providerKey = identity.ProviderKey;
        var conditions = arena.Alloc<FWPM_FILTER_CONDITION0>(spec.Conditions.Count);
        for (var i = 0; i < spec.Conditions.Count; i++)
        {
            conditions[i] = BuildCondition(spec.Conditions[i], arena, cache);
        }

        var flags = persistent ? FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_PERSISTENT : FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_NONE;
        if (indexed)
        {
            flags |= FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_INDEXED;
        }

        var filter = new FWPM_FILTER0
        {
            displayData = new FWPM_DISPLAY_DATA0 { name = new PWSTR(arena.String(spec.Name)) },
            flags = flags,
            providerKey = &providerKey,
            layerKey = layer,
            subLayerKey = identity.SubLayerKey,
            numFilterConditions = (uint)spec.Conditions.Count,
            filterCondition = spec.Conditions.Count == 0 ? null : conditions,
        };
        filter.weight.type = FWP_DATA_TYPE.FWP_UINT8;
        filter.weight.uint8 = spec.Weight;
        filter.action.type = spec.Action == FilterAction.Permit ? FWP_ACTION_TYPE.FWP_ACTION_PERMIT : FWP_ACTION_TYPE.FWP_ACTION_BLOCK;

        ulong id;
        var code = PInvoke.FwpmFilterAdd0(engine.Handle, &filter, default, &id);
        NativeCallException.ThrowIfFailed(code, "FwpmFilterAdd0 «" + spec.Name + "»");
        return id;
    }

    private static FWPM_FILTER_CONDITION0 BuildCondition(FilterCondition condition, NativeArena arena, ConditionCache cache) => condition switch
    {
        LoopbackCondition => Uint32(PInvoke.FWPM_CONDITION_FLAGS, FWP_MATCH_TYPE.FWP_MATCH_FLAGS_ALL_SET, ConditionFlagIsLoopback),
        RemoteRangeV4 r when r.Start == r.End => Uint32(PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, r.Start),
        RemoteRangeV4 r => Range32(PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS, r.Start, r.End, arena),
        RemotePrefixV6 p => PrefixV6(p, arena),
        RemotePortCondition p => Uint16(PInvoke.FWPM_CONDITION_IP_REMOTE_PORT, p.Port),
        LocalPortRange p when p.Low == p.High => Uint16(PInvoke.FWPM_CONDITION_IP_LOCAL_PORT, p.Low),
        LocalPortRange p => Range16(PInvoke.FWPM_CONDITION_IP_LOCAL_PORT, p.Low, p.High, arena),
        ProtocolCondition p => Uint8(PInvoke.FWPM_CONDITION_IP_PROTOCOL, p.Protocol),
        LocalInterfaceCondition i => Interface(i, arena),
        AppIdCondition a => Blob(PInvoke.FWPM_CONDITION_ALE_APP_ID, FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE, cache.AppId(a.ExecutablePath)),
        LocalSystemUserCondition => Blob(PInvoke.FWPM_CONDITION_ALE_USER_ID, FWP_DATA_TYPE.FWP_SECURITY_DESCRIPTOR_TYPE, cache.SystemOnlyDescriptor()),
        _ => throw new NotSupportedException("Неизвестное условие фильтра: " + condition.GetType().Name),
    };

    private static FWPM_FILTER_CONDITION0 Uint32(Guid field, FWP_MATCH_TYPE match, uint value)
    {
        var condition = new FWPM_FILTER_CONDITION0 { fieldKey = field, matchType = match };
        condition.conditionValue.type = FWP_DATA_TYPE.FWP_UINT32;
        condition.conditionValue.uint32 = value;
        return condition;
    }

    private static FWPM_FILTER_CONDITION0 Uint16(Guid field, ushort value)
    {
        var condition = new FWPM_FILTER_CONDITION0 { fieldKey = field, matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL };
        condition.conditionValue.type = FWP_DATA_TYPE.FWP_UINT16;
        condition.conditionValue.uint16 = value;
        return condition;
    }

    private static FWPM_FILTER_CONDITION0 Uint8(Guid field, byte value)
    {
        var condition = new FWPM_FILTER_CONDITION0 { fieldKey = field, matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL };
        condition.conditionValue.type = FWP_DATA_TYPE.FWP_UINT8;
        condition.conditionValue.uint8 = value;
        return condition;
    }

    private static FWPM_FILTER_CONDITION0 Range32(Guid field, uint low, uint high, NativeArena arena)
    {
        var range = arena.Alloc<FWP_RANGE0>();
        range->valueLow.type = FWP_DATA_TYPE.FWP_UINT32;
        range->valueLow.uint32 = low;
        range->valueHigh.type = FWP_DATA_TYPE.FWP_UINT32;
        range->valueHigh.uint32 = high;
        return RangeCondition(field, range);
    }

    private static FWPM_FILTER_CONDITION0 Range16(Guid field, ushort low, ushort high, NativeArena arena)
    {
        var range = arena.Alloc<FWP_RANGE0>();
        range->valueLow.type = FWP_DATA_TYPE.FWP_UINT16;
        range->valueLow.uint16 = low;
        range->valueHigh.type = FWP_DATA_TYPE.FWP_UINT16;
        range->valueHigh.uint16 = high;
        return RangeCondition(field, range);
    }

    private static FWPM_FILTER_CONDITION0 RangeCondition(Guid field, FWP_RANGE0* range)
    {
        var condition = new FWPM_FILTER_CONDITION0 { fieldKey = field, matchType = FWP_MATCH_TYPE.FWP_MATCH_RANGE };
        condition.conditionValue.type = FWP_DATA_TYPE.FWP_RANGE_TYPE;
        condition.conditionValue.rangeValue = range;
        return condition;
    }

    private static FWPM_FILTER_CONDITION0 PrefixV6(RemotePrefixV6 prefix, NativeArena arena)
    {
        if (prefix.Network.BaseAddress.AddressFamily != AddressFamily.InterNetworkV6)
        {
            throw new ArgumentException("Ожидается IPv6-сеть.", nameof(prefix));
        }

        var mask = arena.Alloc<FWP_V6_ADDR_AND_MASK>();
        prefix.Network.BaseAddress.TryWriteBytes(mask->addr.AsSpan(), out _);
        mask->prefixLength = (byte)prefix.Network.PrefixLength;
        var condition = new FWPM_FILTER_CONDITION0 { fieldKey = PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS, matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL };
        condition.conditionValue.type = FWP_DATA_TYPE.FWP_V6_ADDR_MASK;
        condition.conditionValue.v6AddrMask = mask;
        return condition;
    }

    private static FWPM_FILTER_CONDITION0 Interface(LocalInterfaceCondition condition, NativeArena arena)
    {
        var result = new FWPM_FILTER_CONDITION0
        {
            fieldKey = PInvoke.FWPM_CONDITION_IP_LOCAL_INTERFACE,
            matchType = condition.NotEqual ? FWP_MATCH_TYPE.FWP_MATCH_NOT_EQUAL : FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
        };
        result.conditionValue.type = FWP_DATA_TYPE.FWP_UINT64;
        result.conditionValue.uint64 = arena.Value(condition.Luid);
        return result;
    }

    private static FWPM_FILTER_CONDITION0 Blob(Guid field, FWP_DATA_TYPE type, FWP_BYTE_BLOB* blob)
    {
        var condition = new FWPM_FILTER_CONDITION0 { fieldKey = field, matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL };
        condition.conditionValue.type = type;
        condition.conditionValue.byteBlob = blob;
        return condition;
    }

    private static IEnumerable<Guid> LayersOf(FilterFamily family)
    {
        if (family is FilterFamily.V4 or FilterFamily.Both)
        {
            yield return PInvoke.FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            yield return PInvoke.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
        }

        if (family is FilterFamily.V6 or FilterFamily.Both)
        {
            yield return PInvoke.FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            yield return PInvoke.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
        }
    }

    private static void IgnoreExists(uint code, string operation)
    {
        if (code is not 0 and not AlreadyExists)
        {
            throw new NativeCallException(operation, code);
        }
    }

    private static void IgnoreNotFound(uint code, string operation)
    {
        if (code is not 0 and not NotFound and not ProviderNotFound and not SubLayerNotFound)
        {
            throw new NativeCallException(operation, code);
        }
    }

    /// <summary>App-id и дескриптор безопасности выделяются один раз на пакет фильтров.</summary>
    private sealed class ConditionCache : IDisposable
    {
        private readonly Dictionary<string, nint> _appIds = new(StringComparer.OrdinalIgnoreCase);
        private readonly NativeArena _arena = new();
        private FWP_BYTE_BLOB* _systemDescriptor;

        public FWP_BYTE_BLOB* AppId(string path)
        {
            if (_appIds.TryGetValue(path, out var existing))
            {
                return (FWP_BYTE_BLOB*)existing;
            }

            var address = ReadAppId(path);
            _appIds[path] = address;
            _arena.OnDispose(() =>
            {
                var memory = (void*)address;
                PInvoke.FwpmFreeMemory0(&memory);
            });
            return (FWP_BYTE_BLOB*)address;
        }

        public FWP_BYTE_BLOB* SystemOnlyDescriptor()
        {
            if (_systemDescriptor != null)
            {
                return _systemDescriptor;
            }

            if (!PInvoke.ConvertStringSecurityDescriptorToSecurityDescriptor(SystemOnlySddl, SddlRevision1, out var descriptor, out var size))
            {
                throw new NativeCallException("ConvertStringSecurityDescriptorToSecurityDescriptor", (uint)System.Runtime.InteropServices.Marshal.GetLastPInvokeError());
            }

            _arena.OnDispose(() => PInvoke.LocalFree(new HLOCAL((void*)descriptor.Value)));
            _systemDescriptor = _arena.Alloc<FWP_BYTE_BLOB>();
            _systemDescriptor->size = size;
            _systemDescriptor->data = (byte*)descriptor.Value;
            return _systemDescriptor;
        }

        public void Dispose() => _arena.Dispose();

        private static nint ReadAppId(string path)
        {
            FWP_BYTE_BLOB* blob;
            fixed (char* p = path)
            {
                NativeCallException.ThrowIfFailed(PInvoke.FwpmGetAppIdFromFileName0(new PCWSTR(p), &blob), "FwpmGetAppIdFromFileName0");
            }

            return (nint)blob;
        }
    }
}
