using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Windows.Win32.NetworkManagement.IpHelper;

namespace SplitVpn.Windows.Net;

/// <summary>
/// Уведомления IP Helper о смене сети: интерфейс поднялся или лёг, адаптер получил адрес, появился или
/// исчез маршрут по умолчанию. Служба по ним сверяется сразу, не дожидаясь очередного тика: пока новый
/// Wi-Fi не стал основным адаптером, защита держит его заблокированным, а Windows, не видя интернета,
/// может сама перезапустить адаптер («ограниченные возможности подключения»).
/// Маршруты, кроме 0.0.0.0/0, не сообщаются: служба сама ставит их тысячами.
/// Обработчик вызывается из потоков IP Helper и не должен блокировать.
/// </summary>
public sealed unsafe partial class NetworkChangeWatcher : IDisposable
{
    private const ushort AfInet = 2;

    private readonly Action _changed;
    private GCHandle _self;
    private nint _interfaceHandle;
    private nint _addressHandle;
    private nint _routeHandle;

    private NetworkChangeWatcher(Action changed) => _changed = changed;

    /// <summary>Подписка на изменения IPv4. Ошибка регистрации — исключение; частичная подписка снимается.</summary>
    public static NetworkChangeWatcher Start(Action changed)
    {
        ArgumentNullException.ThrowIfNull(changed);
        var watcher = new NetworkChangeWatcher(changed);
        watcher._self = GCHandle.Alloc(watcher);
        try
        {
            var context = GCHandle.ToIntPtr(watcher._self);
            nint handle;
            Check(NotifyIpInterfaceChange(AfInet, &OnInterface, context, 0, &handle), "NotifyIpInterfaceChange");
            watcher._interfaceHandle = handle;
            Check(NotifyUnicastIpAddressChange(AfInet, &OnAddress, context, 0, &handle), "NotifyUnicastIpAddressChange");
            watcher._addressHandle = handle;
            Check(NotifyRouteChange2(AfInet, &OnRoute, context, 0, &handle), "NotifyRouteChange2");
            watcher._routeHandle = handle;
            return watcher;
        }
        catch
        {
            watcher.Dispose();
            throw;
        }
    }

    /// <summary>Только маршрут по умолчанию: остальные маршруты служба ставит сама.</summary>
    internal static bool IsRelevantRoute(MIB_IPFORWARD_ROW2* row) => row is null || IsRelevantRoute(in *row);

    internal static bool IsRelevantRoute(in MIB_IPFORWARD_ROW2 row) => row.DestinationPrefix.PrefixLength == 0;

    public void Dispose()
    {
        // CancelMibChangeNotify2 дожидается выполняющихся обработчиков: после него контекст можно освобождать.
        Cancel(ref _interfaceHandle);
        Cancel(ref _addressHandle);
        Cancel(ref _routeHandle);
        if (_self.IsAllocated)
        {
            _self.Free();
        }
    }

    private static void Cancel(ref nint handle)
    {
        if (handle != 0)
        {
            _ = CancelMibChangeNotify2(handle);
            handle = 0;
        }
    }

    private static void Check(uint code, string function)
    {
        if (code != 0)
        {
            throw new Native.NativeCallException(function, code);
        }
    }

    private static void Raise(nint context)
    {
        try
        {
            if (GCHandle.FromIntPtr(context).Target is NetworkChangeWatcher watcher)
            {
                watcher._changed();
            }
        }
        catch (Exception)
        {
            // Исключение не должно уйти в поток IP Helper: тик всё равно заметит изменение.
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static void OnInterface(nint context, void* row, int type) => Raise(context);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static void OnAddress(nint context, void* row, int type) => Raise(context);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static void OnRoute(nint context, void* row, int type)
    {
        if (IsRelevantRoute((MIB_IPFORWARD_ROW2*)row))
        {
            Raise(context);
        }
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint NotifyIpInterfaceChange(ushort family, delegate* unmanaged[Stdcall]<nint, void*, int, void> callback, nint context, byte initialNotification, nint* handle);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint NotifyUnicastIpAddressChange(ushort family, delegate* unmanaged[Stdcall]<nint, void*, int, void> callback, nint context, byte initialNotification, nint* handle);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint NotifyRouteChange2(ushort family, delegate* unmanaged[Stdcall]<nint, void*, int, void> callback, nint context, byte initialNotification, nint* handle);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint CancelMibChangeNotify2(nint handle);
}
