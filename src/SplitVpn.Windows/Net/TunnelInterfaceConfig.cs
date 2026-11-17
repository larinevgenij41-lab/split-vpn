using System.ComponentModel;
using Windows.Win32;
using Windows.Win32.NetworkManagement.IpHelper;
using Windows.Win32.NetworkManagement.Ndis;
using Windows.Win32.Networking.WinSock;

namespace SplitVpn.Windows.Net;

/// <summary>
/// Настройка адаптера Wintun, созданного libopenconnect: адрес и MTU. Маршруты и DNS на нём не
/// ставятся — ими владеет служба. Адрес назначается с префиксом /32, чтобы Windows не добавила
/// подсетевой маршрут без метки приложения (его бы увидел ConflictDetector как чужой).
/// </summary>
public static unsafe partial class TunnelInterfaceConfig
{
    private const uint ErrorObjectAlreadyExists = 5010;
    private const uint ErrorNotFound = 1168;

    /// <summary>Метрика интерфейса туннеля: выше физических, чтобы маршрут по умолчанию на него не попадал.</summary>
    public const uint InterfaceMetric = 9000;

    private const string NetworkClassKey = @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    /// <summary>
    /// Удаляет запись сетевого подключения Wintun с этим именем, если её устройства больше нет. Такая запись
    /// остаётся после завершения сеанса: устройство удалено, а имя в реестре (и LUID в NSI) осталось. libopenconnect находит
    /// адаптер по имени, не может его открыть и завершается ошибкой «Could not open Wintun adapter», не создавая новый.
    /// Возвращает число удалённых записей.
    /// </summary>
    public static int RemoveStaleWintunEntries(string alias)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        using var network = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(NetworkClassKey, writable: true);
        if (network is null)
        {
            return 0;
        }

        var removed = 0;
        foreach (var name in network.GetSubKeyNames())
        {
            using (var connection = network.OpenSubKey(name + @"\Connection"))
            {
                if (connection?.GetValue("Name") is not string connectionName
                    || !string.Equals(connectionName, alias, StringComparison.OrdinalIgnoreCase)
                    || connection.GetValue("PnPInstanceId") is not string instance
                    || !instance.StartsWith(@"SWD\Wintun\", StringComparison.OrdinalIgnoreCase)
                    || DevicePresent(instance))
                {
                    continue;
                }
            }

            network.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
            removed++;
        }

        return removed;
    }

    internal static bool IsPresentWintun(ulong luid)
    {
        if (PInvoke.ConvertInterfaceLuidToGuid(new NET_LUID_LH { Value = luid }, out var guid) != 0)
        {
            return false;
        }

        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(NetworkClassKey + @"\" + guid.ToString("B") + @"\Connection");
        return key?.GetValue("PnPInstanceId") is string instance
            && instance.StartsWith(@"SWD\Wintun\", StringComparison.OrdinalIgnoreCase) && DevicePresent(instance);
    }

    /// <summary>Устройство с этим PnP-идентификатором подключено (CM_LOCATE_DEVNODE_NORMAL находит только присутствующие).</summary>
    private static bool DevicePresent(string instanceId)
    {
        const uint CrSuccess = 0;
        return CM_Locate_DevNodeW(out _, instanceId, 0) == CrSuccess;
    }

    [System.Runtime.InteropServices.LibraryImport("cfgmgr32.dll", StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf16)]
    private static partial uint CM_Locate_DevNodeW(out uint devInst, string deviceId, uint flags);

    /// <summary>LUID адаптера по его имени; null — адаптера нет.</summary>
    public static ulong? FindLuid(string alias)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        NET_LUID_LH luid;
        fixed (char* name = alias)
        {
            return PInvoke.ConvertInterfaceAliasToLuid(name, &luid) == 0 ? luid.Value : null;
        }
    }

    /// <summary>
    /// Назначает адрес /32 и MTU; повторный вызов с тем же адресом не ошибка. После переподключения шлюз может
    /// выдать другой адрес: прежние IPv4-адреса адаптера снимаются, чтобы Windows не отправляла пакеты с ними.
    /// </summary>
    public static void Configure(ulong luid, uint address, int mtu) => Configure(luid, address, mtu, replaceWrongPrefix: false);

    /// <param name="replaceWrongPrefix">
    /// Адрес уже назначен самим процессом туннеля, возможно, с другой длиной префикса: тогда он снимается и
    /// назначается заново как /32. Иначе Windows держала бы маршрут подсети без метки программы.
    /// </param>
    public static void Configure(ulong luid, uint address, int mtu, bool replaceWrongPrefix)
    {
        if (replaceWrongPrefix)
        {
            RemoveAddresses(luid, address, wrongPrefixOnly: true);
        }

        AssignAddress(luid, address);
        RemoveAddresses(luid, address, wrongPrefixOnly: false);
        SetMtuAndMetric(luid, mtu);
    }

    /// <summary>Снимает с адаптера все IPv4-адреса, кроме заданного; либо только заданный, если его префикс не /32.</summary>
    private static void RemoveAddresses(ulong luid, uint keep, bool wrongPrefixOnly)
    {
        var error = (uint)PInvoke.GetUnicastIpAddressTable(ADDRESS_FAMILY.AF_INET, out var table);
        if (error != 0)
        {
            throw new Win32Exception((int)error, "Не удалось прочитать адреса туннеля AnyConnect");
        }

        try
        {
            var keepNetwork = NetInventory.ToNetworkOrder(keep);
            foreach (ref var row in table->Table.AsSpan((int)table->NumEntries))
            {
                var same = row.Address.Ipv4.sin_addr.S_un.S_addr == keepNetwork;
                if (row.InterfaceLuid.Value != luid || (wrongPrefixOnly ? !same || row.OnLinkPrefixLength == 32 : same))
                {
                    continue;
                }

                fixed (MIB_UNICASTIPADDRESS_ROW* stale = &row)
                {
                    var deleted = (uint)PInvoke.DeleteUnicastIpAddressEntry(stale);
                    if (deleted != 0 && deleted != ErrorNotFound)
                    {
                        throw new Win32Exception((int)deleted, "Не удалось снять прежний адрес туннеля AnyConnect");
                    }
                }
            }
        }
        finally
        {
            PInvoke.FreeMibTable(table);
        }
    }

    private static void AssignAddress(ulong luid, uint address)
    {
        MIB_UNICASTIPADDRESS_ROW row;
        PInvoke.InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid.Value = luid;
        row.Address.si_family = ADDRESS_FAMILY.AF_INET;
        row.Address.Ipv4.sin_family = ADDRESS_FAMILY.AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = NetInventory.ToNetworkOrder(address);
        row.OnLinkPrefixLength = 32;
        row.DadState = NL_DAD_STATE.IpDadStatePreferred;
        var created = (uint)PInvoke.CreateUnicastIpAddressEntry(&row);
        if (created != 0 && created != ErrorObjectAlreadyExists)
        {
            throw new Win32Exception((int)created, "Не удалось назначить адрес туннелю AnyConnect");
        }
    }

    private static void SetMtuAndMetric(ulong luid, int mtu)
    {
        MIB_IPINTERFACE_ROW ip;
        PInvoke.InitializeIpInterfaceEntry(&ip);
        ip.Family = ADDRESS_FAMILY.AF_INET;
        ip.InterfaceLuid.Value = luid;
        var read = (uint)PInvoke.GetIpInterfaceEntry(&ip);
        if (read != 0)
        {
            throw new Win32Exception((int)read, "Не удалось прочитать параметры интерфейса туннеля AnyConnect");
        }

        if (mtu > 0)
        {
            ip.NlMtu = (uint)mtu;
        }

        ip.UseAutomaticMetric = false;
        ip.Metric = InterfaceMetric;
        // Для IPv4 SetIpInterfaceEntry требует нулевой SitePrefixLength.
        ip.SitePrefixLength = 0;
        var written = (uint)PInvoke.SetIpInterfaceEntry(&ip);
        if (written != 0)
        {
            throw new Win32Exception((int)written, "Не удалось задать MTU и метрику туннеля AnyConnect");
        }
    }
}
