using System.Diagnostics;
using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.IpHelper;

namespace SplitVpn.Windows.Dns;

/// <summary>Исходные DNS-настройки интерфейса до установки loopback.</summary>
public sealed record InterfaceDnsBackup(
    Guid InterfaceGuid,
    string NameServerV4,
    string NameServerV6,
    string ProfileNameServerV4,
    int DohServerPropertiesV4,
    DateTimeOffset SavedUtc,
    string SearchList = "");

public sealed record InterfaceDnsState(string NameServer, string ProfileNameServer, int DohServerProperties, string SearchList = "");

public enum DnsRestoreOutcome
{
    Restored,
    ChangedByUser,
    NothingToRestore,
}

/// <summary>DNS-настройки интерфейсов через Get/SetInterfaceDnsSettings (Windows 10 2004+).</summary>
public static unsafe class InterfaceDnsOps
{
    public const string LoopbackV4 = "127.0.0.1";
    public const string LoopbackV6 = "::1";

    private const uint Version1 = 1;
    private const uint Version3 = 3;
    private const ulong SettingIpv6 = 0x0001;
    private const ulong SettingNameServer = 0x0002;
    private const ulong SettingSearchList = 0x0004;

    public static InterfaceDnsState Read(Guid interfaceGuid, bool ipv6)
    {
        var settings = new DNS_INTERFACE_SETTINGS3 { Version = Version3, Flags = ipv6 ? SettingIpv6 : 0 };
        var code = PInvoke.GetInterfaceDnsSettings(interfaceGuid, (DNS_INTERFACE_SETTINGS*)&settings);
        NativeCallException.ThrowIfFailed((uint)code, "GetInterfaceDnsSettings");
        try
        {
            return new InterfaceDnsState(
                settings.NameServer.ToString() ?? "",
                settings.ProfileNameServer.ToString() ?? "",
                (int)settings.cServerProperties,
                settings.SearchList.ToString() ?? "");
        }
        finally
        {
            PInvoke.FreeInterfaceDnsSettings((DNS_INTERFACE_SETTINGS*)&settings);
        }
    }

    /// <summary>Статический список DNS; пустая строка возвращает получение DNS по DHCP.</summary>
    public static void SetNameServer(Guid interfaceGuid, string nameServers, bool ipv6)
    {
        fixed (char* value = nameServers)
        {
            var settings = new DNS_INTERFACE_SETTINGS
            {
                Version = Version1,
                Flags = SettingNameServer | (ipv6 ? SettingIpv6 : 0),
                NameServer = new PWSTR(value),
            };
            var code = PInvoke.SetInterfaceDnsSettings(interfaceGuid, &settings);
            NativeCallException.ThrowIfFailed((uint)code, "SetInterfaceDnsSettings");
        }
    }

    /// <summary>Список поиска DNS-суффиксов адаптера через запятую; пустая строка очищает список.</summary>
    public static void SetSearchList(Guid interfaceGuid, string searchList)
    {
        fixed (char* value = searchList)
        {
            var settings = new DNS_INTERFACE_SETTINGS
            {
                Version = Version1,
                Flags = SettingSearchList,
                SearchList = new PWSTR(value),
            };
            var code = PInvoke.SetInterfaceDnsSettings(interfaceGuid, &settings);
            NativeCallException.ThrowIfFailed((uint)code, "SetInterfaceDnsSettings");
        }
    }

    /// <summary>Снимок исходного состояния. Loopback никогда не считается исходным значением.</summary>
    public static InterfaceDnsBackup Capture(Guid interfaceGuid, InterfaceDnsBackup? previous, DateTimeOffset now)
    {
        var v4 = Read(interfaceGuid, ipv6: false);
        var v6 = Read(interfaceGuid, ipv6: true);
        var nameV4 = IsLoopback(v4.NameServer) ? previous?.NameServerV4 ?? "" : v4.NameServer;
        var nameV6 = IsLoopback(v6.NameServer) ? previous?.NameServerV6 ?? "" : v6.NameServer;
        return new InterfaceDnsBackup(interfaceGuid, nameV4, nameV6, v4.ProfileNameServer, v4.DohServerProperties, now, v4.SearchList);
    }

    public static void ApplyLoopback(Guid interfaceGuid)
    {
        SetNameServer(interfaceGuid, LoopbackV4, ipv6: false);
        SetNameServer(interfaceGuid, LoopbackV6, ipv6: true);
    }

    /// <summary>Возвращает исходные серверы, только если на интерфейсе всё ещё наш loopback.</summary>
    public static DnsRestoreOutcome Restore(Guid interfaceGuid, InterfaceDnsBackup? backup)
    {
        var v4 = Read(interfaceGuid, ipv6: false);
        var v6 = Read(interfaceGuid, ipv6: true);
        // Суффиксы шлюзов AnyConnect в списке поиска добавила служба: исходный список возвращается при любом исходе.
        if (backup is not null && !string.Equals(v4.SearchList, backup.SearchList, StringComparison.OrdinalIgnoreCase))
        {
            SetSearchList(interfaceGuid, backup.SearchList);
        }

        if (!IsLoopback(v4.NameServer) && !IsLoopback(v6.NameServer))
        {
            return string.IsNullOrEmpty(v4.NameServer) && string.IsNullOrEmpty(v6.NameServer)
                ? DnsRestoreOutcome.NothingToRestore
                : DnsRestoreOutcome.ChangedByUser;
        }

        if (IsLoopback(v4.NameServer))
        {
            SetNameServer(interfaceGuid, backup?.NameServerV4 ?? "", ipv6: false);
        }

        if (IsLoopback(v6.NameServer))
        {
            SetNameServer(interfaceGuid, backup?.NameServerV6 ?? "", ipv6: true);
        }

        return DnsRestoreOutcome.Restored;
    }

    public static bool IsLoopback(string nameServers)
    {
        var parts = nameServers.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length > 0 && parts.All(p => p is LoopbackV4 or LoopbackV6);
    }

    public static void FlushResolverCache()
    {
        using var process = Process.Start(new ProcessStartInfo("ipconfig.exe", "/flushdns") { CreateNoWindow = true, UseShellExecute = false });
        process?.WaitForExit(10_000);
    }
}

/// <summary>Файл резервных копий DNS по интерфейсам; запись атомарная.</summary>
public sealed class DnsBackupStore(string path)
{
    /// <summary>Куда сообщать о повреждённом файле копий: журнал событий и предупреждение в статусе.</summary>
    public Action<CorruptFile>? OnCorrupt { get; set; }

    /// <summary>
    /// Резервные копии DNS. Повреждённый файл откладывается в копию и заменяется пустым набором: тогда
    /// восстановление вернёт адаптерам DNS по DHCP там, где стоит только наш loopback.
    /// </summary>
    public IReadOnlyDictionary<Guid, InterfaceDnsBackup> Load() => SafeFile.Load(
        path,
        Parse,
        () => new Dictionary<Guid, InterfaceDnsBackup>(),
        "Резервная копия DNS-настроек была повреждена и заменена пустой",
        OnCorrupt);

    /// <summary>Записи без интерфейса и повторы отбрасываются: дальше с ними работают только по GUID.</summary>
    private static Dictionary<Guid, InterfaceDnsBackup>? Parse(string text)
    {
        var items = JsonSerializer.Deserialize<List<InterfaceDnsBackup>>(text, JsonDefaults.Options);
        if (items is null)
        {
            return null;
        }

        var result = new Dictionary<Guid, InterfaceDnsBackup>();
        foreach (var item in items.Where(i => i is not null))
        {
            result[item.InterfaceGuid] = item with
            {
                NameServerV4 = item.NameServerV4 ?? "",
                NameServerV6 = item.NameServerV6 ?? "",
                ProfileNameServerV4 = item.ProfileNameServerV4 ?? "",
                SearchList = item.SearchList ?? "",
            };
        }

        return result;
    }

    public void Save(IEnumerable<InterfaceDnsBackup> backups)
    {
        AtomicFile.WriteAllText(path, JsonSerializer.Serialize(backups.ToList(), JsonDefaults.Options));
    }

    public void Upsert(InterfaceDnsBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        var all = Load().ToDictionary();
        all[backup.InterfaceGuid] = backup;
        Save(all.Values);
    }

    public void Remove(Guid interfaceGuid)
    {
        var all = Load().ToDictionary();
        if (all.Remove(interfaceGuid))
        {
            Save(all.Values);
        }
    }
}
