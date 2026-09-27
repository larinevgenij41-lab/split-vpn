using System.Collections.Concurrent;
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
    private const uint ErrorFileNotFound = 2;
    private const ulong SettingIpv6 = 0x0001;
    private const ulong SettingNameServer = 0x0002;
    private const ulong SettingSearchList = 0x0004;

    /// <summary>
    /// Настройки одного семейства адресов. Документация велит оставлять Flags пустым, но проверка на
    /// Windows 11 показала: без DNS_SETTING_IPV6 возвращаются настройки IPv4, поэтому для IPv6 флаг нужен.
    /// Структура версии 3 есть только в Windows 11: на Windows 10 чтение повторяется с версией 1 (без DoH).
    /// </summary>
    public static InterfaceDnsState Read(Guid interfaceGuid, bool ipv6)
    {
        var settings = new DNS_INTERFACE_SETTINGS3 { Version = Version3, Flags = ipv6 ? SettingIpv6 : 0 };
        var code = (uint)PInvoke.GetInterfaceDnsSettings(interfaceGuid, (DNS_INTERFACE_SETTINGS*)&settings);
        if (code is not 0 and not ErrorFileNotFound)
        {
            return ReadVersion1(interfaceGuid, ipv6);
        }

        NativeCallException.ThrowIfFailed(code, "GetInterfaceDnsSettings");
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

    private static InterfaceDnsState ReadVersion1(Guid interfaceGuid, bool ipv6)
    {
        var settings = new DNS_INTERFACE_SETTINGS { Version = Version1, Flags = ipv6 ? SettingIpv6 : 0 };
        var code = PInvoke.GetInterfaceDnsSettings(interfaceGuid, &settings);
        NativeCallException.ThrowIfFailed((uint)code, "GetInterfaceDnsSettings");
        try
        {
            return new InterfaceDnsState(
                settings.NameServer.ToString() ?? "",
                settings.ProfileNameServer.ToString() ?? "",
                0,
                settings.SearchList.ToString() ?? "");
        }
        finally
        {
            PInvoke.FreeInterfaceDnsSettings(&settings);
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

    /// <summary>
    /// IPv6-настройки DNS или null, если их нет: у адаптера без IPv6 (PPP SSTP/L2TP без IPv6CP, отвязанный
    /// протокол) чтение даёт ERROR_FILE_NOT_FOUND и другие ошибки. IPv6 для посредника необязателен, поэтому
    /// такой адаптер считается «IPv6 нет»; ошибки IPv4 по-прежнему бросаются вызывающему.
    /// </summary>
    public static InterfaceDnsState? TryReadIpv6(Guid interfaceGuid)
    {
        try
        {
            return Read(interfaceGuid, ipv6: true);
        }
        catch (NativeCallException ex)
        {
            WarnIpv6Once(interfaceGuid, ex);
            return null;
        }
    }

    /// <summary>Запись IPv6-списка DNS без исключений: адаптер без IPv6 пропускается (см. <see cref="TryReadIpv6"/>).</summary>
    public static bool TrySetIpv6NameServer(Guid interfaceGuid, string nameServers)
    {
        try
        {
            SetNameServer(interfaceGuid, nameServers, ipv6: true);
            return true;
        }
        catch (NativeCallException ex)
        {
            WarnIpv6Once(interfaceGuid, ex);
            return false;
        }
    }

    /// <summary>Сверка повторяется каждую минуту: об адаптере без IPv6 достаточно сообщить один раз.</summary>
    private static readonly ConcurrentDictionary<Guid, byte> s_ipv6Warned = new();

    private static void WarnIpv6Once(Guid interfaceGuid, NativeCallException ex)
    {
        if (s_ipv6Warned.TryAdd(interfaceGuid, 0))
        {
            Trace.TraceWarning("IPv6-настройки DNS интерфейса {0} недоступны, IPv6 пропущен: {1}", interfaceGuid, ex.Message);
        }
    }

    /// <summary>
    /// Снимок исходного состояния. Loopback считается нашим, только если по интерфейсу уже есть копия
    /// (previous): без неё это статический DNS пользователя (свой резолвер на 127.0.0.1) и он сохраняется как есть.
    /// Исключение — ::1 при ownsIpv6Loopback: посредник сам занимает [::1]:53, и чужого резолвера там быть не
    /// может, значит ::1 остался от прежнего запуска (например, копия пропала) и исходным не считается.
    /// </summary>
    public static InterfaceDnsBackup Capture(Guid interfaceGuid, InterfaceDnsBackup? previous, DateTimeOffset now, bool ownsIpv6Loopback = false)
    {
        var v4 = Read(interfaceGuid, ipv6: false);
        var v6 = TryReadIpv6(interfaceGuid)?.NameServer ?? "";
        return new InterfaceDnsBackup(interfaceGuid, Original(v4.NameServer, previous?.NameServerV4), OriginalV6(v6, previous?.NameServerV6, ownsIpv6Loopback),
            v4.ProfileNameServer, v4.DohServerProperties, now, v4.SearchList);
    }

    internal static string Original(string current, string? previous) =>
        IsLoopback(current) && previous is not null ? previous : current;

    internal static string OriginalV6(string current, string? previous, bool ownsIpv6Loopback) =>
        previous is null && ownsIpv6Loopback && IsLoopback(current) ? "" : Original(current, previous);

    /// <summary>
    /// Ставит адаптеру DNS-посредник. ::1 — только если посредник занял и этот адрес: иначе там может
    /// отвечать чужой процесс. Без ::1 IPv6-список не трогается вовсе: там может стоять собственный ::1
    /// пользователя, и снятие его потеряло бы (копия хранит его как исходный). Адаптер без IPv6 пропускается.
    /// </summary>
    public static void ApplyLoopback(Guid interfaceGuid, bool ipv6Loopback = true)
    {
        SetNameServer(interfaceGuid, LoopbackV4, ipv6: false);
        if (ipv6Loopback)
        {
            TrySetIpv6NameServer(interfaceGuid, LoopbackV6);
        }
    }

    /// <summary>
    /// Возвращает исходные серверы, только если на интерфейсе всё ещё наш loopback. IPv6 из копии
    /// возвращается и тогда, когда там сейчас пусто, а IPv4 — наш loopback: посредник без [::1]:53 IPv6 не
    /// ставил, но прежний запуск мог снять ::1 пользователя.
    /// </summary>
    public static DnsRestoreOutcome Restore(Guid interfaceGuid, InterfaceDnsBackup? backup)
    {
        var v4 = Read(interfaceGuid, ipv6: false);
        var v6 = TryReadIpv6(interfaceGuid);
        // Суффиксы шлюзов AnyConnect в списке поиска добавила служба: исходный список возвращается при любом исходе.
        if (backup is not null && !string.Equals(v4.SearchList, backup.SearchList, StringComparison.OrdinalIgnoreCase))
        {
            SetSearchList(interfaceGuid, backup.SearchList);
        }

        var v4Ours = IsLoopback(v4.NameServer);
        var v6Current = v6?.NameServer ?? "";
        if (!v4Ours && !IsLoopback(v6Current))
        {
            return string.IsNullOrEmpty(v4.NameServer) && string.IsNullOrEmpty(v6Current)
                ? DnsRestoreOutcome.NothingToRestore
                : DnsRestoreOutcome.ChangedByUser;
        }

        if (v4Ours)
        {
            SetNameServer(interfaceGuid, backup?.NameServerV4 ?? "", ipv6: false);
        }

        var v6Original = backup?.NameServerV6 ?? "";
        if (v6 is not null && (IsLoopback(v6Current) || (v4Ours && v6Current.Length == 0))
            && !string.Equals(v6Current, v6Original, StringComparison.OrdinalIgnoreCase))
        {
            TrySetIpv6NameServer(interfaceGuid, v6Original);
        }

        return DnsRestoreOutcome.Restored;
    }

    /// <summary>
    /// На адаптере ровно набор посредника: IPv4 — только 127.0.0.1, IPv6 — пусто или только ::1.
    /// </summary>
    public static bool IsOnlyProxyLoopback(string nameServerV4, string nameServerV6)
    {
        var v4 = nameServerV4.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        var v6 = nameServerV6.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        return v4.Length > 0 && v4.All(p => p == LoopbackV4) && v6.All(p => p == LoopbackV6);
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
