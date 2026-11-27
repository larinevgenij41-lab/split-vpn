using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.IpHelper;

namespace SplitVpn.Windows.Dns;

/// <summary>Исходные DNS-настройки интерфейса до установки loopback.</summary>
/// <param name="Ipv6Unknown">
/// Исходный IPv6-список неизвестен: при снимке его чтение не удалось временно (не «IPv6 нет»), а прежней копии не было.
/// Пока так, ::1 на адаптер не ставится и восстановление IPv6 не трогает; сверка повторяет чтение и дополняет копию.
/// Копии прежних версий этого поля не имеют — для них IPv6-список известен.
/// </param>
/// <param name="FirstOriginal">
/// Самая первая копия адаптера (до того, как служба запомнила исходным DNS, сменённый извне); null — копию не переписывали.
/// Если DNS адаптера раз за разом переписывает другая программа (чужой VPN-клиент), исходным снова становится она.
/// Копии прежних версий этого поля не имеют.
/// </param>
public sealed record InterfaceDnsBackup(
    Guid InterfaceGuid,
    string NameServerV4,
    string NameServerV6,
    string ProfileNameServerV4,
    int DohServerPropertiesV4,
    DateTimeOffset SavedUtc,
    string SearchList = "", string? AppliedSearchList = null,
    bool Ipv6Unknown = false,
    InterfaceDnsBackup? FirstOriginal = null);

public sealed record InterfaceDnsState(string NameServer, string ProfileNameServer, int DohServerProperties, string SearchList = "");

public enum DnsRestoreOutcome
{
    Restored,
    ChangedByUser,
    NothingToRestore,

    /// <summary>IPv6-список не вернулся (на адаптере остался ::1): резервную копию удалять нельзя.</summary>
    Incomplete,
}

/// <summary>DNS-настройки интерфейсов через Get/SetInterfaceDnsSettings (Windows 10 2004+).</summary>
public static unsafe class InterfaceDnsOps
{
    public const string LoopbackV4 = "127.0.0.1";
    public const string LoopbackV6 = "::1";

    private const uint Version1 = 1;
    private const uint Version3 = 3;
    private const uint ErrorFileNotFound = 2;
    private const uint ErrorNotSupported = 50;
    private const uint ErrorNotFound = 1168;
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
            TraceSet(interfaceGuid, ipv6 ? "DNS IPv6" : "DNS IPv4", nameServers, (uint)code);
            NativeCallException.ThrowIfFailed((uint)code, "SetInterfaceDnsSettings");
        }
    }

    private static void TraceSet(Guid interfaceGuid, string what, string value, uint code)
    {
        if (Verbose.IsOn)
        {
            Verbose.Write("Dns.Interface", $"{interfaceGuid}: {what} := «{value}» — {(code == 0 ? "ok" : NativeCallException.Describe(code))}");
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
            TraceSet(interfaceGuid, "список поиска", searchList, (uint)code);
            NativeCallException.ThrowIfFailed((uint)code, "SetInterfaceDnsSettings");
        }
    }

    /// <summary>
    /// IPv6-настройки DNS или null, если их нет: у адаптера без IPv6 (PPP SSTP/L2TP без IPv6CP, отвязанный
    /// протокол, Loopback) чтение даёт ERROR_FILE_NOT_FOUND и другие ошибки. IPv6 для посредника необязателен,
    /// поэтому такой адаптер считается «IPv6 нет»; ошибки IPv4 по-прежнему бросаются вызывающему.
    /// <paramref name="warn"/> = false — без предупреждения в журнал: сбор диагностики читает все интерфейсы,
    /// и «нет IPv6» у Loopback там не событие.
    /// </summary>
    public static InterfaceDnsState? TryReadIpv6(Guid interfaceGuid, bool warn = true)
    {
        try
        {
            return Read(interfaceGuid, ipv6: true);
        }
        catch (NativeCallException ex)
        {
            if (warn)
            {
                WarnIpv6Once(interfaceGuid, ex);
            }

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
        if (s_ipv6Warned.Count >= 1024) { s_ipv6Warned.Clear(); }
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
    public static InterfaceDnsBackup Capture(Guid interfaceGuid, InterfaceDnsBackup? previous, DateTimeOffset now, bool ownsIpv6Loopback = false) =>
        Capture(interfaceGuid, previous, now, ownsIpv6Loopback, Read);

    /// <summary>
    /// Снимок с подменяемым чтением (для тестов). IPv6 читается устойчиво, как в <see cref="TryReadIpv6"/>, но без
    /// предупреждения в журнал: сверка снимает копию часто. Прежде здесь прощались лишь коды 2, 1168 и 50, и адаптер
    /// с отвязанным IPv6, отвечающий другим кодом (например, 87), ронял снимок: адаптер не переводился на посредник,
    /// а сверка каждый раз была «неполной». Не прочиталось — IPv6-часть берётся из прежней копии. Без прежней копии
    /// пустой она считается только при кодах «IPv6 нет» (<see cref="IsIpv6Absent"/>); иной сбой (87, RPC 1722,
    /// ERROR_NOT_READY) мог быть временным, и тогда IPv6-часть неизвестна (<see cref="InterfaceDnsBackup.Ipv6Unknown"/>):
    /// записать в копию пусто значило бы при восстановлении затереть статический IPv6 DNS пользователя.
    /// </summary>
    internal static InterfaceDnsBackup Capture(Guid interfaceGuid, InterfaceDnsBackup? previous, DateTimeOffset now, bool ownsIpv6Loopback, Func<Guid, bool, InterfaceDnsState> read)
    {
        ArgumentNullException.ThrowIfNull(read);
        var v4 = read(interfaceGuid, false);
        // Копия с неизвестной IPv6-частью прежнего IPv6-списка не знает: он читается так, будто копии нет.
        var previousV6 = previous is { Ipv6Unknown: false } ? previous.NameServerV6 : null;
        string v6;
        var unknown = false;
        try
        {
            v6 = OriginalV6(read(interfaceGuid, true).NameServer, previousV6, ownsIpv6Loopback);
        }
        catch (NativeCallException ex)
        {
            v6 = previousV6 ?? "";
            unknown = previousV6 is null && !IsIpv6Absent(ex.Code);
        }

        var originalSearchList = previous?.AppliedSearchList is { } applied && string.Equals(v4.SearchList, applied, StringComparison.OrdinalIgnoreCase)
            ? previous.SearchList : v4.SearchList;
        return new InterfaceDnsBackup(interfaceGuid, Original(v4.NameServer, previous?.NameServerV4), v6,
            v4.ProfileNameServer, v4.DohServerProperties, now, originalSearchList, v4.SearchList, unknown);
    }

    /// <summary>Код чтения IPv6-настроек означает «у адаптера IPv6 нет»: ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED.</summary>
    internal static bool IsIpv6Absent(uint code) => code is ErrorFileNotFound or ErrorNotFound or ErrorNotSupported;

    /// <summary>Исходный IPv6-список из копии; null — неизвестен (см. <see cref="InterfaceDnsBackup.Ipv6Unknown"/>).</summary>
    public static string? KnownOriginalV6(InterfaceDnsBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        return backup.Ipv6Unknown ? null : backup.NameServerV6;
    }

    internal static string Original(string current, string? previous) =>
        IsProxySet(current) && previous is not null ? previous : current;

    internal static string OriginalV6(string current, string? previous, bool ownsIpv6Loopback) =>
        previous is null && ownsIpv6Loopback && IsLoopback(current) ? "" : Original(current, previous);

    /// <summary>
    /// Ставит адаптеру DNS-посредник. ::1 — только если посредник занял и этот адрес: иначе там может
    /// отвечать чужой процесс. Без ::1 IPv6-список трогается, только если на нём наш ::1 от прежнего запуска
    /// (<see cref="IsStaleIpv6Loopback"/>): он возвращается к исходному <paramref name="originalV6"/>.
    /// Исходный неизвестен (null) — список не трогается: там может стоять собственный ::1 пользователя.
    /// Адаптер без IPv6 пропускается. <paramref name="ipv6Known"/> = false — исходный IPv6-список в копии неизвестен
    /// (<see cref="InterfaceDnsBackup.Ipv6Unknown"/>): IPv6 не трогается вовсе, ::1 тоже не ставится — вернуть
    /// исходный список потом было бы нечем.
    /// </summary>
    public static void ApplyLoopback(Guid interfaceGuid, bool ipv6Loopback = true, string? originalV6 = null, string? nameServerV4 = null, bool ipv6Known = true)
    {
        SetNameServer(interfaceGuid, nameServerV4 ?? LoopbackV4, ipv6: false);
        if (!ipv6Known)
        {
            return;
        }

        if (ipv6Loopback)
        {
            TrySetIpv6NameServer(interfaceGuid, LoopbackV6);
        }
        else if (originalV6 is not null && TryReadIpv6(interfaceGuid) is { } v6 && IsStaleIpv6Loopback(v6.NameServer, originalV6))
        {
            TrySetIpv6NameServer(interfaceGuid, originalV6);
        }
    }

    /// <summary>
    /// ::1 на адаптере поставлен посредником прежнего запуска, а не пользователем: исходный IPv6-список известен
    /// (копия DNS адаптера; у туннеля DNS целиком наш — исходный пуст) и сам не loopback. Собственный ::1
    /// пользователя копия хранит как исходный, и тогда он не считается устаревшим.
    /// </summary>
    internal static bool IsStaleIpv6Loopback(string currentV6, string? originalV6) =>
        originalV6 is not null && IsLoopback(currentV6) && !IsLoopback(originalV6);

    /// <summary>
    /// Возвращает исходные серверы, только если на интерфейсе всё ещё наш loopback. IPv6 из копии
    /// возвращается и тогда, когда там сейчас пусто, а IPv4 — наш loopback: посредник без [::1]:53 IPv6 не
    /// ставил, но прежний запуск мог снять ::1 пользователя. Исходный IPv6-список в копии неизвестен
    /// (<see cref="InterfaceDnsBackup.Ipv6Unknown"/>) — IPv6 не трогается: ::1 посредник тогда не ставил.
    /// </summary>
    public static DnsRestoreOutcome Restore(Guid interfaceGuid, InterfaceDnsBackup? backup) =>
        Restore(interfaceGuid, backup, Read, SetNameServer, SetSearchList, ReadStoredIpv6NameServer);

    private const string Ipv6InterfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\";

    /// <summary>
    /// IPv6-список DNS, сохранённый в настройках адаптера (Tcpip6\Parameters\Interfaces\{guid}\NameServer, туда его
    /// пишет SetInterfaceDnsSettings), — только чтение. null — раздела нет: IPv6-настроек у адаптера не хранится вовсе.
    /// Раздел есть, значения нет — пусто. Ошибка доступа бросается: список неизвестен.
    /// </summary>
    internal static string? ReadStoredIpv6NameServer(Guid interfaceGuid)
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(Ipv6InterfacesKey + interfaceGuid.ToString("B"));
        return key is null ? null : key.GetValue("NameServer") as string ?? "";
    }

    /// <summary>
    /// Восстановление с подменяемыми чтением и записью (для тестов); см. <see cref="Restore(Guid, InterfaceDnsBackup?)"/>.
    /// <paramref name="readStoredV6"/> — сохранённый IPv6-список (<see cref="ReadStoredIpv6NameServer"/>); null — не
    /// читать, раздел считается отсутствующим.
    /// </summary>
    internal static DnsRestoreOutcome Restore(Guid interfaceGuid, InterfaceDnsBackup? backup, Func<Guid, bool, InterfaceDnsState> read,
        Action<Guid, string, bool> setNameServer, Action<Guid, string> setSearchList, Func<Guid, string?>? readStoredV6 = null)
    {
        ArgumentNullException.ThrowIfNull(read);
        ArgumentNullException.ThrowIfNull(setNameServer);
        ArgumentNullException.ThrowIfNull(setSearchList);
        var v4 = read(interfaceGuid, false);
        if (backup is not null && ShouldRestoreSearchList(v4, backup))
        {
            setSearchList(interfaceGuid, backup.SearchList);
        }

        var v4Ours = IsProxySet(v4.NameServer);
        if (backup is { Ipv6Unknown: true })
        {
            if (!v4Ours)
            {
                return string.IsNullOrEmpty(v4.NameServer) ? DnsRestoreOutcome.NothingToRestore : DnsRestoreOutcome.ChangedByUser;
            }

            setNameServer(interfaceGuid, backup.NameServerV4, false);
            return DnsRestoreOutcome.Restored;
        }

        InterfaceDnsState? v6;
        // Чтение с кодом «IPv6 нет» (протокол отвязан или интерфейс временно вне стека — по коду не различить) ещё не
        // значит, что возвращать нечего: в настройках адаптера может храниться наш ::1, и он оживёт вместе с IPv6, а
        // исходные серверы есть только в копии. Поэтому тогда сверяется сохранённый список: он и считается текущим, и
        // наш ::1 в нём даёт попытку записи, а при неудаче — Incomplete с сохранением копии. Раздела IPv6-настроек
        // нет вовсе — ::1 нигде не хранится и вернуться не может: IPv6-часть восстановлена (иначе адаптер с отвязанным
        // насовсем IPv6 вечно числился бы невосстановленным). Иной сбой чтения мог быть временным и успехом не считается.
        var v6Absent = false;
        try
        {
            v6 = read(interfaceGuid, true);
        }
        catch (NativeCallException ex)
        {
            WarnIpv6Once(interfaceGuid, ex);
            v6 = null;
            v6Absent = IsIpv6Absent(ex.Code);
        }

        if (v6Absent && readStoredV6 is not null)
        {
            try
            {
                if (readStoredV6(interfaceGuid) is { } stored)
                {
                    v6 = new InterfaceDnsState(stored, "", 0);
                    v6Absent = false;
                }
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
            {
                // Сохранённый список не прочитан — он неизвестен, как при временном сбое.
                v6Absent = false;
            }
        }

        bool TrySetIpv6(string nameServers)
        {
            try
            {
                setNameServer(interfaceGuid, nameServers, true);
                return true;
            }
            catch (NativeCallException ex)
            {
                WarnIpv6Once(interfaceGuid, ex);
                return false;
            }
        }

        var v6Current = v6?.NameServer ?? "";
        if (!v4Ours && v6 is null && !v6Absent && !string.IsNullOrEmpty(backup?.NameServerV6))
        {
            return DnsRestoreOutcome.Incomplete;
        }
        if (!v4Ours && !IsLoopback(v6Current))
        {
            return string.IsNullOrEmpty(v4.NameServer) && string.IsNullOrEmpty(v6Current)
                ? DnsRestoreOutcome.NothingToRestore
                : DnsRestoreOutcome.ChangedByUser;
        }

        if (v4Ours)
        {
            setNameServer(interfaceGuid, backup?.NameServerV4 ?? "", false);
        }

        var v6Original = backup?.NameServerV6 ?? "";
        if (v6 is null && !v6Absent && v6Original.Length > 0)
        {
            // IPv6-список при снимке прочитался и в нём были свои серверы, а сейчас чтение не удалось (временный
            // сбой): вернуть их нельзя, но и копию удалять нельзя - в ней единственная запись исходных серверов.
            return DnsRestoreOutcome.Incomplete;
        }

        if (v6 is not null && (IsLoopback(v6Current) || (v4Ours && v6Current.Length == 0))
            && !string.Equals(v6Current, v6Original, StringComparison.OrdinalIgnoreCase)
            && !TrySetIpv6(v6Original))
        {
            // IPv6 у адаптера есть (прочитался), а запись не прошла: ::1 остался без посредника, и копия
            // с исходными серверами ещё нужна для повторной попытки.
            return DnsRestoreOutcome.Incomplete;
        }

        return DnsRestoreOutcome.Restored;
    }

    internal static bool ShouldRestoreSearchList(InterfaceDnsState current, InterfaceDnsBackup backup)
    {
        static string[] Suffixes(string list) => list.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries);

        var actual = Suffixes(current.SearchList);
        var original = Suffixes(backup.SearchList);
        var comparer = StringComparer.OrdinalIgnoreCase;
        if (actual.SequenceEqual(original, comparer)) return false;
        if (backup.AppliedSearchList is { } applied) return actual.SequenceEqual(Suffixes(applied), comparer);

        // До 0.17.2 копия содержала лишь исходный список. Шлюз дописывал свои суффиксы в конец
        // после установки IPv4-loopback. Замена или перестановка исходных суффиксов сделана извне.
        var prefix = original.Distinct(comparer).ToArray();
        return IsProxySet(current.NameServer) && actual.Length > prefix.Length
            && actual.Take(prefix.Length).SequenceEqual(prefix, comparer)
            && actual.Skip(prefix.Length).All(Core.Dns.PublicSuffixes.IsSearchListSuffix);
    }

    /// <summary>
    /// На адаптере ровно набор посредника: IPv4 — только 127.0.0.1 либо «адрес самого адаптера, 127.0.0.1»
    /// (<see cref="ProxyNameServers"/>; адреса адаптера — <paramref name="ownAddresses"/>), IPv6 — пусто или только ::1.
    /// </summary>
    public static bool IsOnlyProxyLoopback(string nameServerV4, string nameServerV6, IReadOnlyCollection<string>? ownAddresses = null)
    {
        var v4 = nameServerV4.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        var v6 = nameServerV6.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        return v4.Contains(LoopbackV4) && v4.All(p => p == LoopbackV4 || ownAddresses?.Contains(p) == true) && v6.All(p => p == LoopbackV6);
    }

    /// <summary>
    /// IPv4-список DNS, который посредник ставит адаптеру. Без своего адреса — только 127.0.0.1. Со своим —
    /// «адрес адаптера, 127.0.0.1»: запрос, привязанный к адаптеру (так Windows проверяет интернет на каждом
    /// интерфейсе), до 127.0.0.1 не доходит — стек отвечает ошибкой 10049, — а до адреса самого адаптера
    /// доходит. Без этого прямая проверка интернета Windows на основном адаптере не проходила никогда
    /// (разбор сброса Wi-Fi после загрузки, 20.11.2026). 127.0.0.1 остаётся вторым: он работает, когда адрес
    /// адаптера сменился, а список ещё не обновлён.
    /// </summary>
    public static string ProxyNameServers(string? ownAddress) =>
        string.IsNullOrEmpty(ownAddress) ? LoopbackV4 : ownAddress + "," + LoopbackV4;

    /// <summary>
    /// Список DNS поставлен посредником: только loopback либо ровно «адрес IPv4, 127.0.0.1»
    /// (<see cref="ProxyNameServers"/>). Адрес не сверяется с текущим адресом адаптера: после смены адреса
    /// на адаптере остаётся прежний, и список всё равно наш. Своим он считается только вместе с копией DNS
    /// адаптера — как и одиночный loopback.
    /// </summary>
    public static bool IsProxySet(string nameServers)
    {
        if (IsLoopback(nameServers))
        {
            return true;
        }

        var parts = nameServers.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 2 && parts[1] == LoopbackV4
            && System.Net.IPAddress.TryParse(parts[0], out var own) && own.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
    }

    /// <summary>Один и тот же список серверов: разделители (пробел, запятая) не важны.</summary>
    public static bool SameServers(string left, string right) =>
        left.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)
            .SequenceEqual(right.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);

    public static bool IsLoopback(string nameServers)
    {
        var parts = nameServers.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length > 0 && parts.All(p => p is LoopbackV4 or LoopbackV6);
    }

    /// <summary>
    /// Сбрасывает системный кеш DNS. false — сброс не подтверждён: ipconfig не запустился или не завершился
    /// за 10 секунд. Зависший процесс завершается, иначе повторные сбросы копили бы процессы.
    /// ipconfig запускается полным путём из System32 (служба не ищет программы по PATH и в текущем каталоге) и
    /// под общей очередью запусков дочерних процессов: иначе он мог унаследовать наследуемые концы труб
    /// помощника AnyConnect, запускаемого в то же мгновение, и смерть помощника замечалась бы с задержкой.
    /// Очередь держится только на время запуска, не на ожидание завершения.
    /// </summary>
    public static bool FlushResolverCache()
    {
        var system = Environment.SystemDirectory;
        var start = new ProcessStartInfo(Path.Combine(system, "ipconfig.exe"), "/flushdns")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            WorkingDirectory = system,
        };
        Process? started;
        lock (Operations.ChildProcessJob.StartGate)
        {
            started = Process.Start(start);
        }

        using var process = started;
        if (process is null)
        {
            return false;
        }

        if (process.WaitForExit(10_000))
        {
            return process.ExitCode == 0;
        }

        Trace.TraceWarning("ipconfig /flushdns не завершился за 10 с и будет остановлен");
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Процесс уже завершился сам.
        }

        return false;
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
    public IReadOnlyDictionary<Guid, InterfaceDnsBackup> Load()
    {
        // Служба спрашивает копии много раз за одну сверку (DNS службы для фильтров, маршрутов и прокси):
        // файл перечитывается, только когда изменились его время записи или размер. Отметка снимается до
        // чтения: запись, случившаяся во время чтения, сменит отметку, и следующий вызов перечитает файл.
        var stamp = Stamp();
        lock (_cacheLock)
        {
            if (_cached is not null && stamp is not null && stamp == _cachedStamp)
            {
                return _cached;
            }
        }

        var loaded = SafeFile.Load(
            path,
            Parse,
            () => new Dictionary<Guid, InterfaceDnsBackup>(),
            "Резервная копия DNS-настроек была повреждена и заменена пустой",
            OnCorrupt);
        lock (_cacheLock)
        {
            _cached = loaded;
            _cachedStamp = stamp;
        }

        return loaded;
    }

    private readonly Lock _cacheLock = new();
    private IReadOnlyDictionary<Guid, InterfaceDnsBackup>? _cached;
    private (DateTime WriteTime, long Length)? _cachedStamp;

    private (DateTime WriteTime, long Length)? Stamp()
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists ? (info.LastWriteTimeUtc, info.Length) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void Invalidate()
    {
        lock (_cacheLock)
        {
            _cached = null;
            _cachedStamp = null;
        }
    }

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
        try
        {
            AtomicFile.WriteAllText(path, JsonSerializer.Serialize(backups.ToList(), JsonDefaults.Options));
        }
        finally
        {
            Invalidate();
        }
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
