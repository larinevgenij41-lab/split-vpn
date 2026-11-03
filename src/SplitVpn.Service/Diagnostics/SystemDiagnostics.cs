using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Service.Diagnostics;

/// <summary>
/// Снимки системы для архива разбора: Windows и сеансы, сеть, WFP, журналы событий. Текстом с
/// адресами в обычной записи — архив читают глазами и разбирают, а не загружают обратно.
/// </summary>
public static class SystemDiagnostics
{
    /// <summary>За сколько последних суток берутся журналы событий Windows.</summary>
    public static readonly TimeSpan EventLogAge = TimeSpan.FromDays(3);

    private const int MaxEvents = 2000;

    /// <summary>Вход (21, 22), выход (23), отключение и подключение (24, 25, 39, 40), блокировка и разблокировка (41, 42) — без служебного шума.</summary>
    private const string SessionEvents = "(EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25 or EventID=39 or EventID=40 or EventID=41 or EventID=42)";

    public static IEnumerable<DiagnosticsPart> Parts(Func<DateTimeOffset?> verboseUntil)
    {
        yield return new("system/info.txt", () => SystemInfo(verboseUntil()));
        yield return new("system/sessions.txt", Sessions);
        yield return new("net/inventory.txt", Inventory);
        yield return new("net/wfp.json", () => JsonSerializer.Serialize(WfpInspector.Capture(), JsonDefaults.Options));
        yield return new("eventlog/rasclient.txt", () => Export("Application", "Provider[@Name='RasClient']", null));
        yield return new("eventlog/sessions.txt", () => Export("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", SessionEvents, null));
        yield return new("eventlog/services.txt", () => Export("System", "Provider[@Name='Service Control Manager']", ["SplitVpn", "Раздельный", "BFE", "Base Filtering", "Базовый модуль фильтрации", "RasMan", "SstpSvc"]));
        yield return new("eventlog/crashes.txt", () => Export("Application", "Provider[@Name='Application Error' or @Name='.NET Runtime' or @Name='Windows Error Reporting']", ["SplitVpn"]));
    }

    /// <summary>Профили пользователей Windows из реестра: имя каталога профиля и путь.</summary>
    public static IReadOnlyList<UserProfileFolder> UserProfiles()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var list = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
        var result = new List<UserProfileFolder>();
        foreach (var sid in list?.GetSubKeyNames() ?? [])
        {
            // Обычные учётные записи (локальные и доменные); служебные профили SYSTEM и сетевых служб не нужны.
            if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal))
            {
                continue;
            }

            using var profile = list!.OpenSubKey(sid);
            if (profile?.GetValue("ProfileImagePath") is string path && path.Length > 0)
            {
                var expanded = Environment.ExpandEnvironmentVariables(path);
                result.Add(new UserProfileFolder(Path.GetFileName(expanded.TrimEnd('\\')), expanded));
            }
        }

        return result;
    }

    private static string SystemInfo(DateTimeOffset? verboseUntil)
    {
        var text = new StringBuilder();
        using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var version = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"Windows: {version?.GetValue("ProductName")} {version?.GetValue("DisplayVersion")} сборка {version?.GetValue("CurrentBuild")}.{version?.GetValue("UBR")} ({Environment.OSVersion.VersionString})");
        }

        var (bfePid, bfeState) = SystemMetrics.ServiceStatus("BFE");
        var (servicePid, serviceState) = SystemMetrics.ServiceStatus(ServicePaths.ServiceName);
        text.AppendLine(CultureInfo.InvariantCulture, $"Компьютер: {Environment.MachineName}");
        text.AppendLine(CultureInfo.InvariantCulture, $"Часовой пояс: {TimeZoneInfo.Local.Id} ({TimeZoneInfo.Local.BaseUtcOffset}); сейчас {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        text.AppendLine(CultureInfo.InvariantCulture, $"Время работы Windows: {TimeSpan.FromMilliseconds(Environment.TickCount64):d\\.hh\\:mm\\:ss}");
        text.AppendLine(CultureInfo.InvariantCulture, $"Программа: {UpdateVersion.Text(UpdateVersion.Current)}; .NET {Environment.Version}; служба {Environment.ProcessPath}");
        text.AppendLine(CultureInfo.InvariantCulture, $"Служба SplitVpn: {serviceState}, PID {servicePid}, память {SystemMetrics.ServicePrivateBytes(ServicePaths.ServiceName) / 1_048_576} МБ");
        text.AppendLine(CultureInfo.InvariantCulture, $"BFE: {bfeState}, PID {bfePid}; невыгружаемый пул ядра {SystemMetrics.KernelNonpagedBytes() / 1_048_576} МБ");
        text.AppendLine(CultureInfo.InvariantCulture, $"Лимитная сеть: {(SystemSignals.IsMeteredNetwork() ? "да" : "нет")}");
        text.AppendLine(CultureInfo.InvariantCulture, $"Подробный журнал: {(verboseUntil is { } until ? "до " + until.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture) : "выключен")}");
        return text.ToString();
    }

    private static string Sessions()
    {
        var text = new StringBuilder("Сеанс\tСостояние\tПользователь\tСтанция\tКлиент").AppendLine();
        foreach (var session in WtsSessions.Enumerate())
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"{session.Id}\t{session.State}\t{session.User}\t{session.WinStation}\t{session.ClientName}");
        }

        return text.ToString();
    }

    private static string Inventory()
    {
        var snapshot = NetInventory.Capture();
        var text = new StringBuilder("Адаптеры:").AppendLine();
        foreach (var a in snapshot.Adapters.OrderBy(a => a.InterfaceIndex))
        {
            text.AppendLine(CultureInfo.InvariantCulture,
                $"  [{a.InterfaceIndex}] {a.Name} — {a.Description}; {a.TypeName}{(a.IsHardware ? ", физический" : "")}{(a.IsUp ? ", включён" : ", выключен")}; GUID {a.InterfaceGuid}; LUID {a.Luid}");
            text.AppendLine(CultureInfo.InvariantCulture,
                $"      адреса {Join(a.Addresses)}; шлюз {(a.DefaultGateway is { } g ? Ipv4.Format(g) : "—")} метрика {a.DefaultRouteMetric?.ToString(CultureInfo.InvariantCulture) ?? "—"}; DNS {Join(a.DnsServers)}; сети {string.Join(",", a.OnLinkPrefixes)}");
            text.AppendLine("      " + InterfaceDns(a.InterfaceGuid));
        }

        text.AppendLine().AppendLine("Маршруты IPv4 (назначение, шлюз, интерфейс, метрика, протокол; метрика 3917 — маршруты программы):");
        foreach (var route in snapshot.RoutesV4.OrderBy(r => r.Destination.Network).ThenBy(r => r.Destination.PrefixLength))
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"  {route.Destination}\t{Ipv4.Format(route.NextHop)}\tif{route.InterfaceIndex}\t{route.RouteMetric}\t{route.Protocol}");
        }

        return text.ToString();
    }

    private static string InterfaceDns(Guid interfaceGuid)
    {
        try
        {
            var v4 = InterfaceDnsOps.Read(interfaceGuid, ipv6: false);
            var v6 = InterfaceDnsOps.TryReadIpv6(interfaceGuid);
            return $"настройки DNS: IPv4 «{v4.NameServer}» (профиль «{v4.ProfileNameServer}»), IPv6 «{v6?.NameServer ?? "нет"}», поиск «{v4.SearchList}», DoH {v4.DohServerProperties}";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return "настройки DNS не прочитаны: " + ex.Message;
        }
    }

    private static string Join(IEnumerable<uint> addresses) => string.Join(",", addresses.Select(Ipv4.Format));

    /// <summary>Свежие события за трое суток: время, уровень, источник, код и текст; фильтр — по словам в тексте.</summary>
    private static string Export(string log, string? condition, string[]? mustContain)
    {
        var age = $"TimeCreated[timediff(@SystemTime) <= {(long)EventLogAge.TotalMilliseconds}]";
        var query = new EventLogQuery(log, PathType.LogName, $"*[System[{(condition is null ? "" : condition + " and ")}{age}]]") { ReverseDirection = true };
        using var reader = new EventLogReader(query);
        return ExportRecords(reader.ReadEvent, Describe,
            (record, message) => string.Create(CultureInfo.InvariantCulture,
                $"{record.TimeCreated:yyyy-MM-dd HH:mm:ss.fff} [{record.LevelDisplayNameOrNumber()}] {record.ProviderName} {record.Id}: {message.ReplaceLineEndings(" ")}"), mustContain);
    }

    /// <summary>Источник выдаёт новые события первыми; каждая полученная запись освобождается, включая лишнюю.</summary>
    internal static string ExportRecords<T>(Func<T?> next, Func<T, string> describe, Func<T, string, string> format, string[]? mustContain)
        where T : class, IDisposable
    {
        var text = new StringBuilder();
        var count = 0;
        while (true)
        {
            using var record = next();
            if (record is null) break;
            var message = describe(record);
            if (mustContain is not null && !mustContain.Any(word => message.Contains(word, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (count == MaxEvents)
            {
                text.AppendLine("Журнал усечён: включены последние 2000 подходящих событий, новые первыми.");
                break;
            }

            count++;
            text.AppendLine(format(record, message));
        }

        return text.Length == 0 ? "Событий нет." + Environment.NewLine : text.ToString();
    }

    /// <summary>Текст события; если описания нет (не установлен ресурс), — значения его свойств.</summary>
    private static string Describe(EventRecord record)
    {
        try
        {
            if (record.FormatDescription() is { Length: > 0 } description)
            {
                return description;
            }
        }
        catch (EventLogException)
        {
            // Нет ресурса сообщений: ниже — сырые значения.
        }

        return string.Join(" | ", record.Properties.Select(p => Convert.ToString(p.Value, CultureInfo.InvariantCulture)));
    }

    private static string LevelDisplayNameOrNumber(this EventRecord record)
    {
        try
        {
            return record.LevelDisplayName ?? record.Level?.ToString(CultureInfo.InvariantCulture) ?? "";
        }
        catch (EventLogException)
        {
            return record.Level?.ToString(CultureInfo.InvariantCulture) ?? "";
        }
    }
}
