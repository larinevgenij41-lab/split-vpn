using System.Globalization;
using System.Text;
using Microsoft.Win32;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Windows.Diagnostics;

/// <summary>Туннель службы для детектора: по LUID ищутся чужие маршруты, имя попадает в предупреждение.</summary>
public sealed record ConflictTunnel(ulong Luid, string Name);

/// <summary>
/// Конфликты с другими программами, которые могут нарушить разделение или защиту:
/// чужие активные VPN-соединения, чужие маршруты на нашем туннеле (постоянные маршруты PPP-интерфейсов),
/// жёсткие разрешения WFP в sublayer с весом не ниже нашего.
/// </summary>
public static class ConflictDetector
{
    /// <summary>Сколько чужих маршрутов одного туннеля называть: остальные — той же природы.</summary>
    private const int MaxRoutesPerTunnel = 3;

    public static IReadOnlyList<StatusWarning> Detect(string ownPhonebook, IReadOnlyList<ConflictTunnel> tunnels)
    {
        ArgumentNullException.ThrowIfNull(tunnels);
        var warnings = new List<StatusWarning>();
        AddForeignConnections(warnings, ownPhonebook);
        if (tunnels.Count > 0)
        {
            AddForeignTunnelRoutes(warnings, tunnels);
        }

        AddHardPermits(warnings);
        return warnings;
    }

    private static void AddForeignConnections(List<StatusWarning> warnings, string ownPhonebook)
    {
        var own = FullPathOrSelf(ownPhonebook);
        foreach (var connection in RasClient.EnumerateConnections().Where(c => !IsOwn(c.Phonebook, own)))
        {
            warnings.Add(new StatusWarning("foreign-vpn",
                $"Активно другое VPN-подключение «{connection.EntryName}»: его маршруты и DNS могут перехватывать трафик.", null)
            {
                Subject = connection.EntryName,
            });
        }
    }

    /// <summary>
    /// Соединение своей телефонной книги. У соединения без записи (RAS вернул пустой путь) полного пути нет:
    /// Path.GetFullPath бросил бы ArgumentException, а само соединение — заведомо чужое.
    /// </summary>
    private static bool IsOwn(string? phonebook, string own) =>
        own.Length > 0 && !string.IsNullOrWhiteSpace(phonebook)
        && string.Equals(FullPathOrSelf(phonebook), own, StringComparison.OrdinalIgnoreCase);

    private static string FullPathOrSelf(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "";
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or IOException or System.Security.SecurityException)
        {
            return path;
        }
    }

    private static void AddForeignTunnelRoutes(List<StatusWarning> warnings, IReadOnlyList<ConflictTunnel> tunnels)
    {
        // Windows сам ставит на каждый интерфейс 224.0.0.0/4, 255.255.255.255/32 и маршруты link-local — это не конфликт.
        var foreign = NetInventory.ReadRoutesV4()
            .Where(r => r.RouteMetric != RouteOps.MarkerMetric && r.Destination.PrefixLength is > 1 and < 32)
            .Where(r => !IsLinkLocalOrMulticast(r.Destination))
            .ToList();
        if (foreign.Count == 0)
        {
            return;
        }

        // Телефонные книги Windows читаются только когда чужой маршрут уже найден.
        var profiles = new Lazy<List<WindowsVpnEntry>>(ReadWindowsVpnEntries);
        foreach (var tunnel in tunnels)
        {
            var destinations = foreign.Where(r => r.InterfaceLuid == tunnel.Luid)
                .Select(r => r.Destination)
                .Distinct()
                .Take(MaxRoutesPerTunnel);
            foreach (var destination in destinations)
            {
                var source = SourceProfile(profiles.Value, destination);
                warnings.Add(new StatusWarning("foreign-routes",
                    $"На туннеле «{tunnel.Name}» чужой маршрут {destination}"
                    + (source is null ? "." : $" — вероятно, постоянный маршрут VPN-профиля Windows «{source}»."), null)
                {
                    Subject = tunnel.Name,
                });
            }
        }
    }

    private static bool IsLinkLocalOrMulticast(Ipv4Cidr cidr) =>
        Ipv4Cidr.Parse("169.254.0.0/16").Contains(cidr.Network) || Ipv4Cidr.Parse("224.0.0.0/4").Contains(cidr.Network);

    private static void AddHardPermits(List<StatusWarning> warnings)
    {
        var inventory = WfpInspector.Capture();
        var ownKey = WfpIdentity.Product.SubLayerKey;
        var ownWeight = inventory.SubLayers.FirstOrDefault(s => s.Key == ownKey)?.Weight ?? ushort.MaxValue;
        var risky = inventory.SubLayers.Where(s => s.Key != ownKey && s.Weight >= ownWeight && s.HardPermitCount > 0).ToList();
        if (risky.Count > 0)
        {
            warnings.Add(new StatusWarning("wfp-hard-permit",
                $"Защита не гарантирована: другая программа разрешает трафик жёсткими правилами WFP ({string.Join(", ", risky.Select(s => s.Name))}).", null));
        }
    }

    /// <summary>Запись телефонной книги Windows: имя и шестнадцатеричный список её маршрутов.</summary>
    private sealed record WindowsVpnEntry(string Name, string Routes);

    /// <summary>
    /// Профиль Windows, которому прописан такой же маршрут. Маршруты профиля лежат в записи телефонной книги
    /// («Routes=…») как шестнадцатеричный список: у каждого маршрута идут подряд семейство адресов (2 — IPv4),
    /// длина префикса и сам адрес. По этой тройке и опознаётся источник.
    /// </summary>
    private static string? SourceProfile(IReadOnlyList<WindowsVpnEntry> entries, Ipv4Cidr destination)
    {
        var pattern = LittleEndian(2) + LittleEndian((uint)destination.PrefixLength) + BigEndian(destination.Network);
        var found = entries.FirstOrDefault(e => e.Routes.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        // Имя записи могло не прочитаться (телефонная книга в однобайтовой кодировке): тогда источник не называем.
        return found is null || found.Name.Contains('�', StringComparison.Ordinal) ? null : found.Name;
    }

    private static string LittleEndian(uint value) =>
        string.Create(CultureInfo.InvariantCulture, $"{(byte)value:X2}{(byte)(value >> 8):X2}{(byte)(value >> 16):X2}{(byte)(value >> 24):X2}");

    private static string BigEndian(uint value) =>
        string.Create(CultureInfo.InvariantCulture, $"{(byte)(value >> 24):X2}{(byte)(value >> 16):X2}{(byte)(value >> 8):X2}{(byte)value:X2}");

    /// <summary>Телефонные книги VPN-профилей Windows: общая и по одной у каждого пользователя.</summary>
    private static List<WindowsVpnEntry> ReadWindowsVpnEntries()
    {
        var entries = new List<WindowsVpnEntry>();
        foreach (var path in WindowsPhonebooks())
        {
            try
            {
                ReadPhonebook(path, entries);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException or NotSupportedException)
            {
                // Телефонная книга недоступна: источник чужого маршрута просто не будет назван.
            }
        }

        return entries;
    }

    private const string PhonebookSuffix = @"Microsoft\Network\Connections\Pbk\rasphone.pbk";

    private static IEnumerable<string> WindowsPhonebooks()
    {
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), PhonebookSuffix);
        string[] users;
        try
        {
            var configured = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", "ProfilesDirectory", null) as string;
            var root = Environment.ExpandEnvironmentVariables(string.IsNullOrWhiteSpace(configured) ? @"%SystemDrive%\Users" : configured);
            users = Directory.Exists(root) ? Directory.GetDirectories(root) : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException)
        {
            users = [];
        }

        foreach (var user in users)
        {
            yield return Path.Combine(user, "AppData", "Roaming", PhonebookSuffix);
        }
    }

    /// <summary>Разбор телефонной книги: имена записей и их маршруты. Файл текстовый, строки «ключ=значение».</summary>
    private static void ReadPhonebook(string path, List<WindowsVpnEntry> entries)
    {
        if (!File.Exists(path) || new FileInfo(path).Length > 4 * 1024 * 1024)
        {
            return;
        }

        var name = "";
        var routes = new StringBuilder();
        // Кодировка книги зависит от системы: нечитаемые символы заменяются, такие имена в текст не попадут.
        foreach (var line in File.ReadLines(path, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
        {
            var text = line.Trim();
            if (text.StartsWith('[') && text.EndsWith(']'))
            {
                Flush(entries, name, routes);
                name = text[1..^1];
                routes.Clear();
            }
            else if (text.StartsWith("Routes=", StringComparison.OrdinalIgnoreCase))
            {
                routes.Append(text["Routes=".Length..]);
            }
        }

        Flush(entries, name, routes);
    }

    private static void Flush(List<WindowsVpnEntry> entries, string name, StringBuilder routes)
    {
        if (name.Length > 0 && routes.Length > 0)
        {
            entries.Add(new WindowsVpnEntry(name, routes.ToString()));
        }
    }
}
