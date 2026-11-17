using System.Globalization;
using System.Text;
using Microsoft.Win32;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Windows.Diagnostics;

/// <summary>Туннель службы для детектора: по LUID ищутся чужие маршруты, имя попадает в предупреждение.</summary>
public sealed record ConflictTunnel(ulong Luid, string Name);

/// <summary>
/// Сервер подключения службы: чужое подключение Windows к нему же - отдельный, худший конфликт.
/// <paramref name="Addresses"/> - адреса, в которые служба уже разрешила имя; пусто - туннеля ещё не было.
/// <paramref name="HangUpForeign"/> - служба сейчас держит это подключение поднятым или поднимает его сама (намерение
/// «Подключено», подключение не положено пользователем и не остановлено ошибкой, паролем или входом): чужое
/// подключение Windows к тому же серверу разрывается.
/// </summary>
public sealed record ConflictServer(string ProfileName, string Host, IReadOnlyList<uint> Addresses, Guid ProfileId = default,
    bool HangUpForeign = false);

/// <summary>
/// Что детектор знает о службе: поднятые туннели и серверы всех её подключений. <paramref name="Resolve"/>
/// разрешает имя узла в IPv4-адреса (пусто - не разрешилось); null - имена не разрешаются, серверы
/// сравниваются только по имени и известным адресам. <paramref name="StillCurrent"/> проверяется перед каждым разрывом
/// чужого подключения: false - проверка брошена координатором или устарела (например, VPN уже отключён), и её снимок
/// служб не даёт права ничего разрывать; null - проверка всегда актуальна.
/// </summary>
public sealed record ConflictInputs(IReadOnlyList<ConflictTunnel> Tunnels, IReadOnlyList<ConflictServer> Servers,
    Func<string, IReadOnlyList<uint>>? Resolve = null, Func<bool>? StillCurrent = null);

/// <summary>
/// Конфликты с другими программами, которые могут нарушить разделение или защиту:
/// чужие активные VPN-соединения, чужие маршруты на нашем туннеле (постоянные маршруты PPP-интерфейсов),
/// жёсткие разрешения WFP в sublayer с весом не ниже нашего.
/// </summary>
public static class ConflictDetector
{
    /// <summary>Сколько чужих маршрутов одного туннеля называть: остальные — той же природы.</summary>
    private const int MaxRoutesPerTunnel = 3;

    public static IReadOnlyList<StatusWarning> Detect(string ownPhonebook, IReadOnlyList<ConflictTunnel> tunnels,
        IReadOnlyList<ConflictServer>? servers = null, Func<string, IReadOnlyList<uint>>? resolve = null, Func<bool>? stillCurrent = null)
    {
        ArgumentNullException.ThrowIfNull(tunnels);
        var warnings = new List<StatusWarning>();
        AddForeignConnections(warnings, ownPhonebook, servers ?? [], resolve, stillCurrent);
        if (tunnels.Count > 0)
        {
            AddForeignTunnelRoutes(warnings, tunnels);
        }

        AddHardPermits(warnings);
        return warnings;
    }

    private static void AddForeignConnections(List<StatusWarning> warnings, string ownPhonebook, IReadOnlyList<ConflictServer> servers,
        Func<string, IReadOnlyList<uint>>? resolve, Func<bool>? stillCurrent)
    {
        var own = FullPathOrSelf(ownPhonebook);
        var cached = resolve is null ? null : CachedResolver(resolve);
        // PPPoE-подключение к провайдеру - не VPN: через него идёт сам интернет, конфликта нет.
        foreach (var connection in RasClient.EnumerateConnections().Where(c => !c.IsPppoe && !IsOwn(c.Phonebook, own)))
        {
            var server = servers.Count == 0 ? null : RasPhonebook.TryReadServer(connection.Phonebook, connection.EntryName);
            warnings.Add(ForeignConnectionWarning(connection.EntryName, server, servers, cached, PhonebookOwner(connection.Phonebook),
                () => HangUp(connection.Handle), stillCurrent));
        }
    }

    /// <summary>
    /// Разрыв чужого подключения правами службы. RAS видит подключения всех пользователей Windows, и служба
    /// (SYSTEM) может разорвать любое из них, в том числе поднятое в сеансе другого пользователя.
    /// Возвращает текст ошибки; null - разорвано.
    /// </summary>
    private static string? HangUp(RasConnectionHandle handle)
    {
        try
        {
            RasClient.HangUpAsync(handle, CancellationToken.None).GetAwaiter().GetResult();
            return null;
        }
        catch (Exception ex) when (ex is NativeCallException or TimeoutException or InvalidOperationException)
        {
            return ex.Message;
        }
    }

    /// <summary>
    /// Чужое подключение Windows к тому же серверу, что и подключение службы, - не просто лишние маршруты:
    /// два сеанса одного пользователя сервер может связать с одним адресом туннеля, и пропадает связь у обоих.
    /// Пока служба держит своё подключение поднятым, чужое разрывается (<paramref name="hangUp"/> возвращает текст
    /// ошибки или null при успехе): иначе подключение из профиля другого пользователя Windows, поднятое при его
    /// входе, рвало бы общий для всех пользователей туннель. Положенному пользователем подключению службы чужое
    /// не мешает и не трогается. <paramref name="stillCurrent"/> проверяется прямо перед разрывом: брошенная или
    /// устаревшая проверка (снимок серверов до отключения VPN) ничего не разрывает.
    /// </summary>
    internal static StatusWarning ForeignConnectionWarning(string entryName, string? foreignServer, IReadOnlyList<ConflictServer> servers,
        Func<string, IReadOnlyList<uint>>? resolve = null, string? owner = null, Func<string?>? hangUp = null, Func<bool>? stillCurrent = null)
    {
        var same = SameServer(foreignServer, servers, resolve);
        var whose = owner is null ? "" : $" пользователя Windows {owner}";
        var where = owner is null ? "в параметрах VPN Windows." : $"в параметрах VPN Windows под пользователем {owner}.";
        string text;
        if (same is null)
        {
            text = $"Активно другое VPN-подключение «{entryName}»{whose}: его маршруты и DNS могут перехватывать трафик.";
        }
        else
        {
            var error = same.HangUpForeign && hangUp is not null && (stillCurrent is null || stillCurrent()) ? hangUp() ?? "" : null;
            text = error is ""
                ? $"Разорвано VPN-подключение Windows «{entryName}»{whose} к тому же серверу, что и «{same.ProfileName}»: "
                  + "два сеанса к одному серверу мешают друг другу, и интернет пропадает. "
                  + $"Чтобы оно не поднималось снова, удалите «{entryName}» или выключите его автоматическое подключение " + where
                : $"Активно VPN-подключение Windows «{entryName}»{whose} к тому же серверу, что и «{same.ProfileName}»: "
                  + "два сеанса к одному серверу мешают друг другу, и интернет может пропадать. "
                  + $"Отключите «{entryName}» и его автоматическое подключение " + where
                  + (error is null ? "" : $" Служба не смогла разорвать его: {error}");
        }

        return new StatusWarning("foreign-vpn", text, null) { Subject = entryName, SameServerProfileId = same?.ProfileId };
    }

    /// <summary>
    /// Пользователь Windows, в чьём профиле лежит телефонная книга подключения
    /// (каталог профиля\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk); общая книга
    /// или другой путь - null.
    /// </summary>
    internal static string? PhonebookOwner(string? phonebook)
    {
        if (string.IsNullOrWhiteSpace(phonebook))
        {
            return null;
        }

        var marker = @"\AppData\Roaming\" + PhonebookSuffix;
        var path = phonebook.Trim().Replace('/', '\\');
        var at = path.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (at <= 0 || at + marker.Length != path.Length)
        {
            return null;
        }

        var user = Path.GetFileName(path[..at]);
        return string.IsNullOrWhiteSpace(user) ? null : user;
    }

    /// <summary>
    /// Подключение службы с тем же сервером: по имени узла, а если имена разные - по адресам. Адрес сервера
    /// службы - известный ей или полученный разрешением имени; адрес чужого сервера - IP-адрес из записи или
    /// результат разрешения её имени. Так совпадают и "имя против адреса", и два имени одного сервера.
    /// К одному серверу могут вести несколько профилей службы (SSTP и IKEv2): выбирается тот, что держит своё
    /// подключение поднятым (<see cref="ConflictServer.HangUpForeign"/>), иначе первый совпавший - сначала по имени.
    /// </summary>
    internal static ConflictServer? SameServer(string? foreignServer, IReadOnlyList<ConflictServer> servers, Func<string, IReadOnlyList<uint>>? resolve = null)
    {
        if (string.IsNullOrWhiteSpace(foreignServer))
        {
            return null;
        }

        var host = ServerAddress.TryParse(foreignServer, out var parsed) ? parsed.Host : foreignServer.Trim();
        if (!servers.Any(s => s.HangUpForeign))
        {
            // Разрывать нечего (например, намерение «Отключено»): выбор профиля ничего не меняет, и лишние разрешения
            // имён (до 2 с каждое) не тянут проверку к пределу координатора. Первое совпадение по имени, иначе по адресу.
            return FirstSameServer(host, servers, resolve);
        }

        var matches = servers.Where(s => string.Equals(Normalize(s.Host), Normalize(host), StringComparison.OrdinalIgnoreCase)).ToList();
        if (!matches.Exists(s => s.HangUpForeign))
        {
            // Совпадение по имени не исключает другого профиля с тем же адресом, который держит подключение поднятым.
            var foreign = AddressesOf(host, resolve);
            if (foreign.Count > 0)
            {
                matches.AddRange(servers.Where(s => !matches.Contains(s)
                    && s.Addresses.Concat(s.Addresses.Count > 0 ? [] : AddressesOf(s.Host, resolve)).Any(foreign.Contains)).ToList());
            }
        }

        return matches.Find(s => s.HangUpForeign) ?? matches.FirstOrDefault();
    }

    /// <summary>Первый сервер службы с тем же именем узла, а если такого нет - первый с тем же адресом.</summary>
    private static ConflictServer? FirstSameServer(string host, IReadOnlyList<ConflictServer> servers, Func<string, IReadOnlyList<uint>>? resolve)
    {
        var byName = servers.FirstOrDefault(s => string.Equals(Normalize(s.Host), Normalize(host), StringComparison.OrdinalIgnoreCase));
        if (byName is not null)
        {
            return byName;
        }

        var foreign = AddressesOf(host, resolve);
        return foreign.Count == 0
            ? null
            : servers.FirstOrDefault(s => s.Addresses.Concat(s.Addresses.Count > 0 ? [] : AddressesOf(s.Host, resolve)).Any(foreign.Contains));
    }

    /// <summary>IP-адрес узла как есть; имя - через разрешение, если оно доступно.</summary>
    private static IReadOnlyList<uint> AddressesOf(string host, Func<string, IReadOnlyList<uint>>? resolve)
    {
        var name = Normalize(host);
        if (Ipv4.TryParse(name, out var address))
        {
            return [address];
        }

        return name.Length == 0 || resolve is null ? [] : resolve(name);
    }

    /// <summary>Одно разрешение на имя за проверку: чужих подключений и серверов службы может быть несколько.</summary>
    private static Func<string, IReadOnlyList<uint>> CachedResolver(Func<string, IReadOnlyList<uint>> resolve)
    {
        var cache = new Dictionary<string, IReadOnlyList<uint>>(StringComparer.OrdinalIgnoreCase);
        return host =>
        {
            if (!cache.TryGetValue(host, out var addresses))
            {
                addresses = resolve(host);
                cache[host] = addresses;
            }

            return addresses;
        };
    }

    private static string Normalize(string host) => host.Trim().TrimEnd('.');

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
        var tunnelLuids = tunnels.Select(t => t.Luid).ToHashSet();
        var localNetworks = LocalNetworks(foreign, tunnelLuids);
        foreach (var tunnel in tunnels)
        {
            var reported = 0;
            foreach (var destination in foreign.Where(r => r.InterfaceLuid == tunnel.Luid).Select(r => r.Destination).Distinct())
            {
                if (reported == MaxRoutesPerTunnel)
                {
                    break;
                }

                // Маршрут без записи в профилях Windows выдал при подключении сам сервер VPN (сети за ним, его
                // собственная подсеть). Частная сеть за сервером опасна, только если перехватывает локальную сеть
                // другого адаптера: маршрут не шире этой сети выигрывает у неё. Публичная — всегда: она может увести
                // в туннель адреса, которые идут напрямую.
                var source = SourceProfile(profiles.Value, destination);
                var hijacks = localNetworks.FirstOrDefault(n => Overlaps(n, destination) && destination.PrefixLength >= n.PrefixLength);
                var isPrivate = RangeSet.From([destination.ToRange()]).Subtract(SpecialRanges.Private).Count == 0;
                if (source is null && isPrivate && hijacks == default)
                {
                    continue;
                }

                reported++;
                warnings.Add(new StatusWarning("foreign-routes",
                    $"На туннеле «{tunnel.Name}» чужой маршрут {destination}"
                    + (source is not null ? $" — вероятно, постоянный маршрут VPN-профиля Windows «{source}»."
                        : hijacks != default ? $": он перехватывает локальную сеть {hijacks}." : "."), null)
                {
                    Subject = tunnel.Name,
                });
            }
        }
    }

    /// <summary>Сети других адаптеров, доступные без шлюза: маршруты к ним без следующего узла, кроме адресов узлов.</summary>
    private static List<Ipv4Cidr> LocalNetworks(IEnumerable<RouteEntry> routes, HashSet<ulong> tunnelLuids) =>
        routes.Where(r => !tunnelLuids.Contains(r.InterfaceLuid) && r.NextHop == 0 && r.Destination.PrefixLength is >= 8 and <= 30)
            .Select(r => r.Destination)
            .Distinct()
            .ToList();

    private static bool Overlaps(Ipv4Cidr a, Ipv4Cidr b) => a.Contains(b.Network) || b.Contains(a.Network);

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
        foreach (var (path, root) in WindowsPhonebooks())
        {
            try
            {
                ReadPhonebook(path, root, entries);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException or NotSupportedException)
            {
                // Телефонная книга недоступна: источник чужого маршрута просто не будет назван.
            }
        }

        return entries;
    }

    private const string PhonebookSuffix = @"Microsoft\Network\Connections\Pbk\rasphone.pbk";

    /// <summary>
    /// Путь книги и каталог, за пределы которого её настоящий путь уходить не должен: сам каталог Pbk, так что
    /// подмена его или любого каталога выше ссылкой на другое место отвергается.
    /// </summary>
    private static IEnumerable<(string Path, string Root)> WindowsPhonebooks()
    {
        var common = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), PhonebookSuffix);
        yield return (common, Path.GetDirectoryName(common)!);
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
            var path = Path.Combine(user, "AppData", "Roaming", PhonebookSuffix);
            yield return (path, Path.GetDirectoryName(path)!);
        }
    }

    /// <summary>
    /// Разбор телефонной книги: имена записей и их маршруты. Файл текстовый, строки «ключ=значение».
    /// Книга лежит в профиле пользователя, а служба читает её правами SYSTEM: каталог, подменённый ссылкой
    /// на чужой файл или с несколькими именами, не читается (<see cref="Security.ConfinedFile"/>), файл, открытый
    /// другим процессом без общего доступа, тоже (ошибка открытия), а размер проверяется у уже открытого файла.
    /// Открытие файла, на котором другой процесс держит oplock, ждёт его снятия без предела: вызывающий код
    /// (координатор) поэтому не ждёт детектор дольше своего предела.
    /// </summary>
    private static void ReadPhonebook(string path, string root, List<WindowsVpnEntry> entries)
    {
        if (!File.Exists(path))
        {
            return;
        }

        using var stream = Security.ConfinedFile.OpenRead(path, root);
        if (stream is null || stream.Length > 4 * 1024 * 1024)
        {
            return;
        }

        var name = "";
        var routes = new StringBuilder();
        // Кодировка книги зависит от системы: нечитаемые символы заменяются, такие имена в текст не попадут.
        using var reader = new StreamReader(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        while (reader.ReadLine() is { } line)
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
