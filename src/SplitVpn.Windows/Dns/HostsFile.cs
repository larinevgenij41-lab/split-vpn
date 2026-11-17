using SplitVpn.Core.Net;

namespace SplitVpn.Windows.Dns;

/// <summary>
/// Файл hosts Windows. Системный резолвер, которым пользуется RAS при дозвоне, смотрит его раньше DNS: имя
/// сервера, закреплённое там за адресом (частый приём для SSTP с сертификатом на имя), RAS наберёт по этому
/// адресу. Служба должна знать тот же адрес, иначе защита откроет путь не к нему.
/// </summary>
public static class HostsFile
{
    private const long MaxSize = 4 * 1024 * 1024;

    public static string DefaultPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    /// <summary>IPv4-адреса имени из файла hosts; пусто, если имени там нет или файл не читается.</summary>
    public static IReadOnlyList<uint> Lookup(string host, string? path = null)
    {
        ArgumentNullException.ThrowIfNull(host);
        try
        {
            var file = new FileInfo(path ?? DefaultPath);
            return file.Exists && file.Length <= MaxSize ? Parse(File.ReadLines(file.FullName), host) : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public static IReadOnlyList<uint> Parse(IEnumerable<string> lines, string host)
    {
        ArgumentNullException.ThrowIfNull(lines);
        ArgumentNullException.ThrowIfNull(host);
        var name = host.TrimEnd('.');
        var result = new List<uint>();
        foreach (var raw in lines)
        {
            var hash = raw.IndexOf('#', StringComparison.Ordinal);
            var parts = (hash >= 0 ? raw[..hash] : raw).Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            // 0.0.0.0 и loopback - записи блокировщиков рекламы, а не адрес сервера.
            if (parts.Length >= 2 && Ipv4.TryParse(parts[0], out var address) && address != 0 && address >> 24 != 127
                && parts.Skip(1).Any(p => string.Equals(p.TrimEnd('.'), name, StringComparison.OrdinalIgnoreCase)))
            {
                result.Add(address);
            }
        }

        return result.Distinct().ToList();
    }
}
