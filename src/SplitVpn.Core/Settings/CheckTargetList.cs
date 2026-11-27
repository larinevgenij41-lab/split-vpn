using System.Globalization;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Settings;

/// <summary>
/// Список контрольных целей из <see cref="CheckTargets"/>: «IPv4:порт» через запятую, точку с запятой или пробел
/// («1.1.1.1:443, 1.1.1.1:80»). Один разбор на проверку настроек и на применение: иначе проверка пропустила бы цель,
/// которую служба потом молча выбросит.
/// </summary>
public static class CheckTargetList
{
    private static readonly char[] Separators = [',', ';', ' ', '\t'];

    /// <summary>Элементы списка как написаны, без разделителей и пустых.</summary>
    public static List<string> Split(string? targets) =>
        (targets ?? "").Split(Separators, StringSplitOptions.RemoveEmptyEntries).ToList();

    /// <summary>Элементы списка с приведённым к каноническому виду каждым, разделители остаются как были.</summary>
    internal static string MapItems(string targets, Func<string, string> map)
    {
        var text = new System.Text.StringBuilder(targets.Length);
        var start = -1;
        for (var i = 0; i <= targets.Length; i++)
        {
            var separator = i == targets.Length || Array.IndexOf(Separators, targets[i]) >= 0;
            if (!separator && start < 0)
            {
                start = i;
            }
            else if (separator && start >= 0)
            {
                text.Append(map(targets[start..i]));
                start = -1;
            }

            if (separator && i < targets.Length)
            {
                text.Append(targets[i]);
            }
        }

        return text.ToString();
    }

    /// <summary>Одна цель «IPv4:порт»: адрес без ведущих нулей, порт от 1 до 65535.</summary>
    public static bool TryParse(string item, out uint address, out ushort port)
    {
        address = 0;
        port = 0;
        var parts = item.Split(':');
        return parts.Length == 2 && Ipv4.TryParse(parts[0], out address)
            && ushort.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out port) && port != 0;
    }
}
