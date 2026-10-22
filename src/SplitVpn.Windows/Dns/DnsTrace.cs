using System.Globalization;
using System.Text;
using SplitVpn.Core.Dns;

namespace SplitVpn.Windows.Dns;

/// <summary>
/// Что произошло с одним DNS-запросом — для подробного журнала. Создаётся только в подробном режиме:
/// в обычном обработчик получает null и стоит только проверок на null.
/// </summary>
internal sealed class DnsTrace
{
    /// <summary>Категория строк: служба пишет их в отдельный dns-.log.</summary>
    public const string Category = "Dns.Query";

    public DnsQuestion? Question { get; set; }

    public DomainRoute? Rule { get; set; }

    public DnsRoute? Route { get; set; }

    public string Outcome { get; set; } = "без итога";

    public string? Pin { get; set; }

    /// <summary>«A example.com: переслан; правило *.corp → «Офис»; путь if12 10.0.0.1:53; rcode 0, адресов 2; 34 мс».</summary>
    public string Describe(byte[]? response, TimeSpan elapsed)
    {
        var text = new StringBuilder();
        text.Append(Question is { } q ? TypeName(q.Type) + " " + q.Name : "?").Append(": ").Append(Outcome);
        if (Rule is { } rule)
        {
            text.Append("; правило ").Append(rule.ExactName ? "" : "*.").Append(rule.Suffix).Append(" → ").Append(rule.Target);
        }

        if (Route is { } route)
        {
            text.Append(CultureInfo.InvariantCulture, $"; путь if{route.InterfaceIndex?.ToString(CultureInfo.InvariantCulture) ?? "—"} {string.Join(",", route.Servers)}");
        }

        if (response is not null)
        {
            text.Append(CultureInfo.InvariantCulture, $"; rcode {DnsMessage.GetRcode(response)}");
            if (Question is { Type: DnsMessage.TypeA } a)
            {
                var addresses = DnsMessage.ReadAddresses(response, a.Name);
                text.Append(CultureInfo.InvariantCulture, $", адресов {addresses.Count}");
                if (addresses.Count > 0)
                {
                    text.Append(" (").Append(string.Join(",", addresses.Take(4).Select(Core.Net.Ipv4.Format))).Append(')');
                }
            }
        }

        if (Pin is not null)
        {
            text.Append("; ").Append(Pin);
        }

        return text.Append(CultureInfo.InvariantCulture, $"; {(int)elapsed.TotalMilliseconds} мс").ToString();
    }

    private static string TypeName(ushort type) => type switch
    {
        1 => "A",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        _ => "TYPE" + type.ToString(CultureInfo.InvariantCulture),
    };
}
