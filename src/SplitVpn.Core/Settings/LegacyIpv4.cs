using System.Text.RegularExpressions;

namespace SplitVpn.Core.Settings;

/// <summary>
/// IPv4-литералы с ведущими нулями из настроек до 0.9.6. Прежний разбор (IPAddress.TryParse) понимал
/// такой октет как восьмеричный: «001» = 1, но «010» = 8. Теперь ведущие нули отвергаются, поэтому при
/// загрузке однозначные записи («001», «007» — восьмеричное значение совпадает с десятичным) приводятся
/// к каноническому виду, а неоднозначные («010», «0255») остаются как есть и попадают в предупреждение:
/// угадывать, имел ли пользователь в виду 8 или 10, нельзя.
/// </summary>
internal static partial class LegacyIpv4
{
    /// <summary>
    /// Все поля настроек, где бывает IPv4: DNS, правила сетей, адреса серверов, контрольные цели.
    /// Возвращает те же настройки, если менять нечего.
    /// </summary>
    public static AppSettings Canonicalize(AppSettings settings, out string? warning)
    {
        var ambiguous = new List<string>();
        string Fix(string text) => Canonicalize(text, ambiguous);

        var result = settings with
        {
            UpstreamDns = Changed(settings.UpstreamDns, Fix),
            LocalDnsServer = settings.LocalDnsServer is { } local ? Fix(local) : null,
            Rules = Changed(settings.Rules, r => Fix(r.Cidr) is var cidr && cidr != r.Cidr ? r with { Cidr = cidr } : r),
            Profiles = Changed(settings.Profiles, p => Fix(p.Server) is var server && server != p.Server ? p with { Server = server } : p),
            CheckTargets = settings.CheckTargets with
            {
                Foreign = Fix(settings.CheckTargets.Foreign),
                Russian = Fix(settings.CheckTargets.Russian),
            },
        };

        warning = ambiguous.Count == 0
            ? null
            : "Адреса с ведущими нулями прежние версии читали как восьмеричные (010 = 8), теперь они не принимаются — исправьте: "
                + string.Join(", ", ambiguous.Distinct(StringComparer.Ordinal).Select(a => $"«{a}»")) + ".";
        return result == settings ? settings : result;
    }

    /// <summary>
    /// Приводит IPv4-литералы внутри строки («a.b.c.d», «a.b.c.d/n», «a.b.c.d:порт», адрес шлюза) к виду без
    /// ведущих нулей. Строку с неоднозначным октетом не меняет и добавляет её в <paramref name="ambiguous"/>.
    /// </summary>
    public static string Canonicalize(string text, ICollection<string> ambiguous)
    {
        var isAmbiguous = false;
        var fixedText = DottedQuad().Replace(text, match =>
        {
            var octets = new string[4];
            for (var i = 0; i < 4; i++)
            {
                var octet = match.Groups[i + 1].Value;
                var trimmed = octet.TrimStart('0');
                if (octet.Length == 1 || octet[0] != '0' || octet.Any(c => c > '7'))
                {
                    // Без ведущего нуля, или прежде и не разбиралось («08»): оставить на суд проверки настроек.
                    octets[i] = octet;
                }
                else if (trimmed.Length <= 1)
                {
                    octets[i] = trimmed.Length == 0 ? "0" : trimmed;
                }
                else
                {
                    isAmbiguous = true;
                    return match.Value;
                }
            }

            return string.Join('.', octets);
        });

        if (isAmbiguous)
        {
            ambiguous.Add(text);
            return text;
        }

        return fixedText;
    }

    private static IReadOnlyList<T> Changed<T>(IReadOnlyList<T> source, Func<T, T> fix)
        where T : class
    {
        var result = source.Select(fix).ToList();
        return result.SequenceEqual(source) ? source : result;
    }

    [GeneratedRegex(@"(?<![\w.])([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)(?![\w.])", RegexOptions.CultureInvariant)]
    private static partial Regex DottedQuad();
}
