using System.Text.RegularExpressions;

namespace SplitVpn.Core.Diagnostics;

/// <summary>Маскирование персональных данных в диагностическом отчёте (PLAN §7).</summary>
public static partial class Redactor
{
    public static string Redact(string text, IEnumerable<string?>? secrets = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = text;
        foreach (var secret in (secrets ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).OrderByDescending(s => s!.Length))
        {
            result = result.Replace(secret!, "<скрыто>", StringComparison.OrdinalIgnoreCase);
        }

        result = GuidPattern().Replace(result, "<guid>");
        result = MacPattern().Replace(result, "<mac>");
        result = Ipv6Pattern().Replace(result, "<ipv6>");
        result = Ipv4Pattern().Replace(result, "<ipv4>");
        return result;
    }

    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")]
    private static partial Regex GuidPattern();

    [GeneratedRegex(@"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")]
    private static partial Regex MacPattern();

    // Полная форма из 8 групп либо сокращённая с «::» — время вида 12:30:45 не совпадает.
    [GeneratedRegex(@"(?<![\w:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?)(?:%\w+)?(?![\w:])")]
    private static partial Regex Ipv6Pattern();

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b")]
    private static partial Regex Ipv4Pattern();
}
