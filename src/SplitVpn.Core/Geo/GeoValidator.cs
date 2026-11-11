using System.Globalization;
using System.Net;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Geo;

public sealed record GeoValidationOptions
{
    /// <summary>Предел размера файла ручного импорта: списки российских сетей занимают около мегабайта.</summary>
    public const long MaxImportBytes = 16 * 1024 * 1024;

    public int MinV4Count { get; init; } = 1000;

    /// <summary>Допустимая доля записей, пересекающих непубличные диапазоны (они удаляются).</summary>
    public double MaxNonPublicShare { get; init; } = 0.01;

    /// <summary>
    /// Сети крупнее /8 в таких списках не встречаются: такая запись (например, пара 0.0.0.0/1 и 128.0.0.0/1)
    /// увела бы мимо VPN весь интернет. Действует и для загрузки, и для ручного импорта.
    /// </summary>
    public int MinPrefixLength { get; init; } = 8;

    /// <summary>
    /// Абсолютный предел покрытия: российские сети — около 1 % адресного пространства IPv4, предел — 1/16 (6,25 %).
    /// Ручной импорт не проходит проверку резких изменений, поэтому предел нужен независимо от прежней базы.
    /// </summary>
    public ulong MaxV4Addresses { get; init; } = 1UL << 28;

    /// <summary>
    /// Пороги под конкретный список. В списке обхода блокировок сетей заметно меньше, чем в RU-базе,
    /// и он может ужаться после снятия блокировок — нижняя граница числа записей своя.
    /// </summary>
    public static GeoValidationOptions For(GeoListKind kind) => kind == GeoListKind.Bypass
        ? new GeoValidationOptions { MinV4Count = 100 }
        : new GeoValidationOptions();
}

public sealed record GeoValidationResult(
    bool IsValid,
    IReadOnlyList<string> Problems,
    IReadOnlyList<string> Warnings,
    RangeSet V4,
    int V4EntryCount,
    int V6EntryCount);

public static class GeoValidator
{
    public static GeoValidationResult Validate(GeoParseResult parsed, GeoValidationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        options ??= new GeoValidationOptions();
        var problems = new List<string>();
        var warnings = new List<string>();

        if (parsed.LooksLikeHtml)
        {
            problems.Add("Получена HTML-страница вместо списка сетей.");
            return new GeoValidationResult(false, problems, warnings, RangeSet.Empty, 0, 0);
        }

        CheckErrors(parsed, problems);
        CheckWholeInternet(parsed, problems);
        CheckBroadPrefixes(parsed, options, problems);
        CheckCount(parsed, options, problems);

        var normalized = RangeSet.From(parsed.V4);
        var mergedAway = parsed.V4.Count - normalized.ToCidrs().Count;
        if (mergedAway > 0)
        {
            warnings.Add(Text($"Объединено дубликатов, перекрытий и смежных подсетей: {mergedAway}."));
        }

        var cleaned = RemoveNonPublic(parsed.V4, normalized, options, problems, warnings);
        if (cleaned.TotalAddresses > options.MaxV4Addresses)
        {
            problems.Add(Text($"Список покрывает {(double)cleaned.TotalAddresses / (1UL << 32) * 100:0.#} % адресного пространства IPv4: это слишком много для списка адресов."));
        }

        return new GeoValidationResult(problems.Count == 0, problems, warnings, cleaned, parsed.V4.Count, parsed.V6.Count);
    }

    private static void CheckErrors(GeoParseResult parsed, List<string> problems)
    {
        if (parsed.ErrorCount == 0)
        {
            return;
        }

        var first = parsed.Errors[0];
        problems.Add(Text($"Неверных строк: {parsed.ErrorCount}; первая — строка {first.LineNumber} «{first.Text}»: {first.Reason}."));
    }

    private static void CheckWholeInternet(GeoParseResult parsed, List<string> problems)
    {
        if (parsed.V4.Any(c => c.PrefixLength == 0) || parsed.V6.Any(n => n.PrefixLength == 0))
        {
            problems.Add("Список содержит маршрут на весь интернет (0.0.0.0/0 или ::/0).");
        }
    }

    private static void CheckBroadPrefixes(GeoParseResult parsed, GeoValidationOptions options, List<string> problems)
    {
        var broad = parsed.V4.Where(c => c.PrefixLength > 0 && c.PrefixLength < options.MinPrefixLength).ToList();
        if (broad.Count > 0)
        {
            problems.Add(Text($"Список содержит слишком крупные сети ({broad.Count}, например {broad[0]}): в списках адресов не бывает сетей крупнее /{options.MinPrefixLength}."));
        }
    }

    private static void CheckCount(GeoParseResult parsed, GeoValidationOptions options, List<string> problems)
    {
        if (parsed.V4.Count == 0)
        {
            problems.Add("Список не содержит IPv4-сетей.");
        }
        else if (parsed.V4.Count < options.MinV4Count)
        {
            problems.Add(Text($"Подозрительно мало IPv4-сетей: {parsed.V4.Count} (ожидается не меньше {options.MinV4Count})."));
        }
    }

    private static RangeSet RemoveNonPublic(
        IReadOnlyList<Ipv4Cidr> entries,
        RangeSet normalized,
        GeoValidationOptions options,
        List<string> problems,
        List<string> warnings)
    {
        var offending = entries.Count(c => SpecialRanges.AllNonPublic.Overlaps(c.ToRange()));
        if (offending == 0)
        {
            return normalized;
        }

        if (offending > entries.Count * options.MaxNonPublicShare)
        {
            problems.Add(Text($"Слишком много записей в локальных или зарезервированных диапазонах: {offending}."));
        }
        else
        {
            warnings.Add(Text($"Удалены записи в локальных или зарезервированных диапазонах: {offending}."));
        }

        return normalized.Subtract(SpecialRanges.AllNonPublic);
    }

    private static string Text(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
