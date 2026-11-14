using System.Globalization;

namespace SplitVpn.Cli;

internal sealed class CliArgs(string[] values)
{
    public string? Option(string name)
    {
        var index = Array.FindIndex(values, v => string.Equals(v, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < values.Length ? values[index + 1] : null;
    }

    /// <summary>Все значения повторяющейся опции.</summary>
    public IReadOnlyList<string> Values(string name) =>
        values.Select((v, i) => (v, i)).Where(p => string.Equals(p.v, name, StringComparison.OrdinalIgnoreCase) && p.i + 1 < values.Length)
            .Select(p => values[p.i + 1]).ToList();

    public int IntOption(string name, int fallback) =>
        int.TryParse(Option(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : fallback;

    public bool Flag(string name) => values.Any(v => string.Equals(v, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Флаги без значения. Позиционный аргумент после такого флага остаётся позиционным: иначе
    /// «report --no-mask out.txt» потерял бы имя файла, приняв его за значение флага.
    /// </summary>
    private static readonly HashSet<string> s_flags = new(StringComparer.OrdinalIgnoreCase)
    {
        "--json", "--keep-protection", "--no-mask", "--no-save-password", "--from-dev-creds", "--hangup", "--with-routes",
    };

    /// <summary>Позиционный аргумент (не начинающийся с «--» и не являющийся значением опции).</summary>
    public string? Positional(int index)
    {
        var positional = new List<string>();
        for (var i = 0; i < values.Length; i++)
        {
            if (values[i].StartsWith("--", StringComparison.Ordinal))
            {
                i += !s_flags.Contains(values[i]) && i + 1 < values.Length && !values[i + 1].StartsWith("--", StringComparison.Ordinal) ? 1 : 0;
                continue;
            }

            positional.Add(values[i]);
        }

        return index < positional.Count ? positional[index] : null;
    }
}

internal static class Text
{
    public static string Inv(FormattableString value) => value.ToString(CultureInfo.InvariantCulture);
}
